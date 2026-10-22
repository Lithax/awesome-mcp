"""
router_launch: start (and later tear down) locally hosted Python MCP servers.

A server entry in servers.json becomes "managed" when it has a "path":

    "notes": {                                   # HTTP server the router starts for you
        "path": "~/mcp/notes",                   # project directory
        "entry": "server.py",                    #   script inside it   (or "module": "pkg.server")
        "args": ["--port", "9100"],              #   extra argv for the script
        "url": "http://127.0.0.1:9100/mcp",      # loopback only
        "autostart": true,                       # start with the router (default: on first use)
        "env": {"NOTES_TOKEN": "${NOTES_TOKEN}"},# extra env vars (values expanded from router env)
        "inherit_env": ["OPENAI_API_KEY"],       # router env vars to pass through
        "start_timeout": 30                      # seconds to wait for the port (1-120)
    }
    "calc": {"path": "~/mcp/calc", "module": "calc_server"}   # no url -> stdio server

Interpreter choice: <path>/.venv/bin/python if there is a working .venv, otherwise a
trusted global python3, otherwise nothing is started.

Security model (everything fails closed; the reason is logged and shown by `check`):

  * Nothing is launched unless servers.json and its directory are owned by you (or root)
    and not writable by anyone else. Whoever can edit that file can run code as you.
  * The project dir must be absolute, inside $HOME (or ROUTER_ALLOWED_ROOTS), owned by you,
    not writable by others; so must its ancestors, the entry script, and the .venv.
  * The entry script must resolve (after symlinks) to a .py file inside the project dir.
  * No shell is ever involved: argv is a list passed straight to exec.
  * The child gets a minimal environment, NOT the router's. Secrets reach it only if you
    list them in "env" / "inherit_env". LD_*, DYLD_*, PYTHON*, PATH etc. are refused.
  * Managed HTTP servers must live on loopback (127.0.0.0/8, ::1, localhost).
  * If the port is already in use we don't launch, and we never kill what we didn't start.
  * Each child runs in its own process group, umask 077, stdin closed, output to a
    0600 log file (never to the MCP client). Crash loops are rate limited.
  * Refuses to run as root unless ROUTER_ALLOW_ROOT=1. POSIX only.

Not defended against: another process running as *you* (it could do all this anyway),
or a SIGKILL of the router (children are then orphaned; see README note in router.py).
"""

from __future__ import annotations

import asyncio
import atexit
import collections
import functools
import hashlib
import ipaddress
import json
import os
import re
import signal
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

IS_POSIX = os.name == "posix"

LAUNCH_KEYS = ("path", "entry", "module", "args", "env", "inherit_env", "start_timeout", "url", "command")
SAFE_PATH = ("/usr/local/bin", "/usr/bin", "/bin")
GLOBAL_PYTHON_DIRS = ("/usr/local/bin", "/usr/bin", "/bin", "/opt/homebrew/bin")

MODULE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# Names that change how code is loaded or executed: never allowed from config.
ENV_DENY_RE = re.compile(r"^(LD_.*|DYLD_.*|PYTHON.*|PATH|IFS|BASH_ENV|ENV|SHELLOPTS|PS4|PERL5.*|NODE_OPTIONS)$", re.I)

MAX_ARGS = 64
MAX_ARG_LEN = 1024
MAX_STARTS = 5          # launches allowed per name ...
START_WINDOW = 60.0     # ... within this many seconds
TERM_GRACE = 5.0        # SIGTERM -> SIGKILL grace period


class LaunchError(ValueError):
    """A launch was refused or failed. str(e) is safe to show to the MCP client."""


# --------------------------------------------------------------------------
# Trust checks
# --------------------------------------------------------------------------
@functools.lru_cache(maxsize=None)
def _is_private_group(gid: int) -> bool:
    """True if gid is this user's own single-member group (Ubuntu-style 'user private
    group'). There, group-writable is the same as owner-writable. Shared groups
    (macOS 'staff', 'users', ...) return False."""
    try:
        import grp
        import pwd

        user = pwd.getpwuid(os.geteuid())
        g = grp.getgrgid(gid)
    except Exception:  # noqa: BLE001
        return False
    return gid == user.pw_gid and g.gr_name == user.pw_name and not (set(g.gr_mem) - {user.pw_name})


def _check_trusted(path: Path | str, what: str) -> os.stat_result:
    """Owned by you or root, not writable by anyone else."""
    try:
        st = os.stat(path)
    except OSError as e:
        raise LaunchError(f"{what} is not accessible ({e.strerror})") from None
    if st.st_uid not in (os.geteuid(), 0):
        raise LaunchError(f"{what} ({path}) is owned by uid {st.st_uid}, not by you or root")
    if st.st_mode & stat.S_IWOTH:
        raise LaunchError(f"{what} ({path}) is world-writable (fix: chmod o-w)")
    if st.st_mode & stat.S_IWGRP and not _is_private_group(st.st_gid):
        raise LaunchError(f"{what} ({path}) is writable by a shared group (fix: chmod g-w)")
    return st


def _check_ancestors(path: Path, what: str) -> None:
    """Every parent must be owned by you/root and not world-writable (unless sticky,
    like /tmp). Otherwise someone could swap the directory out from under us."""
    for anc in path.parents:
        try:
            st = os.stat(anc)
        except OSError as e:
            raise LaunchError(f"parent of {what} is not accessible ({e.strerror})") from None
        if st.st_uid not in (os.geteuid(), 0):
            raise LaunchError(f"parent directory {anc} of {what} is owned by uid {st.st_uid}")
        if st.st_mode & stat.S_IWOTH and not st.st_mode & stat.S_ISVTX:
            raise LaunchError(f"parent directory {anc} of {what} is world-writable")


def _audit_config(config_path: Path) -> None:
    try:
        real = config_path.resolve(strict=True)
    except OSError:
        raise LaunchError("servers.json not found") from None
    _check_trusted(real, "servers.json")
    _check_trusted(real.parent, "the directory containing servers.json")


def _allowed_roots() -> list[Path]:
    raw = os.environ.get("ROUTER_ALLOWED_ROOTS")
    roots = [Path(r).expanduser() for r in raw.split(os.pathsep) if r] if raw else [Path.home()]
    return [r.resolve() for r in roots]


# --------------------------------------------------------------------------
# Validating the config
# --------------------------------------------------------------------------
def _clean_str(value: Any, what: str, max_len: int = MAX_ARG_LEN) -> str:
    if not isinstance(value, str) or not value or "\0" in value or len(value) > max_len:
        raise LaunchError(f"{what} must be a non-empty string (no NUL bytes, max {max_len} chars)")
    return value


def _validate_project_dir(raw: Any) -> Path:
    p = Path(_clean_str(raw, "'path'")).expanduser()  # ~ only; deliberately no $VAR expansion
    if not p.is_absolute():
        raise LaunchError("'path' must be absolute (or start with ~)")
    try:
        real = p.resolve(strict=True)
    except OSError:
        raise LaunchError(f"'path' does not exist: {p}") from None
    if not real.is_dir():
        raise LaunchError(f"'path' is not a directory: {real}")
    if not any(root in real.parents for root in _allowed_roots()):
        raise LaunchError(
            f"'path' {real} is outside the allowed roots (default: your home directory; "
            "set ROUTER_ALLOWED_ROOTS to change)"
        )
    _check_trusted(real, "project directory")
    _check_ancestors(real, "project directory")
    return real


def _validate_target(project: Path, cfg: dict[str, Any]) -> list[str]:
    entry, module = cfg.get("entry"), cfg.get("module")
    if (entry is None) == (module is None):
        raise LaunchError("set exactly one of 'entry' (script) or 'module' alongside 'path'")
    if module is not None:
        if not isinstance(module, str) or not MODULE_RE.match(module):
            raise LaunchError("'module' must be a dotted Python module name")
        return ["-m", module]
    rel = Path(_clean_str(entry, "'entry'"))
    if rel.is_absolute() or rel.suffix != ".py":
        raise LaunchError("'entry' must be a relative path to a .py file inside 'path'")
    try:
        real = (project / rel).resolve(strict=True)
    except OSError:
        raise LaunchError(f"'entry' does not exist: {rel}") from None
    if project not in real.parents:
        raise LaunchError("'entry' resolves outside the project directory")
    if not real.is_file():
        raise LaunchError("'entry' is not a regular file")
    _check_trusted(real, "entry script")
    for d in real.parents:  # sub-directories between the script and the project root
        if d == project:
            break
        _check_trusted(d, "directory containing the entry script")
    return [str(real)]


def _validate_args(raw: Any) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list) or len(raw) > MAX_ARGS:
        raise LaunchError(f"'args' must be a list of at most {MAX_ARGS} strings")
    # Args are literal (no $VAR expansion): they show up in `ps`, so secrets belong in 'env'.
    return [_clean_str(a, "each arg") if a != "" else "" for a in raw]


def _check_env_name(name: Any, what: str) -> str:
    if not isinstance(name, str) or not ENV_NAME_RE.match(name):
        raise LaunchError(f"{what}: invalid environment variable name {name!r}")
    if ENV_DENY_RE.match(name):
        raise LaunchError(f"{what}: environment variable {name} is not allowed (it alters code loading)")
    return name


def _build_env(cfg: dict[str, Any], venv: Path | None) -> dict[str, str]:
    path_dirs = ([str(venv / "bin")] if venv else []) + list(SAFE_PATH)
    env = {"PATH": os.pathsep.join(path_dirs), "PYTHONUNBUFFERED": "1"}
    if venv:
        env["VIRTUAL_ENV"] = str(venv)
    for k in ("HOME", "LANG", "LC_ALL", "TZ"):
        if k in os.environ:
            env[k] = os.environ[k]

    inherit = cfg.get("inherit_env", [])
    if not isinstance(inherit, list):
        raise LaunchError("'inherit_env' must be a list of variable names")
    for name in inherit:
        _check_env_name(name, "inherit_env")
        if name in os.environ:
            env[name] = os.environ[name]

    extra = cfg.get("env", {})
    if not isinstance(extra, dict):
        raise LaunchError("'env' must be an object of NAME: value")
    for name, value in extra.items():
        _check_env_name(name, "env")
        env[name] = os.path.expandvars(_clean_str(value, f"env value for {name}", 8192))
    return env


# --------------------------------------------------------------------------
# Choosing a Python: .venv -> trusted global -> nothing
# --------------------------------------------------------------------------
def _find_venv(project: Path) -> tuple[Path, Path] | None:
    """Return (venv_dir, python) if the project has a usable .venv.
    A *missing or hollow* .venv returns None (caller falls back to global python).
    A *suspicious* one (symlink, wrong owner, writable by others) raises."""
    venv = project / ".venv"
    if venv.is_symlink():
        raise LaunchError(".venv is a symlink; refusing (it could point anywhere)")
    if not venv.exists():
        return None
    if not venv.is_dir():
        raise LaunchError(".venv exists but is not a directory")
    _check_trusted(venv, ".venv")
    cfgfile = venv / "pyvenv.cfg"
    if not cfgfile.is_file():
        return None  # not actually a venv
    _check_trusted(cfgfile, ".venv/pyvenv.cfg")  # its 'home =' line decides which python runs
    bindir = venv / "bin"
    if bindir.is_symlink() or not bindir.is_dir():
        raise LaunchError(".venv/bin is missing or a symlink")
    _check_trusted(bindir, ".venv/bin")
    py = bindir / "python"
    if not py.exists():
        return None
    target = py.resolve(strict=True)
    if not target.is_file() or not os.access(target, os.X_OK):
        return None
    _check_trusted(target, "the interpreter .venv/bin/python points to")
    return venv, py  # NOTE: keep `py` unresolved; python finds pyvenv.cfg via its own path


def _global_python() -> Path | None:
    override = os.environ.get("ROUTER_GLOBAL_PYTHON")
    if override:
        candidates = [Path(override)]
    else:
        candidates = [Path(d) / n for d in GLOBAL_PYTHON_DIRS for n in ("python3", "python")]
    for c in candidates:
        try:
            real = c.resolve(strict=True)
            if not c.is_absolute() or not real.is_file() or not os.access(real, os.X_OK):
                continue
            _check_trusted(real, "global python")
            _check_trusted(real.parent, "global python's directory")
        except (OSError, LaunchError):
            continue
        return real
    return None


async def _probe(py: Path, env: dict[str, str]) -> bool:
    """Does this interpreter actually start? (isolated mode, 10s cap)"""
    try:
        proc = await asyncio.create_subprocess_exec(
            str(py), "-I", "-c", "import sys",
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=env, cwd="/",
        )
    except OSError:
        return False
    try:
        return await asyncio.wait_for(proc.wait(), 10) == 0
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return False


@dataclass(frozen=True)
class Launch:
    argv: list[str]
    cwd: str
    env: dict[str, str]
    interpreter: str  # "venv" | "global"

    def summary(self) -> str:
        return f"{self.interpreter} python: {' '.join(self.argv)}  (cwd {self.cwd})"


async def resolve_launch(cfg: dict[str, Any], config_path: Path) -> Launch:
    """Run every check and pick an interpreter. Raises LaunchError on any doubt."""
    if not IS_POSIX:
        raise LaunchError("managed launch is only supported on Linux/macOS")
    if os.geteuid() == 0 and os.environ.get("ROUTER_ALLOW_ROOT") != "1":
        raise LaunchError("refusing to launch servers as root (set ROUTER_ALLOW_ROOT=1 to override)")
    _audit_config(config_path)
    if "command" in cfg:
        raise LaunchError("use either 'command' or 'path' (+ 'entry'/'module'), not both")

    project = _validate_project_dir(cfg.get("path"))
    target = _validate_target(project, cfg)
    args = _validate_args(cfg.get("args"))

    candidates: list[tuple[str, Path, Path | None]] = []
    if found := _find_venv(project):
        candidates.append(("venv", found[1], found[0]))
    if (g := _global_python()) is not None:
        candidates.append(("global", g, None))
    if not candidates:
        raise LaunchError("no .venv and no trusted global python found")

    for kind, py, venv in candidates:
        env = _build_env(cfg, venv)
        if await _probe(py, env):
            return Launch([str(py), "-u", *target, *args], str(project), env, kind)
    raise LaunchError("the interpreter(s) found would not start")


# --------------------------------------------------------------------------
# HTTP helpers
# --------------------------------------------------------------------------
def loopback_target(url: Any) -> tuple[str, int]:
    u = urlparse(_clean_str(url, "'url'"))
    if u.scheme not in ("http", "https") or not u.hostname:
        raise LaunchError("'url' must be an http(s) URL")
    host = u.hostname
    if host != "localhost":
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise ValueError
        except ValueError:
            raise LaunchError(f"managed servers must listen on loopback; '{host}' is not") from None
    try:
        port = u.port or (443 if u.scheme == "https" else 80)
    except ValueError:
        raise LaunchError("'url' has an invalid port") from None
    return host, port


async def _port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (OSError, asyncio.TimeoutError):
        return False
    w.close()
    try:
        await w.wait_closed()
    except OSError:
        pass
    return True


# --------------------------------------------------------------------------
# Supervisor
# --------------------------------------------------------------------------
@dataclass
class _Managed:
    proc: asyncio.subprocess.Process
    fp: str


def _fingerprint(cfg: dict[str, Any]) -> str:
    sub = {k: cfg.get(k) for k in LAUNCH_KEYS}
    return hashlib.sha256(json.dumps(sub, sort_keys=True, default=str).encode()).hexdigest()


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name).lstrip(".") or "server"


class Supervisor:
    def __init__(self, config_path: Path, log: Callable[..., None]) -> None:
        self.config_path = config_path
        self.log = log
        self._procs: dict[str, _Managed] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._starts: dict[str, collections.deque[float]] = {}
        self._status: dict[str, str] = {}
        atexit.register(self.kill_all_sync)  # last resort if the loop is already gone

    def _lock(self, name: str) -> asyncio.Lock:
        return self._locks.setdefault(name, asyncio.Lock())

    def status(self, name: str) -> str:
        m = self._procs.get(name)
        if m and m.proc.returncode is None:
            return "running (started by router)"
        return self._status.get(name, "idle")

    # ---- starting ------------------------------------------------------
    async def prepare(self, name: str, cfg: dict[str, Any]) -> Launch | None:
        """Called before the pool connects.

        * no "path"            -> nothing to do (None)
        * "path" + "url"       -> start the HTTP server if needed. Failure is logged and
                                  swallowed: the connection attempt then proceeds as it
                                  always did, and fails normally if nothing is listening.
        * "path", no "url"     -> stdio server: returns the vetted Launch for the pool's
                                  transport. Failure raises LaunchError.
        """
        if "path" not in cfg:
            return None
        async with self._lock(name):
            if "url" in cfg:
                await self._ensure_http(name, cfg)
                return None
            try:
                launch = await resolve_launch(cfg, self.config_path)
            except LaunchError as e:
                self._fail(name, e)
                raise
            self._status[name] = f"stdio, {launch.interpreter} python"
            self.log(f"'{name}': launching over stdio ({launch.summary()})")
            return launch

    def _fail(self, name: str, err: Exception) -> None:
        self._status[name] = f"not started: {err}"
        self.log(f"'{name}' not started: {err}")

    def _rate_limit(self, name: str) -> None:
        now = time.monotonic()
        q = self._starts.setdefault(name, collections.deque())
        while q and now - q[0] > START_WINDOW:
            q.popleft()
        if len(q) >= MAX_STARTS:
            raise LaunchError(f"started {MAX_STARTS} times in {int(START_WINDOW)}s; cooling down")
        q.append(now)

    async def _ensure_http(self, name: str, cfg: dict[str, Any]) -> None:
        fp = _fingerprint(cfg)
        cur = self._procs.get(name)
        if cur:
            if cur.fp == fp and cur.proc.returncode is None:
                return
            why = "config changed" if cur.fp != fp else "process exited"
            self.log(f"'{name}': restarting ({why})")
            await self._stop_locked(name)
        try:
            host, port = loopback_target(cfg["url"])
            timeout = cfg.get("start_timeout", 30)
            if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 1 <= timeout <= 120:
                raise LaunchError("'start_timeout' must be a number between 1 and 120")
            if await _port_open(host, port, 1.0):
                self._status[name] = f"external: {host}:{port} already in use, not launching"
                self.log(f"'{name}': {host}:{port} already accepting connections; using it, not launching")
                return
            self._rate_limit(name)
            launch = await resolve_launch(cfg, self.config_path)
            proc = await self._spawn(name, launch)
            if not await self._wait_ready(proc, host, port, float(timeout)):
                await self._terminate(proc)
                if proc.returncode is not None and proc.returncode >= 0:
                    raise LaunchError(f"exited with code {proc.returncode} before listening (see {_safe_name(name)}.log)")
                raise LaunchError(f"did not start listening on {host}:{port} in {timeout}s (see {_safe_name(name)}.log)")
            self._procs[name] = _Managed(proc, fp)
            self._status[name] = "running (started by router)"
            self.log(f"'{name}': started pid {proc.pid} ({launch.summary()})")
        except LaunchError as e:
            self._fail(name, e)

    async def _spawn(self, name: str, launch: Launch) -> asyncio.subprocess.Process:
        fd = self._open_log(name)
        try:
            return await asyncio.create_subprocess_exec(
                *launch.argv,
                cwd=launch.cwd,
                env=launch.env,
                stdin=subprocess.DEVNULL,
                stdout=fd if fd is not None else subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
                start_new_session=True,  # own process group -> we can kill the whole tree
                umask=0o077,
            )
        except OSError as e:
            raise LaunchError(f"could not execute interpreter ({e.strerror})") from None
        finally:
            if fd is not None:
                os.close(fd)

    def _open_log(self, name: str) -> int | None:
        """0600 log file in a 0700 directory; never follows symlinks. None on any problem."""
        try:
            base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
            d = base / "mcp-router" / "logs"
            d.mkdir(parents=True, exist_ok=True, mode=0o700)
            st = os.lstat(d)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
                self.log(f"log directory {d} is not private (0700, yours); child output discarded")
                return None
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            return os.open(d / f"{_safe_name(name)}.log", flags, 0o600)
        except OSError as e:
            self.log(f"cannot open log file ({e.strerror}); child output discarded")
            return None

    @staticmethod
    async def _wait_ready(proc: asyncio.subprocess.Process, host: str, port: int, timeout: float) -> bool:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            if proc.returncode is not None:
                return False
            if await _port_open(host, port):
                # A child that lost a bind race exits right away; an impostor already holding
                # the port would otherwise look like success.
                await asyncio.sleep(0.3)
                return proc.returncode is None
            await asyncio.sleep(0.25)
        return False

    # ---- stopping ------------------------------------------------------
    @staticmethod
    async def _terminate(proc: asyncio.subprocess.Process) -> None:
        """SIGTERM the process group, wait, then SIGKILL. Only ever signals a group whose
        leader we still hold (unreaped), so a recycled pid can't be hit."""
        if proc.returncode is not None:
            return
        for sig, wait in ((signal.SIGTERM, TERM_GRACE), (signal.SIGKILL, 5.0)):
            try:
                os.killpg(proc.pid, sig)
            except ProcessLookupError:
                break
            except PermissionError:
                break
            try:
                await asyncio.wait_for(proc.wait(), wait)
                return
            except asyncio.TimeoutError:
                continue

    async def _stop_locked(self, name: str) -> bool:
        m = self._procs.pop(name, None)
        if m is None:
            return False
        await self._terminate(m.proc)
        self._status[name] = "stopped"
        self.log(f"'{name}': stopped")
        return True

    async def stop(self, name: str) -> bool:
        async with self._lock(name):
            return await self._stop_locked(name)

    async def prune(self, enabled: set[str]) -> None:
        """Stop anything we started whose server was removed or disabled in servers.json."""
        for name in [n for n in self._procs if n not in enabled]:
            await self.stop(name)

    async def shutdown(self) -> None:
        await asyncio.gather(*(self.stop(n) for n in list(self._procs)), return_exceptions=True)

    def kill_all_sync(self) -> None:
        """atexit fallback: no event loop needed."""
        live = [m.proc.pid for m in self._procs.values() if m.proc.returncode is None]
        for pid in live:
            try:
                os.killpg(pid, signal.SIGTERM)
            except OSError:
                pass
        deadline = time.monotonic() + TERM_GRACE
        while live and time.monotonic() < deadline:
            time.sleep(0.1)
            live = [pid for pid in live if _group_alive(pid)]
        for pid in live:
            try:
                os.killpg(pid, signal.SIGKILL)
            except OSError:
                pass
        self._procs.clear()


def _group_alive(pgid: int) -> bool:
    try:
        os.waitpid(pgid, os.WNOHANG)  # reap the leader if it is our direct child
    except ChildProcessError:
        pass
    try:
        os.killpg(pgid, 0)
    except OSError:
        return False
    return True
