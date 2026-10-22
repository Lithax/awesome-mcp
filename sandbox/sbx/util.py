"""Small, dependency-free helpers: bounded subprocess runner, file locks, name/ref validation."""
from __future__ import annotations

import contextlib
import dataclasses
import fcntl
import os
import re
import signal
import subprocess
import threading
import time
from typing import Iterator, Sequence

from .errors import BackendError, SbxError

NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,30}$")
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
# docker-style image reference: no leading dash (option injection), no whitespace/shell chars
IMAGE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,254}$")
FILE_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
FLOOD_FACTOR = 64      # kill a process that emits this many times the output cap

# Variables a runtime CLI legitimately needs. Everything else (API keys, tokens...) is dropped.
CLI_ENV_PASS = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME",
                "XDG_DATA_HOME", "DBUS_SESSION_BUS_ADDRESS", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT",
                "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY", "CONTAINER_HOST", "TMPDIR", "TZ", "HTTP_PROXY",
                "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy", "DOWNLOAD_KEYSERVER")


def validate_name(name: str) -> str:
    if not isinstance(name, str) or not NAME_RE.match(name) or name.endswith("-"):
        raise SbxError("invalid sandbox name: use 1-31 chars of a-z, 0-9 and '-', starting with a letter")
    return name


def cli_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {k: os.environ[k] for k in CLI_ENV_PASS if k in os.environ}
    env.setdefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    if extra:
        env.update(extra)
    return env


@dataclasses.dataclass
class CmdResult:
    exit_code: int | None
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False
    truncated: bool = False
    flooded: bool = False
    duration: float = 0.0
    signal: int | None = None

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    def out(self) -> str:
        return self.stdout.decode("utf-8", "replace")

    def err(self) -> str:
        return self.stderr.decode("utf-8", "replace")

    def message(self, limit: int = 600) -> str:
        """Best human-readable failure text (stderr first), single-spaced and bounded."""
        text = (self.err().strip() or self.out().strip() or f"exit code {self.exit_code}")
        text = re.sub(r"\s+", " ", text)
        return text if len(text) <= limit else text[:limit] + "..."


class _Capture:
    def __init__(self, limit: int, flood_at: int, flood: threading.Event):
        self.limit, self.flood_at, self.flood = limit, flood_at, flood
        self.buf = bytearray()
        self.total = 0

    def feed(self, stream) -> None:
        try:
            while True:
                chunk = stream.read1(65536) if hasattr(stream, "read1") else stream.read(65536)
                if not chunk:
                    break
                self.total += len(chunk)
                room = self.limit - len(self.buf)
                if room > 0:
                    self.buf += chunk[:room]
                if self.total > self.flood_at:
                    self.flood.set()
        except (OSError, ValueError):
            pass

    @property
    def truncated(self) -> bool:
        return self.total > self.limit


def _kill_group(proc: subprocess.Popen) -> None:
    for sig in (signal.SIGTERM, signal.SIGKILL):
        with contextlib.suppress(OSError, ProcessLookupError):
            os.killpg(proc.pid, sig)
        if sig == signal.SIGTERM:
            try:
                proc.wait(timeout=0.4)
                break
            except subprocess.TimeoutExpired:
                pass


def run_cmd(argv: Sequence[str], *, input: bytes | None = None, timeout: float = 60.0,
            env: dict[str, str] | None = None, max_output: int = 1 << 20,
            cwd: str | None = None) -> CmdResult:
    """Run argv (never through a shell) with bounded output and a hard deadline.

    The child gets its own process group; on timeout or output flood the whole group is killed.
    """
    started = time.monotonic()
    try:
        p = subprocess.Popen(list(argv), stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env if env is not None else cli_env(),
                             cwd=cwd, start_new_session=True, close_fds=True)
    except FileNotFoundError:
        raise BackendError(f"required program not found: {argv[0]}") from None
    except OSError as e:
        raise BackendError(f"could not start {argv[0]}: {e.strerror or e}") from None
    flood = threading.Event()
    out = _Capture(max_output, max_output * FLOOD_FACTOR, flood)
    err = _Capture(max_output, max_output * FLOOD_FACTOR, flood)
    threads = [threading.Thread(target=out.feed, args=(p.stdout,), daemon=True),
               threading.Thread(target=err.feed, args=(p.stderr,), daemon=True)]
    if input is not None:
        def feed_in() -> None:
            with contextlib.suppress(OSError, ValueError):
                p.stdin.write(input)
            with contextlib.suppress(OSError, ValueError):
                p.stdin.close()
        threads.append(threading.Thread(target=feed_in, daemon=True))
    for t in threads:
        t.start()
    deadline = started + timeout
    timed_out = flooded = False
    while p.poll() is None:
        if time.monotonic() > deadline:
            timed_out = True
        elif flood.is_set():
            flooded = True
        else:
            time.sleep(0.01)
            continue
        _kill_group(p)
        break
    with contextlib.suppress(subprocess.TimeoutExpired):
        p.wait(timeout=3)
    # a surviving grandchild may hold the pipes open; reap the group before joining readers
    with contextlib.suppress(OSError, ProcessLookupError):
        os.killpg(p.pid, signal.SIGKILL)
    for t in threads:
        t.join(timeout=2)
    for s in (p.stdout, p.stderr):
        with contextlib.suppress(OSError, ValueError):
            s.close()
    code = p.returncode
    sig = -code if code is not None and code < 0 else None
    return CmdResult(None if sig else code, bytes(out.buf), bytes(err.buf), timed_out,
                     out.truncated or err.truncated, flooded, time.monotonic() - started, sig)


def run_checked(argv: Sequence[str], what: str, **kw) -> CmdResult:
    """run_cmd that raises BackendError with a readable message on any failure."""
    r = run_cmd(argv, **kw)
    if r.timed_out:
        raise BackendError(f"{what}: timed out")
    if r.exit_code != 0:
        raise BackendError(f"{what}: {r.message()}")
    return r


@contextlib.contextmanager
def file_lock(path: str, timeout: float = 30.0) -> Iterator[None]:
    """Cross-process exclusive lock (flock). Re-entrancy is NOT supported; keep critical sections small."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0), 0o600)
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise SbxError("timed out waiting for another operation on this sandbox") from None
                time.sleep(0.02)
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def secure_makedirs(path: str) -> None:
    os.makedirs(path, mode=0o700, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(path, 0o700)


def short(text: str, n: int = 1500) -> str:
    return text if len(text) <= n else text[:n] + f"... (+{len(text) - n} chars)"
