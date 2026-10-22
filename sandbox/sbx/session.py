"""Persistent shell sessions for sandbox targets.

Every `run_command` is still its own process (backends are stateless and the in-guest `timeout -s KILL` must
keep working), but the shell *state that people expect to persist* is carried over:

  * the working directory, and
  * exported environment variables (set, changed or unset), PATH included.

How: the guest wrapper dumps `env -0` before the command and `pwd -P` + `env -0` when the shell exits (EXIT
trap, on a private copy of stdout so redirections inside the command cannot swallow it). The host diffs the two
env dumps, validates the result and replays it on the next call through `ExecRequest.env`.

Security notes:
  * State is held on the HOST and replayed as *data* (env vars, a cwd). It is never `source`d or `eval`d, and
    nothing is written into the guest, so it cannot be used to smuggle unclassified code into a later command.
  * Whatever the guest prints is untrusted (a command can fake the trailer), so everything captured is
    re-validated here: variable names, execution-hijack variables, path-list shape, sizes. The cwd goes through
    the same path guard as an explicit `cwd` argument on every call.
  * Not persisted (a real shell would keep these; a stateless exec cannot): unexported shell variables,
    functions, aliases, `set` options, `trap`s, background jobs. A killed (timed-out) command leaves state as it was.
"""
from __future__ import annotations

import re
import secrets
import shlex
import threading
import time
from dataclasses import dataclass, field

from .errors import SbxError
from .util import ENV_NAME_RE

# ---- guest side ------------------------------------------------------------------------------------
# POSIX sh compatible (falls back to plain `sh` when the image has no bash). Args: $1 command, $2 token,
# $3 space-separated names to unset before the command runs.
_WRAPPER = r'''__sbx_c=$1; __sbx_t=$2; __sbx_u=$3
exec 9>&1
for __sbx_n in $__sbx_u; do unset "$__sbx_n"; done
{ printf '%sB\0' "$__sbx_t"; env -0; printf '%sM\0' "$__sbx_t"; } >&9 2>/dev/null
trap '__sbx_rc=$?; { printf "%sF\0" "$__sbx_t"; printf "%s\0" "$(pwd -P)"; env -0; printf "%sZ\0" "$__sbx_t"; } >&9 2>/dev/null; exit $__sbx_rc' EXIT
unset __sbx_u __sbx_n
eval "$__sbx_c"
'''
_Q = shlex.quote(_WRAPPER)
GUEST_SESSION_SHELL = (f'W={_Q}; if command -v bash >/dev/null 2>&1; then exec bash --noprofile --norc -c "$W" sbx "$@"; '
                       f'else exec sh -c "$W" sbx "$@"; fi')

# Room on top of the user-visible output cap for the two env dumps (each is bounded by the guest environment).
TRAILER_HEADROOM = 512 * 1024

# ---- validation ------------------------------------------------------------------------------------
# Bookkeeping the shell itself rewrites on every run.
VOLATILE = {"_", "PWD", "OLDPWD", "SHLVL", "BASH_EXECUTION_STRING", "BASH_ARGV0"}
# Variables that make a *later* command execute attacker-chosen code. The classifier flags setting them
# directly; a dynamic `export "$n=$v"` would slip past it, so they are never carried between calls.
# (Mirrors shellcore.ENV_HIJACK minus the path-list variables below, plus loader prefixes.)
PATH_LIST_VARS = {"PATH", "PYTHONPATH", "NODE_PATH", "PERL5LIB", "RUBYLIB"}
HIJACK_PREFIXES = ("LD_", "DYLD_", "BASH_FUNC_", "__sbx")
MAX_VALUE_BYTES = 32 * 1024
MAX_VARS = 256


def _hijack_names() -> frozenset[str]:
    from .shellcore import ENV_HIJACK
    return frozenset(ENV_HIJACK) - PATH_LIST_VARS


def _bad_path_list(value: str) -> str | None:
    """PATH-like values must be absolute directories only: an empty entry or '.' means 'the current directory'."""
    for part in value.split(":"):
        if not part.startswith("/"):
            return "contains an empty or relative entry"
    return None


@dataclass
class Session:
    name: str
    cwd: str | None = None
    env_set: dict[str, str] = field(default_factory=dict)
    env_unset: set[str] = field(default_factory=set)
    runs: int = 0
    last_used: float = 0.0
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def env_bytes(self) -> int:
        return sum(len(k) + len(v) + 2 for k, v in self.env_set.items())


class SessionStore:
    """Sessions per (sandbox name, sandbox id). In memory: a server restart starts fresh shells."""

    def __init__(self) -> None:
        self._s: dict[tuple[str, str], dict[str, Session]] = {}
        self._lock = threading.Lock()

    def get(self, sandbox: str, sandbox_id: str, name: str, limit: int) -> Session:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", name or ""):
            raise SbxError("invalid session name: use 1-32 chars of letters, digits, '_' and '-'")
        with self._lock:
            d = self._s.setdefault((sandbox, sandbox_id), {})
            if name not in d:
                if len(d) >= limit:
                    raise SbxError(f"too many shell sessions in {sandbox!r} (max {limit}); "
                                   f"reuse one or call reset_shell_session. Open: {', '.join(sorted(d))}")
                d[name] = Session(name)
            return d[name]

    def peek(self, sandbox: str, sandbox_id: str) -> list[Session]:
        with self._lock:
            return list(self._s.get((sandbox, sandbox_id), {}).values())

    def reset(self, sandbox: str, name: str | None = None) -> int:
        """Drop one session (or all of a sandbox's). Returns how many were dropped."""
        n = 0
        with self._lock:
            for key in [k for k in self._s if k[0] == sandbox]:
                d = self._s[key]
                for sn in [x for x in d if name is None or x == name]:
                    del d[sn]
                    n += 1
                if not d:
                    del self._s[key]
        return n


# ---- one call ----------------------------------------------------------------------------------------
@dataclass
class Prepared:
    token: str
    unset: str
    env: dict[str, str]
    cwd: str | None


def prepare(sess: Session, base_env: dict[str, str], admin_env: dict[str, str]) -> Prepared:
    """Env for the next command: baseline < session changes < admin-forced values."""
    with sess.lock:
        env = {**base_env, **sess.env_set, **admin_env}
        unset = " ".join(sorted(n for n in sess.env_unset if n not in admin_env and ENV_NAME_RE.match(n)))
        return Prepared(secrets.token_hex(12), unset, env, sess.cwd)


def _records(blob: bytes) -> list[bytes]:
    parts = blob.split(b"\0")
    if parts and parts[-1] == b"":
        parts.pop()
    return parts


def _env_dict(recs: list[bytes]) -> dict[str, str]:
    out: dict[str, str] = {}
    for r in recs:
        k, eq, v = r.decode("utf-8", "replace").partition("=")
        if eq and ENV_NAME_RE.match(k):
            out[k] = v
    return out


@dataclass
class Captured:
    cwd: str | None
    before: dict[str, str]
    after: dict[str, str]


def split_output(stdout: bytes, token: str) -> tuple[bytes, Captured | None]:
    """Remove the framing from stdout. Returns (what the command printed, captured state or None)."""
    t = token.encode()
    start, mid = t + b"B\0", t + b"M\0"
    fin, end = t + b"F\0", t + b"Z\0"
    before: dict[str, str] | None = None
    if stdout.startswith(start):
        i = stdout.find(mid, len(start))
        if i >= 0:
            before = _env_dict(_records(stdout[len(start):i]))
            stdout = stdout[i + len(mid):]
    j = stdout.rfind(fin)
    if j < 0:
        return stdout, None
    visible, tail = stdout[:j], stdout[j + len(fin):]
    if before is None or not tail.endswith(end):
        return visible, None            # truncated / killed / shell replaced by `exec`: keep the old state
    recs = _records(tail[:-len(end)])
    if not recs:
        return visible, None
    cwd = recs[0].decode("utf-8", "replace")
    return visible, Captured(cwd or None, before, _env_dict(recs[1:]))


def absorb(sess: Session, cap: Captured, admin_env: dict[str, str], max_env_bytes: int) -> list[str]:
    """Validate what the command left behind and merge it into the session. Returns notes for the model."""
    notes: list[str] = []
    hijack = _hijack_names()
    new_set: dict[str, str] = {}
    new_unset: set[str] = set()
    for k, v in cap.after.items():
        if k in VOLATILE or cap.before.get(k) == v:
            continue
        if k in admin_env:
            notes.append(f"{k} is fixed by the server configuration and was not changed")
        elif k in hijack or k.startswith(HIJACK_PREFIXES):
            if not k.startswith("__sbx"):
                notes.append(f"{k} is not carried between commands (it can change how programs run); "
                             f"set it inline in the command that needs it")
        elif len(v.encode()) > MAX_VALUE_BYTES:
            notes.append(f"{k} is too large to carry between commands")
        elif k in PATH_LIST_VARS and _bad_path_list(v):
            notes.append(f"{k} was not carried between commands: it {_bad_path_list(v)}")
        else:
            new_set[k] = v
    for k in cap.before:
        if k not in cap.after and k not in VOLATILE and k not in admin_env and not k.startswith(HIJACK_PREFIXES) \
                and k not in hijack:
            new_unset.add(k)
    with sess.lock:
        env = dict(sess.env_set)
        unset = set(sess.env_unset)
        for k, v in new_set.items():
            env[k] = v
            unset.discard(k)
        for k in new_unset:
            env.pop(k, None)
            unset.add(k)
        size = sum(len(k) + len(v) + 2 for k, v in env.items())
        if len(env) > MAX_VARS or size > max_env_bytes or len(unset) > MAX_VARS:
            notes.append(f"environment changes from this command were not kept: a session may carry at most "
                         f"{MAX_VARS} variables / {max_env_bytes} bytes")
        else:
            sess.env_set, sess.env_unset = env, unset
        if cap.cwd and cap.cwd.startswith("/") and "\0" not in cap.cwd and len(cap.cwd) < 4096:
            sess.cwd = cap.cwd
        sess.runs += 1
        sess.last_used = time.time()
    return notes
