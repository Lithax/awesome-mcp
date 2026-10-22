"""Clients for the two control sockets of a QEMU VM: QMP (the monitor) and the QEMU Guest Agent (QGA).

QGA is how we run commands inside a VM without any network (the agent talks over a virtio-serial port).
Its chardev accepts ONE client at a time, so every request is a short connect -> sync -> command ->
close exchange guarded by a cross-process file lock; long-running guest commands are polled.
"""
from __future__ import annotations

import base64
import json
import os
import random
import socket
import time
from typing import Any

from ..errors import BackendError
from ..util import CmdResult, file_lock

MAX_REPLY = 512 * 1024 * 1024


class _LineConn:
    def __init__(self, path: str, timeout: float):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        try:
            self.sock.connect(path)
        except OSError as e:
            self.sock.close()
            raise BackendError(f"cannot connect to the VM control socket ({e.strerror or e})") from None
        self.buf = b""

    def send(self, obj: dict[str, Any], prefix: bytes = b"") -> None:
        self.sock.sendall(prefix + json.dumps(obj).encode() + b"\n")

    def read_obj(self, deadline: float) -> dict[str, Any]:
        while True:
            nl = self.buf.find(b"\n")
            if nl >= 0:
                line, self.buf = self.buf[:nl], self.buf[nl + 1:]
                line = line.lstrip(b"\xff").strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if isinstance(obj, dict):
                    return obj
                continue
            left = deadline - time.monotonic()
            if left <= 0:
                raise BackendError("timed out waiting for the VM")
            self.sock.settimeout(left)
            try:
                chunk = self.sock.recv(1 << 20)
            except socket.timeout:
                raise BackendError("timed out waiting for the VM") from None
            except OSError as e:
                raise BackendError(f"VM control socket error: {e.strerror or e}") from None
            if not chunk:
                raise BackendError("VM control socket closed")
            self.buf += chunk
            if len(self.buf) > MAX_REPLY:
                raise BackendError("VM reply too large")

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


# ------------------------------------------------------------------------------ QMP

def qmp(path: str, command: str, arguments: dict[str, Any] | None = None, timeout: float = 10.0) -> Any:
    c = _LineConn(path, timeout)
    deadline = time.monotonic() + timeout
    try:
        c.read_obj(deadline)                       # greeting
        c.send({"execute": "qmp_capabilities"})
        while "return" not in (r := c.read_obj(deadline)) and "error" not in r:
            pass                                    # skip async events
        c.send({"execute": command, **({"arguments": arguments} if arguments else {})})
        while True:
            r = c.read_obj(deadline)
            if "return" in r:
                return r["return"]
            if "error" in r:
                raise BackendError(f"qmp {command}: {r['error'].get('desc', r['error'])}")
    finally:
        c.close()


# ------------------------------------------------------------------------------ QGA

def ga_call(path: str, lock_path: str, command: str, arguments: dict[str, Any] | None = None,
            timeout: float = 15.0) -> Any:
    """One serialised QGA request. Raises BackendError if the agent does not answer in time."""
    with file_lock(lock_path, timeout=timeout + 30):
        c = _LineConn(path, timeout)
        deadline = time.monotonic() + timeout
        try:
            sync_id = random.randint(1, 2**31 - 1)
            c.send({"execute": "guest-sync-delimited", "arguments": {"id": sync_id}}, prefix=b"\xff")
            while True:                              # discard stale replies from earlier exchanges
                r = c.read_obj(deadline)
                if r.get("return") == sync_id:
                    break
            c.send({"execute": command, **({"arguments": arguments} if arguments else {})})
            r = c.read_obj(deadline)
            if "error" in r:
                raise BackendError(f"guest agent {command}: {r['error'].get('desc', r['error'])}")
            return r.get("return")
        finally:
            c.close()


def ga_ping(path: str, lock_path: str, timeout: float = 3.0) -> bool:
    try:
        ga_call(path, lock_path, "guest-ping", timeout=timeout)
        return True
    except BackendError:
        return False


GUEST_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root",
             "LANG": "C.UTF-8", "TERM": "dumb"}


def ga_exec(path: str, lock_path: str, argv: list[str], *, env: dict[str, str], stdin: bytes | None,
            timeout: float, max_output: int) -> CmdResult:
    """Run argv in the guest and wait for it. The deadline inside the guest is enforced by the caller
    wrapping argv in `timeout -s KILL`; `timeout` here is only the host-side give-up time."""
    started = time.monotonic()
    exe = "/bin/sh" if argv[0] == "sh" else argv[0]
    args: dict[str, Any] = {"path": exe, "arg": argv[1:], "capture-output": True,
                            "env": [f"{k}={v}" for k, v in {**GUEST_ENV, **env}.items()]}
    if stdin:
        args["input-data"] = base64.b64encode(stdin).decode("ascii")
    pid = ga_call(path, lock_path, "guest-exec", args, timeout=30.0 + len(stdin or b"") / (4 << 20))["pid"]
    deadline = started + timeout
    delay = 0.02
    while True:
        st = ga_call(path, lock_path, "guest-exec-status", {"pid": pid}, timeout=30.0)
        if st.get("exited"):
            break
        if time.monotonic() > deadline:
            return CmdResult(None, b"", b"", timed_out=True, duration=time.monotonic() - started)
        time.sleep(delay)
        delay = min(delay * 1.5, 0.25)
    out = base64.b64decode(st.get("out-data", "") or b"")
    err = base64.b64decode(st.get("err-data", "") or b"")
    trunc = bool(st.get("out-truncated") or st.get("err-truncated") or len(out) > max_output or len(err) > max_output)
    sig = st.get("signal")
    return CmdResult(None if sig else st.get("exitcode", 0), out[:max_output], err[:max_output], False, trunc,
                     False, time.monotonic() - started, sig)


def sock_paths(rec_dir: str) -> tuple[str, str, str]:
    return (os.path.join(rec_dir, "qmp.sock"), os.path.join(rec_dir, "ga.sock"), os.path.join(rec_dir, "ga.lock"))
