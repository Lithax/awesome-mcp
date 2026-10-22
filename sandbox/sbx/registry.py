"""Durable sandbox registry: one JSON record per sandbox under <state_dir>/sandboxes/<name>/.

Sandboxes outlive the MCP server process (docker/lxc containers and qemu VMs keep running), and several
server processes can share one state dir; flock-based locks make that safe. Only sandboxes that appear
here can be reached by any tool, so the model can never touch containers it did not create.
"""
from __future__ import annotations

import contextlib
import json
import os
import secrets
import shutil
import socket
import time
from typing import Iterator

from .backends.base import Record
from .errors import SbxError
from .util import file_lock, secure_makedirs, validate_name


class Registry:
    def __init__(self, state_dir: str):
        self.root = state_dir
        self.dir = os.path.join(state_dir, "sandboxes")
        secure_makedirs(self.root)
        secure_makedirs(self.dir)
        self._global = os.path.join(self.root, ".registry.lock")

    # -- locking --
    @contextlib.contextmanager
    def global_lock(self) -> Iterator[None]:
        with file_lock(self._global):
            yield

    @contextlib.contextmanager
    def lock(self, name: str) -> Iterator[None]:
        """Serialise lifecycle operations (start/stop/destroy) on one sandbox across processes."""
        validate_name(name)
        d = os.path.join(self.dir, name)
        secure_makedirs(d)
        with file_lock(os.path.join(d, ".lock"), timeout=300):
            yield

    # -- records --
    def path(self, name: str) -> str:
        return os.path.join(self.dir, validate_name(name), "record.json")

    def get(self, name: str) -> Record:
        try:
            with open(self.path(name), encoding="utf-8") as f:
                return Record.from_json(json.load(f))
        except FileNotFoundError:
            raise SbxError(f"no such sandbox: {name!r} (use sandbox_list)") from None
        except (ValueError, TypeError, KeyError):
            raise SbxError(f"sandbox record for {name!r} is corrupt; destroy it with sandbox_destroy") from None

    def exists(self, name: str) -> bool:
        return os.path.exists(self.path(name))

    def save(self, rec: Record) -> None:
        d = os.path.join(self.dir, rec.name)
        secure_makedirs(d)
        tmp = os.path.join(d, ".record.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(rec.to_json(), f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path(rec.name))

    def list(self) -> list[Record]:
        out = []
        for name in sorted(os.listdir(self.dir)):
            if os.path.exists(os.path.join(self.dir, name, "record.json")):
                with contextlib.suppress(SbxError):
                    out.append(self.get(name))
        return out

    def delete(self, name: str) -> None:
        shutil.rmtree(os.path.join(self.dir, validate_name(name)), ignore_errors=True)

    # -- allocation (call under global_lock) --
    @staticmethod
    def new_id() -> str:
        return secrets.token_hex(3)

    def used_host_ports(self) -> set[int]:
        return {p.host for r in self.list() for p in r.spec.ports}

    def pick_host_port(self, lo: int, hi: int, bind: str, taken: set[int]) -> int:
        span = list(range(lo, hi + 1))
        start = secrets.randbelow(len(span))
        for i in range(len(span)):
            port = span[(start + i) % len(span)]
            if port in taken:
                continue
            fam = socket.AF_INET6 if ":" in bind else socket.AF_INET
            with socket.socket(fam, socket.SOCK_STREAM) as s:
                try:
                    s.bind(("::1" if ":" in bind else "127.0.0.1", port))
                except OSError:
                    continue
            return port
        raise SbxError(f"no free host port in {lo}-{hi}")

    @staticmethod
    def now() -> float:
        return time.time()
