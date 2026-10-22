"""The backend contract shared by docker / lxc / qemu, plus the data types that cross it."""
from __future__ import annotations

import abc
import dataclasses
import math
import os
from dataclasses import dataclass, field
from typing import Any

from ..util import CmdResult

__all__ = ["PortMap", "Mount", "Spec", "Record", "ExecRequest", "Backend", "guest_wrap", "CmdResult", "GUEST_PYTHON"]


@dataclass
class PortMap:
    host: int
    guest: int
    proto: str = "tcp"
    bind: str = "127.0.0.1"

    def __str__(self) -> str:
        return f"{self.bind}:{self.host}->{self.guest}/{self.proto}"


@dataclass
class Mount:
    """A host folder mapped into the sandbox. `host` is the resolved real path (never shown to the model)."""
    host: str
    guest: str
    mode: str = "ro"                 # "ro" | "rw"
    name: str = ""                   # the [mounts.NAME] it came from

    @property
    def rw(self) -> bool:
        return self.mode == "rw"


@dataclass
class Spec:
    """A fully resolved, validated environment description. Stored with the sandbox."""
    backend: str
    image: str
    cpus: float
    memory_mb: int
    disk_mb: int
    pids: int
    network: str
    ports: list[PortMap] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    workdir: str = "/workspace"
    ttl_seconds: int = 0
    profile: str = ""
    mounts: list[Mount] = field(default_factory=list)   # parents first (see mounts.in_mount_order)

    def to_json(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "Spec":
        d = dict(d)
        d["ports"] = [PortMap(**p) for p in d.get("ports", [])]
        d["mounts"] = [Mount(**m) for m in d.get("mounts", [])]      # records from before mappings existed have none
        return cls(**d)


@dataclass
class Record:
    name: str
    id: str
    backend: str
    spec: Spec
    state: str = "creating"          # creating | running | stopped | error
    created_at: float = 0.0
    expires_at: float = 0.0          # 0 = never
    data: dict[str, Any] = field(default_factory=dict)   # backend-private (runtime ids, ssh keys, ...)
    error: str = ""

    @property
    def runtime_name(self) -> str:
        return f"sbx-{self.name}-{self.id}"

    def to_json(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["spec"] = self.spec.to_json()
        return d

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "Record":
        d = dict(d)
        d["spec"] = Spec.from_json(d["spec"])
        return cls(**d)


@dataclass
class ExecRequest:
    argv: list[str]
    cwd: str = "/"
    env: dict[str, str] = field(default_factory=dict)
    stdin: bytes | None = None
    timeout: float = 60.0
    max_output: int = 1 << 20


# Finds an interpreter for the filesystem agent without assuming a name.
GUEST_PYTHON = ('P=$(command -v python3 || command -v python) || '
                '{ echo "sandbox has no python3: the filesystem tools need it (shell commands still work)" >&2; exit 127; }; '
                'exec "$P" -c "$1"')

# cd, then run under `timeout` when the guest has it. SIGKILL: a timeout must really stop the command.
_WRAP = ('d=$1; t=$2; shift 2; cd "$d" || exit 126; '
         'if command -v timeout >/dev/null 2>&1; then exec timeout -s KILL "$t" "$@"; else exec "$@"; fi')


def guest_wrap(req: ExecRequest) -> list[str]:
    """Wrap req.argv so it runs in req.cwd, with req.env, killed after req.timeout seconds *inside the guest*.

    `docker exec` / `lxc-attach` / guest-exec do not kill the guest process when the client goes away,
    so the deadline has to live in the guest.
    """
    cmd = ["sh", "-c", _WRAP, "sbx", req.cwd or "/", str(max(1, math.ceil(req.timeout)))]
    if req.env:
        cmd += ["env", "--"] + [f"{k}={v}" for k, v in req.env.items()]
    return cmd + list(req.argv)


class Backend(abc.ABC):
    """One runtime. Instances are cheap and stateless: all durable state is in the registry/runtime."""

    name = ""
    networks: tuple[str, ...] = ("none",)
    ports_networks: tuple[str, ...] = ()       # networks on which published ports work
    caveats: tuple[str, ...] = ()              # limitations worth telling the user about

    def __init__(self, cfg, state_dir: str):
        self.cfg = cfg
        self.state_dir = state_dir

    # -- helpers --
    def rec_dir(self, rec: Record) -> str:
        return os.path.join(self.state_dir, "sandboxes", rec.name)

    # -- capability / health --
    @abc.abstractmethod
    def available(self) -> tuple[bool, str]:
        """(usable, human-readable detail). Must be cheap and never raise."""

    def validate(self, spec: Spec) -> None:
        """Raise SbxError if this backend cannot honour the spec."""

    # -- images --
    @abc.abstractmethod
    def list_images(self) -> list[dict[str, Any]]: ...

    @abc.abstractmethod
    def pull_image(self, ref: str) -> str: ...

    @abc.abstractmethod
    def remove_image(self, ref: str) -> None: ...

    # -- lifecycle --
    @abc.abstractmethod
    def create(self, rec: Record) -> dict[str, Any]:
        """Create (not start) the runtime object; return backend-private data to store on the record."""

    @abc.abstractmethod
    def start(self, rec: Record) -> None: ...

    @abc.abstractmethod
    def stop(self, rec: Record, timeout: int = 10) -> None: ...

    @abc.abstractmethod
    def destroy(self, rec: Record) -> None:
        """Remove everything. Must succeed (idempotently) even if the runtime object is already gone."""

    @abc.abstractmethod
    def status(self, rec: Record) -> str:
        """'running' | 'stopped' | 'missing'."""

    @abc.abstractmethod
    def info(self, rec: Record) -> dict[str, Any]: ...

    @abc.abstractmethod
    def exec(self, rec: Record, req: ExecRequest) -> CmdResult: ...
