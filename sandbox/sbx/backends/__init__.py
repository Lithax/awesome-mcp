"""Backend factory."""
from __future__ import annotations

from ..errors import SbxError
from .base import Backend


def make_backend(name: str, cfg, state_dir: str) -> Backend:
    if name == "docker":
        from .docker import DockerBackend
        return DockerBackend(cfg, state_dir)
    if name == "lxc":
        from .lxc import LxcBackend
        return LxcBackend(cfg, state_dir)
    if name == "qemu":
        from .qemu import QemuBackend
        return QemuBackend(cfg, state_dir)
    raise SbxError(f"unknown backend {name!r}")
