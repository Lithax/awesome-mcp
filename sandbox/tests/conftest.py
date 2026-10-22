import os
import shutil
import stat
import sys

import pytest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.dirname(HERE))

from sbx import config as C  # noqa: E402
from sbx.manager import Manager  # noqa: E402


@pytest.fixture
def fake_docker(tmp_path, monkeypatch):
    d = tmp_path / "fakedocker"
    d.mkdir()
    monkeypatch.setenv("FAKE_DOCKER_DIR", str(d))
    return str(d)


def fake_bin(tmp_path, name="docker"):
    """A wrapper that pins FAKE_DOCKER_DIR (the manager scrubs the environment given to runtime CLIs)."""
    d = tmp_path / "fakedocker"
    d.mkdir(exist_ok=True)
    w = tmp_path / ("bin-" + name)
    w.write_text(f"#!/bin/sh\nFAKE_DOCKER_DIR={d} exec {sys.executable} {HERE}/fakes/docker \"$@\"\n")
    w.chmod(0o755)
    return str(w)


def make_cfg(tmp_path, **over):
    ws = tmp_path / "guest-ws"
    ws.mkdir(exist_ok=True)
    raw = {
        "server": {"state_dir": str(tmp_path / "state")},
        "docker": {"binary": fake_bin(tmp_path)},
        "sandbox": {"workdir": str(ws), "ttl_seconds": 600},
        "fs": {"guest_roots": [str(ws)], "read_only": False, "allow_delete": True},
        "shell": {"limits": {"timeout_seconds": 20, "max_timeout_seconds": 60}},
    }
    for k, v in over.items():
        raw.setdefault(k, {}).update(v) if isinstance(v, dict) else raw.__setitem__(k, v)
    return C.from_dict(raw)


@pytest.fixture
def cfg(tmp_path, fake_docker):
    return make_cfg(tmp_path)


@pytest.fixture
def mgr(cfg):
    return Manager(cfg)


def fake_lxc_path(tmp_path, monkeypatch):
    """Put fake lxc-* tools first in PATH (each pins FAKE_LXC_DIR) and return the state dir."""
    state = tmp_path / "fakelxc"
    state.mkdir(exist_ok=True)
    bindir = tmp_path / "lxcbin"
    bindir.mkdir(exist_ok=True)
    from sbx.backends.lxc import TOOLS
    for t in TOOLS:
        w = bindir / t
        w.write_text(f"#!/bin/sh\nFAKE_LXC_DIR={state} exec {sys.executable} {HERE}/fakes/lxc \"$0\" \"$@\"\n")
        w.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    return str(state)
