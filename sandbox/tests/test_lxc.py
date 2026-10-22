import json
import os

import pytest

from conftest import fake_lxc_path, make_cfg
from sbx.backends.base import ExecRequest
from sbx.backends.lxc import LxcBackend
from sbx.errors import SbxError
from sbx.manager import Manager


@pytest.fixture
def lxc(tmp_path, monkeypatch, fake_docker):
    state = fake_lxc_path(tmp_path, monkeypatch)
    monkeypatch.setattr(LxcBackend, "_cgroup2", staticmethod(lambda: True))
    cfg = make_cfg(tmp_path, lxc={"enabled": True, "allow_privileged": True},
                   limits={"allow_outbound": True, "allow_ports": True})
    return Manager(cfg), state


def conf_of(state, rec):
    return json.load(open(os.path.join(state, f"c_{rec.runtime_name}.json")))["conf"]


def test_lxc_roundtrip_and_config(lxc):
    m, state = lxc
    rec = m.create("box", {"backend": "lxc", "image": "debian/bookworm/amd64", "cpus": 1.5, "memory_mb": 256,
                           "pids": 77, "env": {"K": "v"}})
    conf = conf_of(state, rec)
    for want in ("lxc.cgroup2.memory.max = 268435456", "lxc.cgroup2.memory.swap.max = 0",
                 "lxc.cgroup2.cpu.max = 150000 100000", "lxc.cgroup2.pids.max = 77", "lxc.no_new_privs = 1",
                 "lxc.net =", "lxc.net.0.type = empty", "lxc.environment = K=v", "lxc.uts.name = box"):
        assert want in conf, want
    r = m.exec(rec, ExecRequest(["sh", "-c", "echo $K; pwd"], cwd=rec.spec.workdir))
    assert r.out().split() == ["v", os.path.realpath(rec.spec.workdir)]
    assert m.describe(rec)["ip"] == "10.0.3.55"
    m.stop("box")
    assert m.backend("lxc").status(m.get("box")) == "stopped"
    m.start("box")
    m.destroy("box")
    assert m.backend("lxc").status(rec) == "missing"


def test_lxc_outbound_uses_bridge_and_all_tools_get_private_lxcpath(lxc):
    m, state = lxc
    rec = m.create("net", {"backend": "lxc", "image": "alpine/3.19/amd64", "network": "outbound"})
    conf = conf_of(state, rec)
    assert "lxc.net.0.type = veth" in conf and "lxc.net.0.link = lxcbr0" in conf
    for line in open(os.path.join(state, "calls.log")):
        call = json.loads(line)
        if "--list" not in call:
            assert call[call.index("-P") + 1] == m.cfg.lxc.lxcpath


def test_lxc_rejections(lxc):
    m, _ = lxc
    with pytest.raises(SbxError, match="can publish ports only"):
        m.resolve_spec({"backend": "lxc", "image": "debian/bookworm/amd64", "ports": ["80"], "network": "outbound"})
    with pytest.raises(SbxError, match="dist/release/arch"):
        m.resolve_spec({"backend": "lxc", "image": "debian:12"})
    with pytest.raises(SbxError, match="allow-list"):
        m.resolve_spec({"backend": "lxc", "image": "evil/distro/amd64"})


def test_lxc_image_list_and_pull(lxc):
    m, _ = lxc
    refs = [r["ref"] for r in m.list_images("lxc")]
    assert refs == ["debian/bookworm/amd64", "alpine/3.19/amd64"]       # evil/* filtered by allow-list
    assert "available" in m.pull_image("lxc", "debian/bookworm/amd64")
    with pytest.raises(SbxError, match="not offered"):
        m.pull_image("lxc", "debian/nosuchrelease/amd64")
    with pytest.raises(SbxError, match="managed by the download template"):
        m.remove_image("lxc", "debian/bookworm/amd64")


def test_lxc_root_requires_opt_in(tmp_path, monkeypatch, fake_docker):
    fake_lxc_path(tmp_path, monkeypatch)
    monkeypatch.setattr(LxcBackend, "_cgroup2", staticmethod(lambda: True))
    m = Manager(make_cfg(tmp_path, lxc={"enabled": True}))
    ok, detail = m.backend("lxc").available()
    assert (not ok and "PRIVILEGED" in detail) if os.geteuid() == 0 else ok
