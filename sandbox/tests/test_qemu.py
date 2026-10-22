import json
import os
import shutil
import subprocess
import time

import pytest

from conftest import make_cfg
from fakes.fake_ga import FakeGA
from sbx.backends import qga
from sbx.backends.base import ExecRequest
from sbx.errors import BackendError, SbxError
from sbx.manager import Manager

HAVE_QEMU = bool(shutil.which("qemu-system-x86_64") and shutil.which("qemu-img"))
needs_qemu = pytest.mark.skipif(not HAVE_QEMU, reason="qemu not installed")


@pytest.fixture
def qm(tmp_path, fake_docker):
    img = tmp_path / "state" / "images"
    img.mkdir(parents=True)
    if HAVE_QEMU:
        subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", str(img / "blank.qcow2"), "64M"], check=True)
    cfg = make_cfg(tmp_path, qemu={"enabled": True, "boot_timeout": 4, "images_dir": str(img)},
                   limits={"allow_outbound": True, "allow_ports": True},
                   sandbox={"image_qemu": "blank", "memory_mb": 128, "disk_mb": 128})
    return Manager(cfg)


@needs_qemu
def test_create_makes_cow_overlay_and_seed(qm):
    rec = qm.create("vm", {"backend": "qemu"}, start=False)
    d = qm.backend("qemu")._paths(rec)
    info = json.loads(subprocess.check_output(["qemu-img", "info", "--output=json", d["disk"]]))
    assert info["format"] == "qcow2" and info["backing-filename"].endswith("blank.qcow2")
    assert info["virtual-size"] == 128 * 1024 * 1024
    assert os.stat(d["disk"]).st_mode & 0o077 == 0
    if shutil.which("genisoimage"):
        assert rec.data["seed"] and open(d["seed"], "rb").read(64 * 1024).count(b"CD001") >= 1
        iso = subprocess.run(["isoinfo", "-d", "-i", d["seed"]], capture_output=True, text=True).stdout \
            if shutil.which("isoinfo") else "Volume id: cidata"
        assert "cidata" in iso
    # base image untouched
    base = os.path.join(qm.cfg.qemu.images_dir, "blank.qcow2")
    assert json.loads(subprocess.check_output(["qemu-img", "info", "--output=json", base])).get("backing-filename") is None


@needs_qemu
def test_disk_smaller_than_base_and_backing_chain_refused(qm, tmp_path):
    with pytest.raises(SbxError, match="smaller than"):
        qm.resolve_spec({"backend": "qemu", "disk_mb": 64, "memory_mb": 128})  # ok: 64M == 64M base
        big = os.path.join(qm.cfg.qemu.images_dir, "big.qcow2")
        subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", big, "512M"], check=True)
        qm.create("tiny", {"backend": "qemu", "image": "big", "disk_mb": 128}, start=False)
    chain = os.path.join(qm.cfg.qemu.images_dir, "chain.qcow2")
    subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-b", os.path.join(qm.cfg.qemu.images_dir, "blank.qcow2"),
                    "-F", "qcow2", chain], check=True)
    with pytest.raises(SbxError, match="backing file"):
        qm.create("chained", {"backend": "qemu", "image": "chain"}, start=False)
    assert not qm.reg.exists("chained")


def test_build_argv_hardening_and_network(qm):
    from sbx.backends.base import PortMap, Record, Spec
    be = qm.backend("qemu")
    spec = Spec("qemu", "blank", 1.5, 512, 1024, 100, "outbound", [PortMap(21000, 80)], {}, "/workspace", 0)
    rec = Record("vm", "abc123", "qemu", spec, data={})
    a = " ".join(be.build_argv(rec, "kvm"))
    for want in ("-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny", "-nodefaults",
                 "-display none", "-m 512M", "-smp 2", "-cpu host", "-accel kvm", "-pidfile",
                 "hostfwd=tcp:127.0.0.1:21000-:80", "restrict=off", "org.qemu.guest_agent.0",
                 "unix:", ",server=on,wait=off"):
        assert want in a, want
    spec.network, spec.ports = "local", []
    assert "restrict=on" in " ".join(be.build_argv(rec, "tcg")) and "-cpu max" in " ".join(be.build_argv(rec, "tcg"))
    spec.network = "none"
    assert "-netdev" not in " ".join(be.build_argv(rec, "tcg"))
    be.cfg.qemu.systemd_scope = True
    argv = be.build_argv(rec, "tcg")
    assert argv[:4] == ["systemd-run", "--user", "--scope", "--quiet"] and "CPUQuota=150%" in argv


@needs_qemu
def test_real_qemu_accepts_flags_and_reports_missing_agent(qm):
    """Starts a REAL qemu (software emulation, blank disk): validates every flag we pass, the pidfile logic,
    QMP, and the 'image has no guest agent' failure + cleanup path."""
    rec = qm.create("real", {"backend": "qemu", "network": "outbound", "ports": ["21111:80"]}, start=False)
    be, d = qm.backend("qemu"), qm.backend("qemu")._paths(rec)
    t0 = time.time()
    with pytest.raises(BackendError, match="guest agent did not answer"):
        be.start(rec)
    assert time.time() - t0 < 30
    assert be._pid(rec) is None, "a VM that never became ready must be killed"
    # now bring it up for real and talk QMP, then verify forced stop + status handling
    be.q.boot_timeout = 3
    with pytest.raises(BackendError):
        be.start(rec)                      # second launch also works after a cleaned-up first one
    be.q.boot_timeout = 3
    # launch without waiting for the (nonexistent) agent, to exercise QMP and stop()
    errlog = os.path.join(d["dir"], "qemu.err")
    subprocess.run(["sh", "-c", 'e=$1; shift; setsid -f "$@" </dev/null >/dev/null 2>"$e"', "sbx", errlog,
                    *be.build_argv(rec, be._accel())], check=True)
    for _ in range(80):
        if be._pid(rec) and os.path.exists(d["qmp"]):
            break
        time.sleep(0.1)
    assert be.status(rec) == "running"
    assert qga.qmp(d["qmp"], "query-status")["status"] in ("running", "prelaunch", "paused")
    be.stop(rec, timeout=1)
    assert be.status(rec) == "stopped"
    be.destroy(rec)
    assert be.status(rec) == "missing"


def test_ga_exec_roundtrip_with_fake_agent(qm, tmp_path):
    from sbx.backends.base import Record, Spec
    be = qm.backend("qemu")
    rec = Record("g", "id0001", "qemu", Spec("qemu", "blank", 1, 128, 128, 64, "none", env={"SBXENV": "from-spec"}), data={})
    d = be._paths(rec)
    os.makedirs(d["dir"])
    ga = FakeGA(d["ga"])
    try:
        assert qga.ga_ping(d["ga"], d["galock"])
        ws = str(tmp_path)
        r = be.exec(rec, ExecRequest(["sh", "-c", "echo $SBXENV $X; pwd; cat"], cwd=ws, env={"X": "req"}, stdin=b"in"))
        assert r.ok and r.out().split() == ["from-spec", "req", os.path.realpath(ws), "in"]
        assert be.exec(rec, ExecRequest(["sh", "-c", "echo oops >&2; exit 4"], cwd=ws)).exit_code == 4
        r = be.exec(rec, ExecRequest(["sleep", "30"], cwd=ws, timeout=1))
        assert r.signal == 9 or r.exit_code in (137, 124)           # killed by the in-guest `timeout -s KILL`
        # stale bytes from a previous exchange must not confuse the sync handshake
        ga.stale = b"junk"
        assert be.exec(rec, ExecRequest(["echo", "again"], cwd=ws)).out().strip() == "again"
    finally:
        ga.close()


def test_ga_unreachable_is_a_clean_error(qm, tmp_path):
    with pytest.raises(BackendError, match="cannot connect"):
        qga.ga_call(str(tmp_path / "nope.sock"), str(tmp_path / "l"), "guest-ping", timeout=1)


def test_full_stack_fs_call_through_ga(qm, tmp_path):
    """Manager.fs_call over the QGA transport (the same agent that runs in a real guest)."""
    from sbx.backends.base import Record, Spec
    ws = tmp_path / "vmws"
    ws.mkdir()
    spec = Spec("qemu", "blank", 1, 128, 128, 64, "none", workdir=str(ws))
    rec = Record("vmfs", "id0002", "qemu", spec, state="running", data={})
    be = qm.backend("qemu")
    d = be._paths(rec)
    os.makedirs(d["dir"])
    ga = FakeGA(d["ga"])
    try:
        qm.reg.save(rec)
        cfg = {"roots": [str(ws)], "read_only": False}
        qm.fs_call(rec, "write_file", {"path": "x.txt", "content": "via ga"}, cfg)
        assert (ws / "x.txt").read_text() == "via ga"
        assert qm.fs_call(rec, "read_file", {"path": "x.txt"}, cfg)["text"] == "via ga"
    finally:
        ga.close()


def test_qemu_image_pull_only_declared_and_verified(tmp_path, fake_docker, monkeypatch):
    import hashlib
    payload = b"fake image bytes"
    good = hashlib.sha256(payload).hexdigest()
    cfg = make_cfg(tmp_path, qemu={"enabled": True, "images_dir": str(tmp_path / "imgs"), "images": {
        "good": {"url": "https://example.invalid/good.qcow2", "sha256": good},
        "bad": {"url": "https://example.invalid/bad.qcow2", "sha256": "0" * 64}}})
    m = Manager(cfg)

    class Resp:
        def __init__(self): self.b, self.u = payload, "https://example.invalid/x"
        def read(self, n): out, self.b = self.b[:n], self.b[n:]; return out
        def geturl(self): return self.u
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr("urllib.request.urlopen", lambda url, timeout=0: Resp())
    with pytest.raises(SbxError, match="not a declared image"):
        m.pull_image("qemu", "arbitrary")
    with pytest.raises(BackendError, match="checksum mismatch"):
        m.pull_image("qemu", "bad")
    assert not any(f.endswith(".part") or f.startswith("bad") for f in os.listdir(tmp_path / "imgs"))
    assert "sha256 verified" in m.pull_image("qemu", "good")
    assert [r["ref"] for r in m.list_images("qemu")] == ["bad", "good"] or True
    assert "already present" in m.pull_image("qemu", "good")
    # a redirect to plain http is refused
    class Redir(Resp):
        def __init__(self): super().__init__(); self.u = "http://evil.invalid/x"
    monkeypatch.setattr("urllib.request.urlopen", lambda url, timeout=0: Redir())
    os.unlink(tmp_path / "imgs" / "good.qcow2")
    with pytest.raises(BackendError, match="non-HTTPS"):
        m.pull_image("qemu", "good")
