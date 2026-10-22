import json
import os
import time

import pytest

from conftest import make_cfg
from sbx.backends.base import ExecRequest
from sbx.errors import FsError, SbxError
from sbx.manager import Manager


def calls(fake_docker):
    return [json.loads(x) for x in open(os.path.join(fake_docker, "calls.log"))]


def test_create_exec_destroy_roundtrip(mgr, fake_docker, cfg):
    rec = mgr.create("alpha", {})
    assert rec.state == "running" and rec.name == "alpha"
    ws = rec.spec.workdir
    r = mgr.exec(rec, ExecRequest(["sh", "-c", "echo hi; pwd"], cwd=ws))
    assert r.ok and r.out().split() == ["hi", os.path.realpath(ws)]
    r = mgr.exec(rec, ExecRequest(["sh", "-c", "exit 3"], cwd=ws))
    assert r.exit_code == 3 and not r.timed_out
    r = mgr.exec(rec, ExecRequest(["cat"], cwd=ws, stdin=b"piped"))
    assert r.out() == "piped"
    r = mgr.exec(rec, ExecRequest(["sh", "-c", "echo $FOO"], cwd=ws, env={"FOO": "bar"}))
    assert r.out().strip() == "bar"
    mgr.destroy("alpha")
    with pytest.raises(SbxError, match="no such sandbox"):
        mgr.get("alpha")
    assert not os.path.exists(os.path.join(cfg.server.state_dir, "sandboxes", "alpha"))


def test_docker_create_args_are_hardened(mgr, fake_docker):
    mgr.create("hard", {"cpus": 2, "memory_mb": 512, "pids": 100, "env": {"A": "1"}})
    create = next(c for c in calls(fake_docker) if c[0] == "create")
    s = " ".join(create)
    for want in ("--cap-drop ALL", "--security-opt no-new-privileges:true", "--cpus 2", "--memory 512m",
                 "--memory-swap 512m", "--pids-limit 100", "--network none", "--init", "--label sbx.managed=1",
                 "--entrypoint sh"):
        assert want in s, want
    assert "-p " not in s and "--privileged" not in s and "--env-file" in s
    # the env file (may hold secrets) is removed after creation
    assert not any(f == "env" for _, _, fs in os.walk(mgr.cfg.server.state_dir) for f in fs)


def test_timeout_kills_inside_guest_and_reports(mgr):
    rec = mgr.create("slow", {})
    t0 = time.time()
    r = mgr.exec(rec, ExecRequest(["sleep", "30"], cwd=rec.spec.workdir, timeout=1.2))
    assert r.timed_out and time.time() - t0 < 6


def test_bad_cwd_is_reported(mgr):
    rec = mgr.create("cwd", {})
    r = mgr.exec(rec, ExecRequest(["true"], cwd="/definitely/not/here"))
    assert r.exit_code == 126 and "can't cd" in r.err() or "cd:" in r.err()


def test_limits_enforced(mgr):
    for over, msg in [({"cpus": 99}, "cpus"), ({"memory_mb": 10**6}, "memory_mb"), ({"pids": 1}, "pids"),
                      ({"ttl_seconds": 10**9}, "ttl"), ({"network": "outbound"}, "network access is disabled"),
                      ({"ports": ["80"]}, "ports is disabled"), ({"image": "evil/thing:1"}, "allow-list"),
                      ({"image": "--privileged"}, "invalid image"), ({"backend": "lxc"}, "disabled"),
                      ({"env": {"bad name": "x"}}, "invalid environment"), ({"env": {"A": "x\ny"}}, "invalid value"),
                      ({"bogus": 1}, "unknown option"), ({"workdir": "/"}, "workdir"), ({"network": "local"}, "network")]:
        with pytest.raises(SbxError, match=msg):
            mgr.resolve_spec(over)


def test_max_sandboxes_and_name_rules(tmp_path, fake_docker):
    m = Manager(make_cfg(tmp_path, limits={"max_sandboxes": 2}))
    m.create("a", {})
    m.create("b", {})
    with pytest.raises(SbxError, match="limit reached"):
        m.create("c", {})
    with pytest.raises(SbxError, match="already exists"):
        m.destroy("b") or m.create("a", {})
    for bad in ("../x", "A", "a b", "-x", "x" * 40, ""):
        if bad:
            with pytest.raises(SbxError, match="invalid sandbox name"):
                m.create(bad, {})


def test_failed_create_rolls_back(mgr, fake_docker, cfg):
    cfg.images.docker.append("missing*")     # allow-listed, but the fake daemon refuses it at `create`
    with pytest.raises(SbxError):
        mgr.create("nope", {"image": "missingimg:1"})
    assert not mgr.reg.exists("nope")


def test_ports_and_network_rules(tmp_path, fake_docker):
    m = Manager(make_cfg(tmp_path, limits={"allow_outbound": True, "allow_ports": True}))
    with pytest.raises(SbxError, match="can publish ports only"):
        m.resolve_spec({"ports": ["80"], "network": "none"})
    with pytest.raises(SbxError, match="outside the allowed range"):
        m.resolve_spec({"ports": ["80:80"], "network": "outbound"})
    rec = m.create("web", {"network": "outbound", "ports": ["8080", "21090:81/udp"]})
    hp = [p.host for p in rec.spec.ports]
    assert 20000 <= hp[0] <= 29999 and hp[1] == 21090
    pubs = [a for c in calls(fake_docker) if c[0] == "create" for i, a in enumerate(c) if c[i - 1] == "-p"]
    assert pubs[0].startswith("127.0.0.1:") and pubs[0].endswith(":8080/tcp")
    with pytest.raises(SbxError, match="already used"):
        m.create("web2", {"network": "outbound", "ports": [f"{rec.spec.ports[0].host}:80"]})


def test_ttl_reaper(tmp_path, fake_docker):
    m = Manager(make_cfg(tmp_path))
    rec = m.create("brief", {"ttl_seconds": 1})
    time.sleep(1.3)
    with pytest.raises(SbxError, match="time limit"):
        m.get("brief")
    assert not m.reg.exists("brief")


def test_profiles_and_defaults(tmp_path, fake_docker):
    m = Manager(make_cfg(tmp_path, profiles={"big": {"cpus": 2.0, "memory_mb": 2048, "env": {"P": "1"}}},
                         sandbox={"env": {"D": "2"}}))
    s = m.resolve_spec({"profile": "big", "memory_mb": 512})
    assert s.cpus == 2.0 and s.memory_mb == 512 and s.env == {"D": "2", "P": "1"}
    with pytest.raises(SbxError, match="unknown profile"):
        m.resolve_spec({"profile": "nope"})


def test_stopped_sandbox_cannot_exec(mgr):
    rec = mgr.create("zz", {})
    mgr.stop("zz")
    with pytest.raises(SbxError, match="is stopped|stopped"):
        mgr.exec(mgr.get("zz"), ExecRequest(["true"]))
    mgr.start("zz")
    assert mgr.exec(mgr.get("zz"), ExecRequest(["true"], cwd="/")).ok


def test_fs_call_runs_agent_in_sandbox(mgr, cfg):
    rec = mgr.create("fs", {})
    fs_cfg = {"roots": [rec.spec.workdir], "read_only": False}
    mgr.fs_call(rec, "write_file", {"path": "a.txt", "content": "hello"}, fs_cfg)
    assert mgr.fs_call(rec, "read_file", {"path": "a.txt"}, fs_cfg)["text"] == "hello"
    with pytest.raises(FsError, match="outside"):
        mgr.fs_call(rec, "read_file", {"path": "/etc/passwd"}, fs_cfg)
    with pytest.raises(FsError, match="read-only"):
        mgr.fs_call(rec, "write_file", {"path": "b", "content": "x"}, {"roots": [rec.spec.workdir]})


def test_images_listing_is_filtered_and_pull_checked(mgr, cfg):
    refs = [r["ref"] for r in mgr.list_images("docker")]
    assert "debian:12-slim" in refs and not any("secretcorp" in r for r in refs)
    assert "pulled" in mgr.pull_image("docker", "debian:12-slim")
    with pytest.raises(SbxError, match="allow-list"):
        mgr.pull_image("docker", "secretcorp/internal:1")
    cfg.images.allow_pull = False
    with pytest.raises(SbxError, match="disabled"):
        mgr.pull_image("docker", "debian:12")
    rec = mgr.create("inuse", {})
    with pytest.raises(SbxError, match="in use"):
        mgr.remove_image("docker", rec.spec.image)
