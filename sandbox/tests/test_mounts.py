"""Folder mappings (host <-> sandbox): validation, gating, and what each backend hands to its runtime."""
import json
import os
import shutil
import subprocess

import pytest

from conftest import fake_lxc_path, make_cfg
from sbx import config as C
from sbx import mounts as M
from sbx.backends import qemu as Q
from sbx.backends.base import ExecRequest, Mount, Record, Spec
from sbx.backends.lxc import LxcBackend, fstab_escape
from sbx.backends.qemu import QemuBackend
from sbx.errors import BackendError, ConfigError, SbxError
from sbx.util import CmdResult
from sbx.manager import Manager


# --------------------------------------------------------------------------------------- helpers

def calls(fake_docker):
    return [json.loads(x) for x in open(os.path.join(fake_docker, "calls.log"))]


def create_call(fake_docker):
    return next(c for c in calls(fake_docker) if c[0] == "create")


def flag_values(argv, flag):
    return [argv[i + 1] for i, a in enumerate(argv) if a == flag]


@pytest.fixture
def host(tmp_path):
    d = tmp_path / "hostproj"
    d.mkdir()
    (d / "hello.txt").write_text("from the host")
    return d


def cfg_with(tmp_path, host, mode="ro", attach=True, **over):
    over.setdefault("mounts", {"proj": {"host": str(host), "guest": "/workspace/proj", "mode": mode}})
    if attach:
        over.setdefault("sandbox", {})["mounts"] = ["proj"]
    return make_cfg(tmp_path, **over)


# ------------------------------------------------------------------------------ config validation

def test_declaration_is_normalised_and_read_only_by_default(tmp_path, host, fake_docker):
    cfg = make_cfg(tmp_path, mounts={"proj": {"host": str(host), "guest": "/workspace//proj/"}})
    assert cfg.mounts["proj"] == {"host": os.path.realpath(host), "guest": "/workspace/proj", "mode": "ro"}


def test_tilde_and_symlinks_resolve(tmp_path, host, fake_docker, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    link = tmp_path / "link"
    link.symlink_to(host)
    cfg = make_cfg(tmp_path, mounts={"a": {"host": "~/link", "guest": "/a"}})
    assert cfg.mounts["a"]["host"] == os.path.realpath(host)


@pytest.mark.parametrize("body, msg", [
    ({"host": "relative/dir", "guest": "/x"}, "absolute"),
    ({"host": "/tmp/a,b", "guest": "/x"}, "commas"),
    ({"host": '/tmp/a"b', "guest": "/x"}, "commas"),
    ({"host": "@", "guest": "x"}, "absolute path inside"),
    ({"host": "@", "guest": "/a/../b"}, r"\.\."),
    ({"host": "@", "guest": "/"}, "cannot be"),
    ({"host": "@", "guest": "/proc"}, "nothing may be mapped"),
    ({"host": "@", "guest": "/dev/shm/x"}, "nothing may be mapped"),
    ({"host": "@", "guest": "/has space"}, "only letters"),
    ({"host": "@", "guest": "/x", "mode": "rwx"}, "'ro' or 'rw'"),
    ({"host": "@", "guest": "/x", "readonly": True}, "unknown setting"),
    ({"host": "@"}, "needs 'guest'"),
    ({"guest": "/x"}, "needs 'host'"),
    ({"host": "/", "guest": "/x"}, "filesystem root"),
    ({"host": "/proc/self", "guest": "/x"}, "pseudo filesystems"),
    ({"host": "/sys", "guest": "/x"}, "pseudo filesystems"),
    ({"host": "/run/user/1000", "guest": "/x"}, "sockets"),
    ({"host": "/var/run/docker", "guest": "/x"}, "sockets"),
])
def test_bad_declarations_are_loud(tmp_path, host, fake_docker, body, msg):
    body = {k: (str(host) if v == "@" else v) for k, v in body.items()}      # "@" = a harmless host folder
    with pytest.raises(ConfigError, match=msg):
        make_cfg(tmp_path, mounts={"m": body})


def test_removable_media_under_run_is_allowed(tmp_path, fake_docker):
    cfg = make_cfg(tmp_path, mounts={"usb": {"host": "/run/media/me/DRIVE", "guest": "/usb"}})
    assert cfg.mounts["usb"]["host"] == "/run/media/me/DRIVE"


def test_the_servers_own_files_cannot_be_mapped(tmp_path, fake_docker):
    state = tmp_path / "state"
    for bad in (tmp_path, state, state / "sandboxes"):                  # parent of, equal to, inside the state dir
        with pytest.raises(ConfigError, match="state directory"):
            make_cfg(tmp_path, mounts={"m": {"host": str(bad), "guest": "/x"}})
    logs = tmp_path / "logs"
    logs.mkdir()
    with pytest.raises(ConfigError, match="audit log"):
        make_cfg(tmp_path, audit={"log_file": str(logs / "a.jsonl")}, mounts={"m": {"host": str(logs), "guest": "/x"}})
    imgs = tmp_path / "elsewhere" / "images"
    imgs.mkdir(parents=True)
    with pytest.raises(ConfigError, match="QEMU image directory"):
        make_cfg(tmp_path, qemu={"images_dir": str(imgs)}, mounts={"m": {"host": str(imgs.parent), "guest": "/x"}})
    lxcdir = tmp_path / "lxcdir"
    lxcdir.mkdir()
    with pytest.raises(ConfigError, match="LXC container directory"):
        make_cfg(tmp_path, lxc={"lxcpath": str(lxcdir)}, mounts={"m": {"host": str(lxcdir), "guest": "/x"}})


def test_config_file_itself_cannot_be_mapped(tmp_path, fake_docker):
    cfgdir = tmp_path / "cfgdir"
    cfgdir.mkdir()
    cfgfile = cfgdir / "config.toml"
    cfgfile.write_text("")
    raw = {"server": {"state_dir": str(tmp_path / "state")}, "mounts": {"m": {"host": str(cfgdir), "guest": "/x"}}}
    with pytest.raises(ConfigError, match="config file"):
        C.from_dict(raw, str(cfgfile))


def test_server_code_is_protected_only_when_writable(tmp_path, fake_docker):
    code = M.CODE_DIR
    with pytest.raises(ConfigError, match="server's own code"):
        make_cfg(tmp_path, mounts={"m": {"host": code, "guest": "/x", "mode": "rw"}})
    assert make_cfg(tmp_path, mounts={"m": {"host": code, "guest": "/x", "mode": "ro"}}).mounts["m"]["mode"] == "ro"


def test_references_are_validated(tmp_path, host, fake_docker):
    decl = {"proj": {"host": str(host), "guest": "/a"}, "other": {"host": str(host), "guest": "/a"}}
    with pytest.raises(ConfigError, match="unknown mapping 'nope'"):
        make_cfg(tmp_path, mounts=decl, sandbox={"mounts": ["nope"]})
    with pytest.raises(ConfigError, match="unknown mapping 'nope'"):
        make_cfg(tmp_path, mounts=decl, profiles={"p": {"mounts": ["nope"]}})
    with pytest.raises(ConfigError, match="twice"):
        make_cfg(tmp_path, mounts=decl, sandbox={"mounts": ["proj", "proj"]})
    with pytest.raises(ConfigError, match="same sandbox path"):
        make_cfg(tmp_path, mounts=decl, sandbox={"mounts": ["proj", "other"]})
    with pytest.raises(ConfigError, match="at most 1"):
        make_cfg(tmp_path, mounts={**decl, "other": {"host": str(host), "guest": "/b"}},
                 sandbox={"mounts": ["proj", "other"]}, limits={"max_mounts": 1})
    with pytest.raises(ConfigError, match="mount_selinux"):
        make_cfg(tmp_path, docker={"mount_selinux": "yes"})


# --------------------------------------------------------------------------------------- CLI flag

@pytest.mark.parametrize("item, want", [
    ("/a:/b", {"host": "/a", "guest": "/b", "mode": "ro"}),
    ("/a:/b:rw", {"host": "/a", "guest": "/b", "mode": "rw"}),
    ("/a:/b:ro", {"host": "/a", "guest": "/b", "mode": "ro"}),
])
def test_cli_parse(item, want):
    assert M.parse_cli(item) == want


@pytest.mark.parametrize("item", ["/a", "/a:", ":/b", "/a:/b:c", "/a:/b:rw:x", ""])
def test_cli_parse_rejects(item):
    with pytest.raises(ConfigError, match="HOST:GUEST"):
        M.parse_cli(item)


def test_cli_mount_adds_to_the_config_file_and_is_validated(tmp_path, host, fake_docker):
    other = tmp_path / "other"
    other.mkdir()
    cfgfile = tmp_path / "c.toml"
    cfgfile.write_text(f'[server]\nstate_dir = "{tmp_path}/state"\n[mounts.keep]\nhost = "{host}"\nguest = "/keep"\n'
                       f'[sandbox]\nmounts = ["keep"]\n')
    import argparse
    p = argparse.ArgumentParser()
    C.add_cli_args(p)
    cfg = C.build_config(p.parse_args(["--config", str(cfgfile), "--mount", f"{other}:/extra:rw"]))
    assert cfg.sandbox.mounts == ["keep", "cli1"]
    assert cfg.mounts["cli1"] == {"host": os.path.realpath(other), "guest": "/extra", "mode": "rw"}
    with pytest.raises(ConfigError, match="state directory"):
        C.build_config(p.parse_args(["--config", str(cfgfile), "--mount", f"{tmp_path}/state:/x"]))


# ------------------------------------------------------------------------------------- the manager

def test_default_mapping_reaches_the_spec_and_is_hidden_from_the_model(tmp_path, host, fake_docker):
    m = Manager(cfg_with(tmp_path, host, mode="rw"))
    rec = m.create("a", {})
    (mt,) = rec.spec.mounts
    assert (mt.host, mt.guest, mt.mode, mt.name) == (os.path.realpath(host), "/workspace/proj", "rw", "proj")
    d = m.describe(rec)
    assert d["mounts"] == [{"name": "proj", "guest": "/workspace/proj", "mode": "rw"}]
    assert str(host) not in json.dumps(d)
    # survives a registry round trip (records written before mappings existed load too)
    assert m.get("a").spec.mounts == rec.spec.mounts
    old = rec.spec.to_json()
    del old["mounts"]
    assert Spec.from_json(old).mounts == []


def test_profile_mounts_and_ordering(tmp_path, host, fake_docker):
    deep = tmp_path / "deep"
    deep.mkdir()
    cfg = make_cfg(tmp_path, mounts={"outer": {"host": str(host), "guest": "/w"},
                                     "inner": {"host": str(deep), "guest": "/w/sub/inner", "mode": "rw"}},
                   profiles={"both": {"mounts": ["inner", "outer"]}})
    spec = Manager(cfg).resolve_spec({"profile": "both"})
    assert [m.guest for m in spec.mounts] == ["/w", "/w/sub/inner"]        # parents first


def test_model_cannot_choose_mappings_unless_enabled(tmp_path, host, fake_docker):
    m = Manager(cfg_with(tmp_path, host))
    with pytest.raises(SbxError, match="not enabled"):
        m.resolve_spec({"mounts": ["proj"]})
    # an empty list must not strip what the administrator attached
    assert [x.name for x in m.resolve_spec({"mounts": []}).mounts] == ["proj"]


def test_model_may_choose_declared_names_when_enabled(tmp_path, host, fake_docker):
    m = Manager(cfg_with(tmp_path, host, attach=False, limits={"allow_mount_requests": True}))
    assert m.resolve_spec({}).mounts == []
    assert [x.name for x in m.resolve_spec({"mounts": ["proj"]}).mounts] == ["proj"]
    with pytest.raises(SbxError, match=r"unknown folder mapping 'etc' \(available: proj\)"):
        m.resolve_spec({"mounts": ["etc"]})
    with pytest.raises(SbxError, match="twice"):
        m.resolve_spec({"mounts": ["proj", "proj"]})
    assert m.resolve_spec({"mounts": []}).mounts == []                      # may drop them: that is less access


def test_host_folder_is_rechecked_when_the_sandbox_is_created(tmp_path, host, fake_docker):
    m = Manager(cfg_with(tmp_path, host))
    shutil.rmtree(host)
    with pytest.raises(SbxError, match="does not exist"):
        m.create("gone", {})
    assert not m.reg.exists("gone")
    host.symlink_to(tmp_path / "state")                                      # swapped for a link into the state dir
    with pytest.raises(SbxError, match="cannot be used.*state directory"):
        m.create("swapped", {})
    assert not m.reg.exists("swapped")
    host.unlink()
    host.write_text("a file, not a directory")
    with pytest.raises(SbxError, match="not a directory"):
        m.create("file", {})


def test_approval_text_names_the_folder_and_flags_write_access(tmp_path, host, fake_docker):
    rw = Manager(cfg_with(tmp_path, host, mode="rw")).resolve_spec({})
    ro = Manager(cfg_with(tmp_path, host, mode="ro")).resolve_spec({})
    (risk,) = Manager.risks(rw)
    assert os.path.realpath(host) in risk and "READ-WRITE" in risk and "/workspace/proj" in risk
    assert "read-only" in Manager.risks(ro)[0] and "READ-WRITE" not in Manager.risks(ro)[0]


# ------------------------------------------------------------------------------------- docker args

def test_docker_bind_mounts(tmp_path, host, fake_docker):
    rw_dir = tmp_path / "rwdir"
    rw_dir.mkdir()
    cfg = make_cfg(tmp_path, mounts={"ro": {"host": str(host), "guest": "/workspace/ro"},
                                     "rw": {"host": str(rw_dir), "guest": "/workspace/rw", "mode": "rw"}},
                   sandbox={"mounts": ["ro", "rw"]})
    Manager(cfg).create("d", {})
    args = create_call(fake_docker)
    assert flag_values(args, "--mount") == [
        f"type=bind,src={os.path.realpath(host)},dst=/workspace/ro,readonly",
        f"type=bind,src={os.path.realpath(rw_dir)},dst=/workspace/rw"]
    assert "--volume" not in args and "-v" not in args
    assert args.index("--mount") < args.index("--entrypoint")                # options precede the image


def test_docker_without_mappings_adds_nothing(tmp_path, fake_docker):
    Manager(make_cfg(tmp_path)).create("plain", {})
    assert "--mount" not in create_call(fake_docker)


def test_docker_selinux_relabel_uses_volume_syntax(tmp_path, host, fake_docker):
    Manager(cfg_with(tmp_path, host, mode="rw", docker={"mount_selinux": "private"})).create("se", {})
    assert flag_values(create_call(fake_docker), "--volume") == [f"{os.path.realpath(host)}:/workspace/proj:rw,Z"]
    colon = tmp_path / "a:b"
    colon.mkdir()
    cfg = make_cfg(tmp_path, docker={"mount_selinux": "shared"}, mounts={"c": {"host": str(colon), "guest": "/c"}},
                   sandbox={"mounts": ["c"]})
    with pytest.raises(SbxError, match="cannot express a host path containing ':'"):
        Manager(cfg).resolve_spec({})


def test_docker_read_only_rootfs_gives_way_to_a_mapped_workdir(tmp_path, host, fake_docker):
    cfg = make_cfg(tmp_path, docker={"read_only_rootfs": True}, sandbox={"workdir": "/workspace", "mounts": ["w"]},
                   fs={"guest_roots": ["/workspace"]}, mounts={"w": {"host": str(host), "guest": "/workspace"}})
    Manager(cfg).create("ro", {})
    tmpfs = flag_values(create_call(fake_docker), "--tmpfs")
    assert [t.split(":")[0] for t in tmpfs] == ["/tmp"]                      # no tmpfs on top of the mapping
    assert flag_values(create_call(fake_docker), "--mount") == [
        f"type=bind,src={os.path.realpath(host)},dst=/workspace,readonly"]


# ----------------------------------------------------------------------------------------- lxc

@pytest.fixture
def lxc(tmp_path, monkeypatch, host, fake_docker):
    state = fake_lxc_path(tmp_path, monkeypatch)
    monkeypatch.setattr(LxcBackend, "_cgroup2", staticmethod(lambda: True))
    spaced = tmp_path / "my data"
    spaced.mkdir()
    cfg = make_cfg(tmp_path, lxc={"enabled": True, "allow_privileged": True},
                   mounts={"proj": {"host": str(host), "guest": "/workspace/proj", "mode": "rw"},
                           "data": {"host": str(spaced), "guest": "/data"}},
                   sandbox={"backend": "lxc", "image_lxc": "debian/bookworm/amd64", "mounts": ["data", "proj"]})
    return Manager(cfg), state, spaced


def test_lxc_mount_entries(lxc, host):
    m, state, spaced = lxc
    rec = m.create("box", {})
    conf = json.load(open(os.path.join(state, f"c_{rec.runtime_name}.json")))["conf"]
    entries = [l for l in conf.splitlines() if l.startswith("lxc.mount.entry")]
    assert entries == [
        f"lxc.mount.entry = {os.path.realpath(spaced).replace(' ', chr(92) + '040')} data none "
        "bind,create=dir,nosuid,nodev,ro 0 0",
        f"lxc.mount.entry = {os.path.realpath(host)} workspace/proj none bind,create=dir,nosuid,nodev,rw 0 0"]
    assert conf.index("lxc.mount.entry") < conf.index("lxc.cap.drop")


def test_fstab_escape():
    assert fstab_escape("/a b\tc\\d") == "/a\\040b\\011c\\134d"


# ---------------------------------------------------------------------------------------- qemu

@pytest.fixture
def qm(tmp_path, host, fake_docker):
    img = tmp_path / "state" / "images"
    img.mkdir(parents=True)
    (img / "blank.qcow2").write_bytes(b"")                                   # validate() only needs the file to exist
    other = tmp_path / "second"
    other.mkdir()
    cfg = make_cfg(tmp_path, qemu={"enabled": True, "images_dir": str(img)},
                   mounts={"ro": {"host": str(host), "guest": "/mnt/ro"},
                           "rw": {"host": str(other), "guest": "/mnt/rw", "mode": "rw"}},
                   sandbox={"image_qemu": "blank", "mounts": ["ro", "rw"]})
    return Manager(cfg), cfg


def qemu_record(cfg, *mounts):
    spec = Spec("qemu", "blank", 1, 256, 256, 64, "none", mounts=list(mounts))
    return Record("vm", "abc123", "qemu", spec, data={})


def test_qemu_argv_exports_9p_shares(qm, host):
    m, cfg = qm
    be = m.backend("qemu")
    mounts = [Mount(str(host), "/mnt/ro", "ro", "ro"), Mount("/data/x", "/mnt/rw", "rw", "rw")]
    argv = be.build_argv(qemu_record(cfg, *mounts), "tcg")
    assert flag_values(argv, "-fsdev") == [f"local,id=fs0,path={host},security_model=none,readonly=on",
                                           "local,id=fs1,path=/data/x,security_model=none"]
    assert [a for a in flag_values(argv, "-device") if "9p" in a] == [
        "virtio-9p-pci,fsdev=fs0,mount_tag=sbx0", "virtio-9p-pci,fsdev=fs1,mount_tag=sbx1"]
    assert "-sandbox" in argv and "-nodefaults" in argv                    # still hardened
    assert "-fsdev" not in be.build_argv(qemu_record(cfg), "tcg")


def test_qemu_requires_9p_support_in_the_binary(qm):
    m, _ = qm
    be = m.backend("qemu")
    be._has_9p = False
    with pytest.raises(SbxError, match="no virtio-9p support"):
        be.validate(Spec("qemu", "blank", 1, 256, 256, 64, "none", mounts=[Mount("/x", "/y")]))
    be._has_9p = False
    be.validate(Spec("qemu", "blank", 1, 256, 256, 64, "none"))             # not needed without mappings


def test_qemu_guest_mount_requests(qm, host, monkeypatch):
    m, cfg = qm
    be = m.backend("qemu")
    rec = qemu_record(cfg, Mount(str(host), "/mnt/ro", "ro", "ro"), Mount("/x", "/mnt/rw", "rw", "rw"))
    seen = []

    def fake_exec(r, req):
        seen.append(req)
        return CmdResult(0)
    monkeypatch.setattr(be, "exec", fake_exec)
    be._mount_shares(rec)
    assert [(q.argv[4], q.argv[5]) for q in seen] == [("sbx0", "/mnt/ro"), ("sbx1", "/mnt/rw")]
    assert seen[0].argv[3] == "sbx" and seen[0].argv[2] == Q.MOUNT_SCRIPT
    assert seen[0].argv[6].endswith(",ro") and not seen[1].argv[6].endswith(",ro")
    assert "nosuid,nodev" in seen[1].argv[6] and "trans=virtio" in seen[1].argv[6]


def test_qemu_mount_failure_kills_the_vm_and_explains(qm, host, monkeypatch):
    m, cfg = qm
    be = m.backend("qemu")
    rec = qemu_record(cfg, Mount(str(host), "/mnt/ro", "ro", "ro"))
    killed = []
    monkeypatch.setattr(be, "exec", lambda r, req: CmdResult(32, stderr=b"mount: unknown filesystem type '9p'"))
    monkeypatch.setattr(be, "_kill", lambda r, grace=5.0: killed.append(1))
    with pytest.raises(BackendError, match="unknown filesystem type '9p'.*9p support"):
        be._mount_shares(rec)
    assert killed


def test_mount_script_runs_with_the_expected_mount_command(tmp_path):
    """The script that runs inside the guest, executed with stand-in mount/modprobe: it must create the directory,
    load the modules, call `mount -t 9p -o OPTS TAG DIR`, and propagate a failing mount's status."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "log"
    (bindir / "mount").write_text(f'#!/bin/sh\necho "mount $@" >> {log}\nexit ${{FAKE_MOUNT_RC:-0}}\n')
    (bindir / "modprobe").write_text(f'#!/bin/sh\necho "modprobe $@" >> {log}\n')
    for f in bindir.iterdir():
        f.chmod(0o755)
    target = tmp_path / "deep" / "dir"
    env = {"PATH": f"{bindir}:/usr/bin:/bin"}
    r = subprocess.run(["sh", "-c", Q.MOUNT_SCRIPT, "sbx", "sbx0", str(target), "trans=virtio,ro"], env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0 and target.is_dir()
    assert log.read_text().splitlines() == ["modprobe 9pnet_virtio", "modprobe 9p",
                                            f"mount -t 9p -o trans=virtio,ro sbx0 {target}"]
    r = subprocess.run(["sh", "-c", Q.MOUNT_SCRIPT, "sbx", "sbx0", str(target), "x"], env={**env, "FAKE_MOUNT_RC": "32"},
                       capture_output=True, text=True)
    assert r.returncode == 32


HAVE_QEMU = bool(shutil.which("qemu-system-x86_64") and shutil.which("qemu-img"))


@pytest.mark.skipif(not HAVE_QEMU, reason="qemu not installed")
def test_real_qemu_accepts_the_9p_flags_under_its_seccomp_sandbox(tmp_path, host, fake_docker):
    """Starts a REAL qemu (software emulation, blank disk) with our exact argv including the shares, and asks it
    which devices it created."""
    from sbx.backends import qga
    img = tmp_path / "state" / "images"
    img.mkdir(parents=True)
    subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", str(img / "blank.qcow2"), "64M"], check=True)
    cfg = make_cfg(tmp_path, qemu={"enabled": True, "images_dir": str(img)},
                   mounts={"ro": {"host": str(host), "guest": "/mnt/ro"}},
                   sandbox={"image_qemu": "blank", "memory_mb": 128, "disk_mb": 128, "mounts": ["ro"]})
    mgr = Manager(cfg)
    rec = mgr.create("real9p", {"backend": "qemu"}, start=False)
    be, d = mgr.backend("qemu"), mgr.backend("qemu")._paths(rec)
    errlog = os.path.join(d["dir"], "qemu.err")
    subprocess.run(["sh", "-c", 'e=$1; shift; setsid -f "$@" </dev/null >/dev/null 2>"$e"', "sbx", errlog,
                    *be.build_argv(rec, "tcg")], check=True)
    try:
        import time
        for _ in range(100):
            if be._pid(rec) and os.path.exists(d["qmp"]):
                break
            time.sleep(0.1)
        assert be._pid(rec), open(errlog).read()
        qtree = qga.qmp(d["qmp"], "human-monitor-command", {"command-line": "info qtree"})
        assert "virtio-9p-pci" in qtree and "mount_tag = \"sbx0\"" in qtree, qtree[-2000:]
    finally:
        be.destroy(rec)


# ---------------------------------------------------------------- through the real MCP surface

@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_mcp_flow_default_mapping_no_prompt_tools_reach_it(tmp_path, host, fake_docker):
    from test_e2e import Session, write_config
    cfgfile, ws, _ = write_config(tmp_path)
    mapped = tmp_path / "mapped"                                          # fake docker mounts nothing: stand-in content
    mapped.mkdir()
    (mapped / "seen.txt").write_text("through the mapping")
    async with Session(cfgfile, "--mount", f"{host}:{mapped}:ro", "--default-sandbox", "dev") as c:
        err, out = await c.call("sandbox_create", name="dev")
        assert not err, out
        info = json.loads(out)
        assert info["mounts"] == [{"name": "cli1", "guest": str(mapped), "mode": "ro"}]
        assert str(host) not in out
        # the mapped folder is an allowed root for the file tools and the shell even though it is outside guest_roots
        err, out = await c.call("list_allowed_directories")
        assert not err and str(mapped) in out
        err, out = await c.call("read_file", path=str(mapped / "seen.txt"))
        assert not err and out == "through the mapping"
        err, out = await c.call("run_command", command="cat seen.txt", cwd=str(mapped))
        assert not err and "through the mapping" in out
        args = create_call(fake_docker)
        assert flag_values(args, "--mount") == [f"type=bind,src={os.path.realpath(host)},dst={mapped},readonly"]
        # the model may not pick mappings on this server
        err, out = await c.call("sandbox_create", name="x", mounts=["cli1"])
        assert err and "not enabled" in out
        err, out = await c.call("sandbox_backends")
        assert not err and "not enabled" in out and str(host) not in out
    # the audit log (admin-facing) does record the host side
    assert str(os.path.realpath(host)) in (tmp_path / "audit.jsonl").read_text()


@pytest.mark.anyio
async def test_mcp_flow_model_requested_mapping_needs_human_approval(tmp_path, host, fake_docker):
    from mcp.types import ElicitResult
    from test_e2e import Session, write_config
    cfgfile, ws, _ = write_config(tmp_path, extra=f'''
[mounts.proj]
host = "{host}"
guest = "{tmp_path}/mapped"
mode = "rw"
''')
    text = open(cfgfile).read().replace("[audit]", "[limits]\nallow_mount_requests = true\n[audit]")
    open(cfgfile, "w").write(text)
    seen, answers = [], iter([False, True])

    async def cb(context, params):
        seen.append(params.message)
        return ElicitResult(action="accept", content={"approve": next(answers)})

    async with Session(cfgfile, elicit=cb) as c:
        err, out = await c.call("sandbox_backends")
        offered = json.loads(out)["requestable_folder_mappings"]
        assert offered == {"proj": {"guest": f"{tmp_path}/mapped", "mode": "rw"}}      # no host path
        err, out = await c.call("sandbox_create", name="no", mounts=["proj"])
        assert err and "DECLINED" in out and "READ-WRITE" in seen[0] and os.path.realpath(host) in seen[0]
        err, out = await c.call("sandbox_create", name="yes", mounts=["proj"])
        assert not err, out
        assert json.loads(out)["mounts"][0]["mode"] == "rw"
        n = len(seen)
        err, out = await c.call("sandbox_create", name="plain")                       # no request -> no prompt
        assert not err and len(seen) == n and json.loads(out)["mounts"] == []
        err, out = await c.call("sandbox_create", name="bad", mounts=["../../etc"])
        assert err and "unknown folder mapping" in out
        err, out = await c.call("sandbox_list")
        assert '"name": "yes"' in out and '"name": "no"' not in out


def test_doctor_reports_mappings(tmp_path, host, fake_docker, capsys):
    from sbx.server import doctor
    cfg = cfg_with(tmp_path, host)
    doctor(cfg)
    out = capsys.readouterr().out
    assert "proj" in out and "/workspace/proj (ro)" in out and "attached to every new sandbox" in out
