"""Opt-in: boot a REAL Linux kernel under REAL qemu (software emulation) and use the folder mappings from inside.

What it proves that the other tests cannot: QEMU's argv from QemuBackend.build_argv (including its seccomp sandbox)
exports the shares, the exact MOUNT_SCRIPT string the backend runs through the guest agent mounts them, reads and
writes reach the host with the host user's ownership, read-only shares refuse changes, and an absolute symlink
inside a share resolves in the *guest*, not on the host.

Needs: qemu-system-x86_64, qemu-img, busybox (static), cpio, zstd, and a kernel with 9p as modules, e.g.

    mkdir k && cd k && apt-get download linux-image-<ver>-generic linux-modules-<ver>-generic
    for f in *.deb; do dpkg -x $f tree; done
    SBX_TEST_KERNEL_TREE=$PWD/tree python -m pytest tests/test_qemu_9p_guest.py -s

The guest is a tiny busybox initramfs, so no guest agent / cloud image is involved (the agent path is covered by
test_qemu.py's fake agent; here the script is run directly by init).
"""
import glob
import os
import shutil
import subprocess
import time

import pytest

from conftest import make_cfg
from sbx.backends.qemu import MOUNT_SCRIPT, NINEP_OPTS
from sbx.manager import Manager

TREE = os.environ.get("SBX_TEST_KERNEL_TREE", "")
TOOLS = ("qemu-system-x86_64", "qemu-img", "busybox", "cpio", "zstd")
pytestmark = pytest.mark.skipif(not TREE or not all(shutil.which(t) for t in TOOLS),
                                reason=f"set SBX_TEST_KERNEL_TREE (and install {', '.join(TOOLS)})")

INIT = r'''#!/bin/sh
mount -t proc proc /proc; mount -t sysfs sys /sys; mount -t devtmpfs dev /dev
S="$(cat /mount_script)"; O="$(cat /opts)"
run() { sh -c "$S" sbx "$1" "$2" "$3"; echo "rc[$1 $2]=$?"; }
run sbx0 /mnt/ro "$O,ro"
run sbx1 /mnt/rw "$O"
run sbx1 /mnt/rw "$O"
echo "OPTS-RO: $(grep 'sbx0 ' /proc/mounts)"
echo "READ-RO=$(cat /mnt/ro/hello.txt)"
echo "READ-RW=$(cat /mnt/rw/hello.txt)"
echo guest-wrote > /mnt/rw/from_guest.txt; echo "WRITE-RW rc=$?"
echo x > /mnt/ro/nope.txt 2>/dev/null; echo "WRITE-RO rc=$?"
rm -f /mnt/ro/hello.txt 2>/dev/null; echo "RM-RO rc=$?"
echo "SYMLINK-LEAK=$(cat /mnt/rw/hostlink 2>/dev/null)"
echo "== DONE"
poweroff -f
'''


def build_initramfs(tmp_path):
    release = os.path.basename(os.path.dirname(glob.glob(f"{TREE}/lib/modules/*/kernel")[0]))
    kdir = f"{TREE}/lib/modules/{release}/kernel"
    root = tmp_path / "irfs"
    moddir = root / "lib" / "modules" / release
    for d in ("bin", "sbin", "proc", "sys", "dev", "mnt", "tmp"):
        (root / d).mkdir(parents=True)
    moddir.mkdir(parents=True)
    shutil.copy(shutil.which("busybox"), root / "bin" / "busybox")
    for applet in ("sh", "mount", "awk", "modprobe", "poweroff", "cat", "mkdir", "grep", "echo", "rm"):
        (root / "bin" / applet).symlink_to("busybox")
    (root / "sbin" / "modprobe").symlink_to("../bin/busybox")
    deps = {"netfs": ("fs/netfs", ""), "9pnet": ("net/9p", ""), "9pnet_virtio": ("net/9p", "9pnet.ko"),
            "9p": ("fs/9p", "9pnet.ko netfs.ko")}
    lines = []
    for mod, (sub, dep) in deps.items():
        subprocess.run(["zstd", "-dq", f"{kdir}/{sub}/{mod}.ko.zst", "-o", str(moddir / f"{mod}.ko")], check=True)
        lines.append(f"{mod}.ko: {dep}".rstrip())
    (moddir / "modules.dep").write_text("\n".join(lines) + "\n")
    (root / "mount_script").write_text(MOUNT_SCRIPT)
    (root / "opts").write_text(NINEP_OPTS)
    (root / "init").write_text(INIT)
    (root / "init").chmod(0o755)
    cpio = subprocess.run("find . | cpio -o -H newc --quiet | gzip -1", shell=True, cwd=root, check=True,
                          capture_output=True).stdout
    (tmp_path / "initrd.gz").write_bytes(cpio)
    return glob.glob(f"{TREE}/boot/vmlinuz-*")[0], str(tmp_path / "initrd.gz")


def test_shares_work_from_inside_a_real_guest(tmp_path):
    kernel, initrd = build_initramfs(tmp_path)
    ro, rw = tmp_path / "share ro", tmp_path / "share-rw"                  # a space: exercised on purpose
    for d, text in ((ro, "ro-content"), (rw, "rw-content")):
        d.mkdir()
        (d / "hello.txt").write_text(text)
    os.symlink("/etc/hostname", rw / "hostlink")
    img = tmp_path / "state" / "images"
    img.mkdir(parents=True)
    subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", str(img / "blank.qcow2"), "64M"], check=True)
    cfg = make_cfg(tmp_path, qemu={"enabled": True, "images_dir": str(img), "extra_args": [
        "-kernel", kernel, "-initrd", initrd, "-append", "console=ttyS0 loglevel=3 rdinit=/init panic=-1"]},
        mounts={"ro": {"host": str(ro), "guest": "/mnt/ro"}, "rw": {"host": str(rw), "guest": "/mnt/rw", "mode": "rw"}},
        sandbox={"backend": "qemu", "image_qemu": "blank", "memory_mb": 512, "disk_mb": 128, "mounts": ["ro", "rw"]})
    mgr = Manager(cfg)
    rec = mgr.create("g9p", {}, start=False)
    be, p = mgr.backend("qemu"), mgr.backend("qemu")._paths(rec)
    open(p["console"], "ab").close()
    subprocess.run(["sh", "-c", 'e=$1; shift; setsid -f "$@" </dev/null >/dev/null 2>"$e"', "sbx",
                    os.path.join(p["dir"], "qemu.err"), *be.build_argv(rec, "tcg")], check=True)
    try:
        out, t0 = "", time.time()
        while "== DONE" not in out and time.time() - t0 < 180:
            time.sleep(1)
            out = open(p["console"], errors="replace").read()
            assert time.time() - t0 < 15 or be._pid(rec) or "== DONE" in out, out
    finally:
        be.destroy(rec)
    assert "== DONE" in out, out[-1500:]
    for want in ("rc[sbx0 /mnt/ro]=0", "rc[sbx1 /mnt/rw]=0", "READ-RO=ro-content", "READ-RW=rw-content",
                 "WRITE-RW rc=0", "WRITE-RO rc=1", "RM-RO rc=1"):
        assert want in out, (want, out[-1500:])
    assert next(l for l in out.splitlines() if l.startswith("SYMLINK-LEAK=")).strip() == "SYMLINK-LEAK="
    assert out.count("rc[sbx1 /mnt/rw]=0") == 2                                # the script is idempotent
    assert " ro," in next(l for l in out.splitlines() if l.startswith("OPTS-RO"))
    assert (rw / "from_guest.txt").read_text().strip() == "guest-wrote"       # guest -> host
    assert (rw / "from_guest.txt").stat().st_uid == os.getuid()               # host user's ownership
    assert os.listdir(ro) == ["hello.txt"]                                    # read-only: untouched
