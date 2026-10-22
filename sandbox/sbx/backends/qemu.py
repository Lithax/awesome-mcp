"""QEMU backend: disposable VMs from qcow2/raw base images, driven without root or a network.

How it works
  * images: admin-provided files in <images_dir>, or entries declared under [qemu.images.*] (https URL +
    mandatory sha256) that the model may fetch with image_pull. The model can never choose a URL.
  * every sandbox gets a copy-on-write qcow2 overlay (`-b base`), so the base image is never modified and
    destroying a sandbox is just deleting one file. disk_mb is the overlay's virtual size = a hard cap.
  * commands and file access go through the QEMU Guest Agent over virtio-serial (no SSH, no network). The
    image therefore must run `qemu-guest-agent` (Debian/Ubuntu cloud images normally do).
  * VMs are detached (`setsid -f`) and survive MCP server restarts; state is found again via a pidfile + sockets.
    We do NOT use qemu's own -daemonize: it forks, which qemu's seccomp filter (spawn=deny) forbids.

Folder mappings use virtio-9p (`-fsdev local` + `virtio-9p-pci`, security_model=none, so files keep your
ownership on the host and nothing is written into xattrs). QEMU only exports the share; mounting it happens
inside the guest, through the guest agent, every time the VM starts. The guest kernel needs the 9p modules
(Ubuntu and most distro kernels have them; very trimmed cloud kernels may not). Read-only mappings are
enforced by QEMU itself (`readonly=on`), not just by the guest's mount option.

Hardening: qemu's own seccomp sandbox (-sandbox on,...spawn=deny,...), -nodefaults, no display, QMP/QGA on
private unix sockets (0700 dir), user-mode networking only (needs no privileges), and run as you, not root.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
import signal
import time
import urllib.request
from typing import Any

from ..errors import BackendError, SbxError
from ..util import cli_env, run_checked, run_cmd, secure_makedirs
from . import qga
from .base import Backend, ExecRequest, Record, Spec, guest_wrap

IMAGE_EXTS = (".qcow2", ".img", ".raw")
MAX_DOWNLOAD = 16 * 1024 ** 3
# Run in the guest (as root, via the guest agent) once per mapping: tag, directory, mount options.
# Idempotent; tries to load the 9p modules first; a distro kernel without 9p fails with a clear message.
MOUNT_SCRIPT = ('tag=$1; dir=$2; opt=$3; mkdir -p "$dir" || exit 1; '
                'awk -v t="$tag" -v d="$dir" \'$1==t && $2==d && $3=="9p" {f=1} END {exit !f}\' /proc/mounts && exit 0; '
                'modprobe 9pnet_virtio >/dev/null 2>&1; modprobe 9p >/dev/null 2>&1; '
                'exec mount -t 9p -o "$opt" "$tag" "$dir"')
NINEP_OPTS = "trans=virtio,version=9p2000.L,msize=524288,cache=mmap,nosuid,nodev"
SEED_TOOLS = (("cloud-localds", None), ("genisoimage", "mkisofs-style"), ("mkisofs", "mkisofs-style"),
              ("xorrisofs", "mkisofs-style"), ("xorriso", "xorriso"))


class QemuBackend(Backend):
    name = "qemu"
    networks = ("none", "local", "outbound")
    ports_networks = ("local", "outbound")
    caveats = ("the image must run qemu-guest-agent (used for all command and file access)",
               "network='outbound' uses user-mode networking: the guest can reach services on the host's "
               "loopback through 10.0.2.2 (use 'local' or 'none' if that matters)",
               "cpus is rounded up to whole vCPUs unless [qemu] systemd_scope = true",
               "folder mappings use virtio-9p: the guest kernel needs the 9p modules (9p, 9pnet_virtio)")
    _has_9p: bool | None = None

    # ---------------------------------------------------------------- small helpers
    @property
    def q(self):
        return self.cfg.qemu

    @property
    def binary(self) -> str:
        return self.q.binary or f"qemu-system-{self.q.arch}"

    def _paths(self, rec: Record) -> dict[str, str]:
        d = self.rec_dir(rec)
        qmp_s, ga_s, ga_l = qga.sock_paths(d)
        return {"dir": d, "disk": os.path.join(d, "disk.qcow2"), "seed": os.path.join(d, "seed.iso"),
                "qmp": qmp_s, "ga": ga_s, "galock": ga_l, "pid": os.path.join(d, "qemu.pid"),
                "console": os.path.join(d, "console.log")}

    def _accel(self) -> str:
        if self.q.accel == "auto":
            return "kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg"
        return self.q.accel

    def _pid(self, rec: Record) -> int | None:
        """pid of OUR vm: pidfile content verified against /proc so a recycled pid is never signalled."""
        try:
            pid = int(open(self._paths(rec)["pid"]).read().strip())
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                if rec.runtime_name.encode() in f.read():
                    return pid
        except (OSError, ValueError):
            pass
        return None

    # -------------------------------------------------------------------- health
    def available(self) -> tuple[bool, str]:
        for b in (self.binary, self.q.img_binary):
            if not shutil.which(b):
                return False, f"'{b}' not found in PATH"
        acc = self._accel()
        extra = "" if acc == "kvm" else " (no usable /dev/kvm: using slow software emulation)"
        root = " WARNING: running as root; run unprivileged" if hasattr(os, "geteuid") and os.geteuid() == 0 else ""
        return True, f"{self.binary}, accel={acc}{extra}{root}"

    def supports_9p(self) -> bool:
        if self._has_9p is None:
            try:
                r = run_cmd([self.binary, "-device", "help"], timeout=30, env=cli_env())
                self._has_9p = "virtio-9p-pci" in r.out() + r.err()
            except SbxError:
                self._has_9p = True            # cannot tell: let qemu itself report it
        return self._has_9p

    def validate(self, spec: Spec) -> None:
        if self.q.arch == "aarch64" and not self.q.firmware:
            raise SbxError("aarch64 needs [qemu] firmware = <path to UEFI image>")
        self.image_path(spec.image)            # raises if the image is missing
        if spec.mounts and not self.supports_9p():
            raise SbxError("this QEMU build has no virtio-9p support, which folder mappings need "
                           "(on Debian/Ubuntu the qemu-system-x86 package has it)")

    # -------------------------------------------------------------------- images
    def image_path(self, name: str) -> str:
        d = self.q.images_dir
        for cand in (name, *(name + e for e in IMAGE_EXTS)):
            p = os.path.join(d, cand)
            if os.path.isfile(p) and os.path.realpath(p).startswith(os.path.realpath(d) + os.sep):
                return p
        hint = " (fetch it with image_pull)" if name in self.q.images else ""
        raise SbxError(f"qemu image {name!r} not found in the images directory{hint}")

    def list_images(self) -> list[dict[str, Any]]:
        d = self.q.images_dir
        rows: dict[str, dict[str, Any]] = {}
        if os.path.isdir(d):
            for f in sorted(os.listdir(d)):
                p = os.path.join(d, f)
                if os.path.isfile(p) and f.endswith(IMAGE_EXTS):
                    ref = f.rsplit(".", 1)[0]
                    rows[ref] = {"ref": ref, "file": f, "size_mb": round(os.path.getsize(p) / 1048576, 1),
                                 "downloaded": True}
        for name, spec in self.q.images.items():
            rows.setdefault(name, {"ref": name, "downloaded": False, "url": spec.get("url")})
        return list(rows.values())

    def pull_image(self, ref: str) -> str:
        spec = self.q.images.get(ref)
        if spec is None:
            raise SbxError(f"{ref!r} is not a declared image; only [qemu.images.*] entries can be downloaded")
        fmt = spec.get("format", "qcow2")
        secure_makedirs(self.q.images_dir)
        final = os.path.join(self.q.images_dir, f"{ref}.{fmt}")
        if os.path.exists(final):
            return f"{ref} is already present"
        part = final + ".part"
        h = hashlib.sha256()
        total = 0
        try:
            with urllib.request.urlopen(spec["url"], timeout=60) as resp:       # noqa: S310 - https enforced by config
                if not resp.geturl().startswith("https://"):
                    raise BackendError("download was redirected to a non-HTTPS URL; refusing")
                with open(part, "wb") as f:
                    while chunk := resp.read(1 << 20):
                        total += len(chunk)
                        if total > MAX_DOWNLOAD:
                            raise BackendError("download exceeds the size limit")
                        h.update(chunk)
                        f.write(chunk)
            if h.hexdigest().lower() != spec["sha256"].lower():
                raise BackendError("checksum mismatch: the downloaded file is NOT the image you declared; discarded")
            os.chmod(part, 0o444)
            os.replace(part, final)
        except OSError as e:
            raise BackendError(f"download failed: {e}") from None
        finally:
            if os.path.exists(part):
                os.unlink(part)
        return f"downloaded {ref} ({total // 1048576} MiB, sha256 verified)"

    def remove_image(self, ref: str) -> None:
        p = self.image_path(ref)
        os.chmod(os.path.dirname(p), 0o700)
        os.unlink(p)

    # ------------------------------------------------------------------ lifecycle
    def _info_json(self, path: str) -> dict[str, Any]:
        r = run_checked([self.q.img_binary, "info", "--output=json", "-U", path], "qemu-img info", timeout=60,
                        env=cli_env())
        return json.loads(r.out())

    def _make_seed(self, rec: Record, p: dict[str, str]) -> bool:
        mode = self.q.cloud_init
        if mode == "off":
            return False
        tool = next(((t, kind) for t, kind in SEED_TOOLS if shutil.which(t)), None)
        if tool is None:
            if mode == "on":
                raise BackendError("[qemu] cloud_init = on but none of cloud-localds, genisoimage, mkisofs, "
                                   "xorrisofs or xorriso is installed")
            return False
        d = os.path.join(p["dir"], "seed")
        secure_makedirs(d)
        user = (
            "#cloud-config\n"
            f"hostname: {rec.name}\n"
            "manage_etc_hosts: true\n"
            "ssh_pwauth: false\n"
            "runcmd:\n"
            f"  - [ sh, -c, \"mkdir -p {rec.spec.workdir}\" ]\n"
            "  - [ sh, -c, \"systemctl enable --now qemu-guest-agent 2>/dev/null || "
            "service qemu-guest-agent start 2>/dev/null || true\" ]\n")
        with open(os.path.join(d, "user-data"), "w") as f:
            f.write(user)
        with open(os.path.join(d, "meta-data"), "w") as f:
            f.write(f"instance-id: {rec.runtime_name}\nlocal-hostname: {rec.name}\n")
        exe, kind = tool
        ud, md = os.path.join(d, "user-data"), os.path.join(d, "meta-data")
        if kind is None:
            argv = [exe, p["seed"], ud, md]
        elif kind == "xorriso":
            argv = [exe, "-as", "mkisofs", "-o", p["seed"], "-V", "cidata", "-J", "-r", ud, md]
        else:
            argv = [exe, "-output", p["seed"], "-volid", "cidata", "-joliet", "-rock", ud, md]
        run_checked(argv, "building the cloud-init seed", timeout=60, env=cli_env())
        return True

    def create(self, rec: Record) -> dict[str, Any]:
        p = self._paths(rec)
        secure_makedirs(p["dir"])
        base = self.image_path(rec.spec.image)
        info = self._info_json(base)
        fmt = info.get("format")
        if fmt not in ("qcow2", "raw"):
            raise SbxError(f"base image format {fmt!r} is not allowed (qcow2 or raw only)")
        if info.get("backing-filename") or info.get("full-backing-filename"):
            raise SbxError("base image has a backing file; refusing (it could reference arbitrary host files)")
        vsize = int(info.get("virtual-size", 0))
        if rec.spec.disk_mb * 1048576 < vsize:
            raise SbxError(f"disk_mb={rec.spec.disk_mb} is smaller than the base image's virtual size "
                           f"({math.ceil(vsize / 1048576)} MiB)")
        run_checked([self.q.img_binary, "create", "-q", "-f", "qcow2", "-b", os.path.realpath(base), "-F", fmt,
                     p["disk"], f"{rec.spec.disk_mb}M"], "qemu-img create", timeout=60, env=cli_env())
        os.chmod(p["disk"], 0o600)
        return {"base": os.path.realpath(base), "base_format": fmt, "seed": self._make_seed(rec, p)}

    @staticmethod
    def share_tag(i: int) -> str:
        return f"sbx{i}"

    def _mount_shares(self, rec: Record) -> None:
        """Mount every mapped folder inside the (booted) guest. On failure the VM is killed so a retry starts clean."""
        for i, m in enumerate(rec.spec.mounts):
            opts = NINEP_OPTS + ("" if m.rw else ",ro")
            r = self.exec(rec, ExecRequest(["sh", "-c", MOUNT_SCRIPT, "sbx", self.share_tag(i), m.guest, opts],
                                           cwd="/", timeout=60))
            if not r.ok:
                self._kill(rec)
                raise BackendError(f"could not mount the host folder {m.name or i!r} at {m.guest} inside the VM: "
                                   f"{r.message(200)}. The guest kernel needs 9p support (modules 9p and 9pnet_virtio).")

    def build_argv(self, rec: Record, accel: str) -> list[str]:
        """Pure function of (record, config, accel): easy to inspect and test."""
        s, q, p = rec.spec, self.q, self._paths(rec)
        arm = q.arch == "aarch64"
        machine = q.machine or ("virt" if arm else "q35")
        a = [self.binary, "-name", f"{rec.runtime_name},process={rec.runtime_name}",
             "-machine", machine, "-accel", accel, "-cpu", "host" if accel == "kvm" else "max",
             "-m", f"{s.memory_mb}M", "-smp", str(max(1, math.ceil(s.cpus))),
             "-nodefaults", "-no-user-config", "-display", "none", "-monitor", "none",
             "-serial", f"file:{p['console']}",
             "-qmp", f"unix:{p['qmp']},server=on,wait=off",
             "-pidfile", p["pid"],
             "-object", "rng-random,id=rng0,filename=/dev/urandom", "-device", "virtio-rng-pci,rng=rng0",
             "-drive", f"file={p['disk']},if=none,id=hd0,format=qcow2,discard=unmap",
             "-device", "virtio-blk-pci,drive=hd0,bootindex=1"]
        if arm and q.firmware:
            a += ["-bios", q.firmware]
        if rec.data.get("seed") and os.path.exists(p["seed"]):
            a += ["-drive", f"file={p['seed']},if=none,id=cd0,format=raw,media=cdrom,readonly=on",
                  "-device", "virtio-blk-pci,drive=cd0"]
        for i, m in enumerate(s.mounts):
            a += ["-fsdev", f"local,id=fs{i},path={m.host},security_model=none" + ("" if m.rw else ",readonly=on"),
                  "-device", f"virtio-9p-pci,fsdev=fs{i},mount_tag={self.share_tag(i)}"]
        a += ["-chardev", f"socket,id=qga0,path={p['ga']},server=on,wait=off",
              "-device", "virtio-serial-pci",
              "-device", "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0"]
        if s.network != "none":
            fwd = "".join(f",hostfwd={pm.proto}:{pm.bind}:{pm.host}-:{pm.guest}" for pm in s.ports)
            restrict = "on" if s.network == "local" else "off"
            a += ["-netdev", f"user,id=n0,restrict={restrict},hostname={rec.name}{fwd}",
                  "-device", "virtio-net-pci,netdev=n0"]
        if q.seccomp_sandbox:
            a += ["-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"]
        a += list(q.extra_args)
        if q.systemd_scope:
            a = ["systemd-run", "--user", "--scope", "--quiet", "--collect",
                 "-p", f"CPUQuota={int(s.cpus * 100)}%", "-p", f"MemoryMax={s.memory_mb + 384}M"] + a
        return a

    @staticmethod
    def _read_tail(path: str, limit: int = 600) -> str:
        try:
            with open(path, "rb") as f:
                return " ".join(f.read(limit * 4).decode("utf-8", "replace").split())[:limit]
        except OSError:
            return ""

    def _console_tail(self, rec: Record, n: int = 8) -> str:
        try:
            with open(self._paths(rec)["console"], "rb") as f:
                f.seek(0, os.SEEK_END)
                f.seek(max(0, f.tell() - 4096))
                lines = f.read().decode("utf-8", "replace").strip().splitlines()[-n:]
            return " | ".join(x.strip() for x in lines if x.strip())
        except OSError:
            return ""

    def start(self, rec: Record) -> None:
        p = self._paths(rec)
        if self._pid(rec):
            return
        for f in (p["qmp"], p["ga"], p["pid"]):
            if os.path.lexists(f):
                os.unlink(f)
        open(p["console"], "ab").close()
        errlog = os.path.join(p["dir"], "qemu.err")
        if os.path.exists(errlog):
            os.unlink(errlog)
        # detach: new session, no inherited pipes, stderr to a file we can read if startup fails
        launch = ["sh", "-c", 'e=$1; shift; setsid -f "$@" </dev/null >/dev/null 2>"$e"', "sbx", errlog,
                  *self.build_argv(rec, self._accel())]
        r = run_cmd(launch, timeout=30, env=cli_env())
        if not r.ok:
            raise BackendError(f"qemu failed to start: {r.message()}")
        deadline = time.monotonic() + 20
        t0 = time.monotonic()
        while not (os.path.exists(p["qmp"]) and self._pid(rec)):
            err = self._read_tail(errlog)
            if err and not self._pid(rec) and time.monotonic() - t0 > 1.0:
                raise BackendError(f"qemu failed to start: {err}")
            if time.monotonic() > deadline:
                raise BackendError("qemu did not come up" + (f": {err}" if err else " (no pidfile / QMP socket)"))
            time.sleep(0.1)
        deadline = time.monotonic() + self.q.boot_timeout
        while not qga.ga_ping(p["ga"], p["galock"], timeout=2.0):
            if not self._pid(rec):
                raise BackendError("the VM exited during boot. Console: " + (self._console_tail(rec) or "(empty)"))
            if time.monotonic() > deadline:
                tail = self._console_tail(rec)
                self._kill(rec)
                raise BackendError(
                    f"the guest agent did not answer within {self.q.boot_timeout}s. Does the image run "
                    f"qemu-guest-agent? Console: {tail or '(empty)'}")
            time.sleep(0.5)
        self._mount_shares(rec)

    def _kill(self, rec: Record, grace: float = 5.0) -> None:
        pid, p = self._pid(rec), self._paths(rec)
        if not pid:
            return
        try:
            qga.qmp(p["qmp"], "quit", timeout=5)
        except BackendError:
            pass
        end = time.monotonic() + grace
        while self._pid(rec) and time.monotonic() < end:
            time.sleep(0.1)
        if self._pid(rec):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def stop(self, rec: Record, timeout: int = 10) -> None:
        p = self._paths(rec)
        if not self._pid(rec):
            return
        try:
            qga.qmp(p["qmp"], "system_powerdown", timeout=5)
        except BackendError:
            pass
        end = time.monotonic() + max(timeout, 20)         # ACPI shutdown of a real OS takes a few seconds
        while self._pid(rec) and time.monotonic() < end:
            time.sleep(0.2)
        if self._pid(rec):
            self._kill(rec)

    def destroy(self, rec: Record) -> None:
        self._kill(rec, grace=3.0)
        p = self._paths(rec)
        for f in ("disk", "seed", "qmp", "ga", "pid"):
            try:
                os.unlink(p[f])
            except FileNotFoundError:
                pass
        shutil.rmtree(os.path.join(p["dir"], "seed"), ignore_errors=True)

    def status(self, rec: Record) -> str:
        if not os.path.exists(self._paths(rec)["disk"]):
            return "missing"
        return "running" if self._pid(rec) else "stopped"

    def info(self, rec: Record) -> dict[str, Any]:
        out: dict[str, Any] = {"runtime": f"qemu VM {rec.runtime_name}", "accel": self._accel(),
                               "base_image": os.path.basename(rec.data.get("base", ""))}
        pid = self._pid(rec)
        if pid:
            out["pid"] = pid
        return out

    # ----------------------------------------------------------------------- exec
    def exec(self, rec: Record, req: ExecRequest):
        p = self._paths(rec)
        env = {**rec.spec.env, **req.env}
        plain = ExecRequest(req.argv, req.cwd, {}, req.stdin, req.timeout, req.max_output)
        return qga.ga_exec(p["ga"], p["galock"], guest_wrap(plain), env=env, stdin=req.stdin,
                           timeout=req.timeout + 5, max_output=req.max_output)
