"""LXC backend (classic `lxc-*` tools, cgroup v2).

All containers live in a dedicated lxcpath (<state_dir>/lxc by default) so we never see, or touch,
containers you created by hand. Unprivileged operation is the default and expected: running as root
makes PRIVILEGED containers (container root == host root), which needs [lxc] allow_privileged = true.

Images are (dist/release/arch[/variant]) tuples from the LXC "download" template; the template
caches downloads, so only the first create of a given image is slow.

Folder mappings are bind mounts declared with `lxc.mount.entry` (nosuid,nodev, ro unless the mapping is rw).
In UNPRIVILEGED containers the host user's files appear owned by 'nobody' (uid 65534) inside, so a read-only
mapping works but a writable one only works where the host folder is writable by "other" - or if you add an
idmap through [lxc] extra_config. Privileged containers (allow_privileged) have no such problem.

Capabilities: network none|outbound (veth on a bridge you provide), cgroup2 cpu/memory/pids caps,
no swap. Not supported: published ports (reach the container at the IP shown by sandbox_info) and a
hard disk cap (depends on your storage backend: use btrfs/zfs/lvm if you need one).
"""
from __future__ import annotations

import os
import shutil
import time
from typing import Any

from ..errors import BackendError, SbxError
from ..util import cli_env, run_checked, run_cmd, secure_makedirs
from .base import Backend, ExecRequest, Record, Spec, guest_wrap

TOOLS = ("lxc-create", "lxc-start", "lxc-stop", "lxc-destroy", "lxc-info", "lxc-attach", "lxc-wait")
# dropped on top of the distro defaults (common.conf already drops sys_module, sys_time, mac_*)
CAP_DROP = ("sys_rawio", "sys_boot", "audit_control", "audit_write", "syslog", "wake_alarm", "block_suspend")


def fstab_escape(path: str) -> str:
    """fstab fields are whitespace separated: spaces, tabs and backslashes are written as octal escapes."""
    return path.replace("\\", "\\134").replace(" ", "\\040").replace("\t", "\\011")


class LxcBackend(Backend):
    name = "lxc"
    networks = ("none", "outbound")
    ports_networks = ()
    caveats = ("disk_mb is not enforced (storage-backend dependent)", "published ports are not supported",
               "folder mappings in unprivileged containers show your files as owned by 'nobody': read-only "
               "mappings work, writable ones need an idmap ([lxc] extra_config) or a world-writable folder")

    @property
    def path(self) -> str:
        return self.cfg.lxc.lxcpath

    def _args(self, tool: str, rec_or_name: Record | str | None = None, *rest: str) -> list[str]:
        a = [tool, "-P", self.path]
        if rec_or_name is not None:
            a += ["-n", rec_or_name if isinstance(rec_or_name, str) else rec_or_name.runtime_name]
        return a + list(rest)

    def _env(self) -> dict[str, str]:
        return cli_env()

    # -------------------------------------------------------------------- health
    @staticmethod
    def _cgroup2() -> bool:
        return os.path.exists("/sys/fs/cgroup/cgroup.controllers")

    def available(self) -> tuple[bool, str]:
        missing = [t for t in TOOLS if not shutil.which(t)]
        if missing:
            return False, "missing LXC tools: " + ", ".join(missing)
        if hasattr(os, "geteuid") and os.geteuid() == 0 and not self.cfg.lxc.allow_privileged:
            return False, ("running as root would create PRIVILEGED containers (container root == host root); "
                           "run unprivileged, or set [lxc] allow_privileged = true")
        if not self._cgroup2():
            return False, "cgroup v2 is required (no /sys/fs/cgroup/cgroup.controllers)"
        priv = "privileged" if os.geteuid() == 0 else "unprivileged"
        return True, f"lxc tools found ({priv} containers, lxcpath {self.path})"

    def validate(self, spec: Spec) -> None:
        if spec.ports:
            raise SbxError("the lxc backend cannot publish ports; use the container IP from sandbox_info "
                           "(reachable from the host) or pick docker/qemu")
        if spec.network == "local":
            raise SbxError("lxc supports network 'none' or 'outbound'")

    # -------------------------------------------------------------------- images
    @staticmethod
    def _split(ref: str) -> tuple[str, str, str, str]:
        parts = ref.split("/")
        return parts[0], parts[1], parts[2], (parts[3] if len(parts) > 3 else "default")

    def list_images(self) -> list[dict[str, Any]]:
        secure_makedirs(self.path)
        r = run_cmd(["lxc-create", "-P", self.path, "-n", "sbx-list", "-t", "download", "--", "--list"],
                    timeout=120, env=self._env())
        if not r.ok:
            raise BackendError(f"listing LXC images failed: {r.message()}")
        rows, seen = [], 0
        for line in r.out().splitlines():
            if line.startswith("---"):
                seen += 1
                continue
            cols = line.split()
            if seen >= 2 and len(cols) >= 4:
                dist, rel, arch, variant = cols[:4]
                ref = f"{dist}/{rel}/{arch}" + ("" if variant == "default" else f"/{variant}")
                rows.append({"ref": ref, "variant": variant, "build": cols[4] if len(cols) > 4 else ""})
        return rows

    def pull_image(self, ref: str) -> str:
        known = {r["ref"] for r in self.list_images()}
        if ref not in known:
            raise SbxError(f"image {ref!r} is not offered by the LXC image server (see image_list)")
        return (f"{ref} is available; the LXC download template fetches and caches it the first time a "
                "sandbox is created from it")

    def remove_image(self, ref: str) -> None:
        raise SbxError("the LXC image cache is managed by the download template "
                       "(delete ~/.cache/lxc/download/... by hand if you need the space)")

    # ------------------------------------------------------------------ lifecycle
    def _config(self, rec: Record) -> str:
        s, c = rec.spec, self.cfg.lxc
        lines = []
        base = c.base_config or next((p for p in (os.path.expanduser("~/.config/lxc/default.conf"),
                                                  "/etc/lxc/default.conf") if os.path.exists(p)), "")
        if base:
            lines.append(f"lxc.include = {base}")
        lines += [f"lxc.uts.name = {rec.name}",
                  f"lxc.cgroup2.memory.max = {s.memory_mb * 1024 * 1024}",
                  "lxc.cgroup2.memory.swap.max = 0",
                  f"lxc.cgroup2.cpu.max = {max(1000, int(s.cpus * 100000))} 100000",
                  f"lxc.cgroup2.pids.max = {s.pids}",
                  "lxc.no_new_privs = 1",
                  "lxc.net ="]                       # clear whatever the base config defined
        if s.network == "none":
            lines.append("lxc.net.0.type = empty")
        else:
            lines += ["lxc.net.0.type = veth", f"lxc.net.0.link = {c.outbound_bridge}", "lxc.net.0.flags = up"]
        for m in s.mounts:
            lines.append(f"lxc.mount.entry = {fstab_escape(m.host)} {fstab_escape(m.guest.lstrip('/'))} none "
                         f"bind,create=dir,nosuid,nodev,{'rw' if m.rw else 'ro'} 0 0")
        lines += [f"lxc.cap.drop = {cap}" for cap in CAP_DROP]
        lines += [f"lxc.environment = {k}={v}" for k, v in s.env.items()]
        lines += list(c.extra_config)
        return "\n".join(lines) + "\n"

    def create(self, rec: Record) -> dict[str, Any]:
        secure_makedirs(self.path)
        d = self.rec_dir(rec)
        secure_makedirs(d)
        conf = os.path.join(d, "lxc.conf")
        fd = os.open(conf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(self._config(rec))
        dist, rel, arch, variant = self._split(rec.spec.image)
        tmpl = ["--", "-d", dist, "-r", rel, "-a", arch]
        if variant != "default":
            tmpl += ["--variant", variant]
        run_checked(self._args("lxc-create", rec, "-f", conf, "-t", "download") + tmpl, "lxc-create",
                    timeout=self.cfg.lxc.create_timeout, env=self._env())
        return {"lxcpath": self.path}

    def start(self, rec: Record) -> None:
        run_checked(self._args("lxc-start", rec, "-d"), "lxc-start", timeout=60, env=self._env())
        run_checked(self._args("lxc-wait", rec, "-s", "RUNNING", "-t", "30"), "lxc-wait", timeout=45, env=self._env())
        deadline = time.monotonic() + 30
        while True:   # wait until the container can actually run commands
            r = run_cmd(self._args("lxc-attach", rec, "--clear-env", "--", "true"), timeout=15, env=self._env())
            if r.ok:
                return
            if time.monotonic() > deadline:
                raise BackendError(f"container started but commands cannot run in it: {r.message(200)}")
            time.sleep(0.5)

    def stop(self, rec: Record, timeout: int = 10) -> None:
        r = run_cmd(self._args("lxc-stop", rec, "-t", str(timeout)), timeout=timeout + 30, env=self._env())
        if not r.ok and self.status(rec) == "running":
            run_checked(self._args("lxc-stop", rec, "-k"), "lxc-stop -k", timeout=30, env=self._env())

    def destroy(self, rec: Record) -> None:
        if self.status(rec) == "running":
            run_cmd(self._args("lxc-stop", rec, "-k"), timeout=30, env=self._env())
        r = run_cmd(self._args("lxc-destroy", rec, "-f"), timeout=120, env=self._env())
        text = r.err().lower()
        if not r.ok and "does not exist" not in text and "not defined" not in text and "no such" not in text:
            raise BackendError(f"lxc-destroy: {r.message()}")

    def status(self, rec: Record) -> str:
        r = run_cmd(self._args("lxc-info", rec, "-s", "-H"), timeout=20, env=self._env())
        if not r.ok:
            return "missing"
        return "running" if r.out().strip().upper() == "RUNNING" else "stopped"

    def info(self, rec: Record) -> dict[str, Any]:
        out: dict[str, Any] = {"runtime": f"lxc container {rec.runtime_name} (lxcpath {self.path})"}
        r = run_cmd(self._args("lxc-info", rec, "-i", "-H"), timeout=20, env=self._env())
        ips = [x.strip() for x in r.out().splitlines() if x.strip()]
        if r.ok and ips:
            out["ip"] = ips[0]
        return out

    # ----------------------------------------------------------------------- exec
    def exec(self, rec: Record, req: ExecRequest):
        argv = self._args("lxc-attach", rec, "--clear-env", "--") + guest_wrap(req)
        return run_cmd(argv, input=req.stdin if req.stdin is not None else b"", timeout=req.timeout + 5,
                       env=self._env(), max_output=req.max_output)
