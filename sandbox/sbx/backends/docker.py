"""Docker (or Podman: same CLI) backend.

Folder mappings are bind mounts (`--mount type=bind`, which - unlike `-v` - refuses to invent a missing host
directory as root). Hosts with SELinux can set [docker] mount_selinux, which switches to `--volume ...:z|Z`.

Hardening applied to every container, none of which the model can change:
  --cap-drop ALL then a small cap-add list, no-new-privileges, pids/memory/cpu limits with swap disabled,
  --init (reaps zombies), private IPC/PID namespaces (docker defaults), core dumps off, bounded logs,
  published ports bound to loopback, and a label so we only ever touch containers we created.
"""
from __future__ import annotations

import json
import os
import shutil
from typing import Any

from ..errors import BackendError, SbxError
from ..util import IMAGE_REF_RE, cli_env, run_checked, run_cmd
from .base import Backend, ExecRequest, Record, Spec, guest_wrap

# PID 1 for the sandbox: sleeps, exits promptly on TERM so `docker stop` is fast.
KEEPALIVE = "trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $!; done"


class DockerBackend(Backend):
    name = "docker"
    networks = ("none", "outbound")
    ports_networks = ("outbound",)
    caveats = ("writable folder mappings: with rootful docker the container's root creates root-owned files in your "
               "folder (rootless podman maps root to you; or set [docker] user = \"UID:GID\")",)

    @property
    def bin(self) -> str:
        return self.cfg.docker.binary

    def _run(self, args: list[str], what: str, timeout: float = 60, **kw):
        return run_checked([self.bin, *args], what, timeout=timeout, **kw)

    # -------------------------------------------------------------------- health
    def available(self) -> tuple[bool, str]:
        if not shutil.which(self.bin):
            return False, f"'{self.bin}' not found in PATH"
        try:
            r = run_cmd([self.bin, "version", "--format", "{{.Server.Version}}"], timeout=15)
        except SbxError as e:
            return False, str(e)
        if not r.ok:
            return False, f"cannot reach the daemon: {r.message(200)}"
        return True, f"{self.bin} server {r.out().strip() or 'ok'}"

    def validate(self, spec: Spec) -> None:
        if spec.network == "local":
            raise SbxError("docker supports network 'none' or 'outbound' (use qemu for 'local')")
        if spec.ports and spec.network == "none":
            raise SbxError("published ports need network='outbound' on docker (a container with no network cannot publish)")
        if self.cfg.docker.read_only_rootfs and spec.disk_mb < 16:
            raise SbxError("disk_mb too small for a read-only rootfs")
        if self.cfg.docker.mount_selinux:
            for m in spec.mounts:
                if ":" in m.host:
                    raise SbxError(f"[docker] mount_selinux uses --volume syntax, which cannot express a host path "
                                   f"containing ':' (mapping {m.name!r})")

    # -------------------------------------------------------------------- images
    def list_images(self) -> list[dict[str, Any]]:
        r = self._run(["image", "ls", "--format", "{{json .}}"], "docker image ls")
        out = []
        for line in r.out().splitlines():
            try:
                j = json.loads(line)
            except ValueError:
                continue
            repo, tag = j.get("Repository", ""), j.get("Tag", "")
            if repo and repo != "<none>":
                out.append({"ref": f"{repo}:{tag}" if tag and tag != "<none>" else repo,
                            "id": j.get("ID", ""), "size": j.get("Size", ""), "created": j.get("CreatedSince", "")})
        return out

    @staticmethod
    def _ref(ref: str) -> str:
        if not IMAGE_REF_RE.match(ref or ""):
            raise SbxError("invalid image reference")
        return ref

    def pull_image(self, ref: str) -> str:
        self._run(["pull", self._ref(ref)], f"pull {ref}", timeout=1800)
        return f"pulled {ref}"

    def remove_image(self, ref: str) -> None:
        self._run(["rmi", self._ref(ref)], f"remove {ref}")

    # ------------------------------------------------------------------ lifecycle
    def _create_args(self, rec: Record, env_file: str | None) -> list[str]:
        s, d = rec.spec, self.cfg.docker
        net = "none" if s.network == "none" else d.outbound_network
        mem = f"{s.memory_mb}m"
        a = ["create", "--name", rec.runtime_name,
             "--label", "sbx.managed=1", "--label", f"sbx.name={rec.name}", "--label", f"sbx.id={rec.id}",
             "--hostname", rec.name,
             "--cpus", f"{s.cpus:g}", "--memory", mem, "--memory-swap", mem, "--pids-limit", str(s.pids),
             "--security-opt", "no-new-privileges:true",
             "--init", "--stop-timeout", "5", "--restart", "no",
             "--ulimit", f"nofile={d.nofile}:{d.nofile}", "--ulimit", "core=0",
             "--shm-size", f"{d.shm_mb}m", "--network", net, "--workdir", s.workdir]
        for c in d.cap_drop:
            a += ["--cap-drop", c]
        for c in d.cap_add:
            a += ["--cap-add", c]
        if "docker" in os.path.basename(self.bin):
            a += ["--log-opt", f"max-size={d.log_max_size}"]
        for p in s.ports:
            a += ["-p", f"{p.bind}:{p.host}:{p.guest}/{p.proto}"]
        if d.user:
            a += ["--user", d.user]
        if env_file:
            a += ["--env-file", env_file]
        mapped = {m.guest for m in s.mounts}
        if d.read_only_rootfs:
            a += ["--read-only"]
            if "/tmp" not in mapped:
                a += ["--tmpfs", f"/tmp:rw,nosuid,nodev,size={max(16, s.disk_mb // 4)}m"]
            if s.workdir not in mapped:          # a mapped workdir replaces the scratch tmpfs
                a += ["--tmpfs", f"{s.workdir}:rw,nosuid,nodev,exec,size={s.disk_mb}m"]
        for m in s.mounts:
            if d.mount_selinux:
                label = "z" if d.mount_selinux == "shared" else "Z"
                a += ["--volume", f"{m.host}:{m.guest}:{'rw' if m.rw else 'ro'},{label}"]
            else:
                a += ["--mount", f"type=bind,src={m.host},dst={m.guest}" + ("" if m.rw else ",readonly")]
        if d.storage_opt_size:
            a += ["--storage-opt", f"size={s.disk_mb}m"]
        a += list(d.extra_args)
        a += ["--entrypoint", "sh", s.image, "-c", KEEPALIVE]
        return a

    def create(self, rec: Record) -> dict[str, Any]:
        env_file = None
        if rec.spec.env:
            env_file = os.path.join(self.rec_dir(rec), "env")
            os.makedirs(os.path.dirname(env_file), mode=0o700, exist_ok=True)
            fd = os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                for k, v in rec.spec.env.items():
                    f.write(f"{k}={v}\n")
        try:
            r = self._run(self._create_args(rec, env_file), "docker create", timeout=300)
        finally:
            if env_file:
                try:
                    os.unlink(env_file)
                except OSError:
                    pass
        return {"container_id": r.out().strip()[:64]}

    def start(self, rec: Record) -> None:
        self._run(["start", rec.runtime_name], "docker start")

    def stop(self, rec: Record, timeout: int = 10) -> None:
        r = run_cmd([self.bin, "stop", "-t", str(timeout), rec.runtime_name], timeout=timeout + 30)
        if not r.ok and "No such" not in r.err():
            raise BackendError(f"docker stop: {r.message()}")

    def destroy(self, rec: Record) -> None:
        r = run_cmd([self.bin, "rm", "-f", "-v", rec.runtime_name], timeout=90)
        if not r.ok and "No such" not in r.err():
            raise BackendError(f"docker rm: {r.message()}")

    def status(self, rec: Record) -> str:
        r = run_cmd([self.bin, "inspect", "-f", "{{.State.Status}}", rec.runtime_name], timeout=20)
        if not r.ok:
            return "missing" if "No such" in r.err() or "no such" in r.err() else "missing"
        return "running" if r.out().strip() == "running" else "stopped"

    def info(self, rec: Record) -> dict[str, Any]:
        r = run_cmd([self.bin, "inspect", rec.runtime_name], timeout=20)
        out: dict[str, Any] = {"runtime": f"{self.bin} container {rec.runtime_name}"}
        if r.ok:
            try:
                j = json.loads(r.out())[0]
                nets = (j.get("NetworkSettings") or {}).get("Networks") or {}
                ips = [n.get("IPAddress") for n in nets.values() if n.get("IPAddress")]
                if ips:
                    out["ip"] = ips[0]
                out["started_at"] = (j.get("State") or {}).get("StartedAt")
            except (ValueError, IndexError, AttributeError):
                pass
        st = run_cmd([self.bin, "stats", "--no-stream", "--format",
                      "cpu={{.CPUPerc}} mem={{.MemUsage}} pids={{.PIDs}}", rec.runtime_name], timeout=20)
        if st.ok and st.out().strip():
            out["usage"] = st.out().strip()
        return out

    # ----------------------------------------------------------------------- exec
    def exec(self, rec: Record, req: ExecRequest):
        argv = [self.bin, "exec", "-i", rec.runtime_name, *guest_wrap(req)]
        return run_cmd(argv, input=req.stdin if req.stdin is not None else b"", timeout=req.timeout + 5,
                       env=cli_env(), max_output=req.max_output)
