"""SandboxManager: the one place that turns requests into validated, limit-checked runtime operations."""
from __future__ import annotations

import fnmatch
import logging
import posixpath
import re
from typing import Any

from . import mounts as mountslib
from .backends import make_backend
from .backends.base import Backend, ExecRequest, Mount, PortMap, Record, Spec
from .config import BACKENDS, NETWORKS, PROFILE_KEYS, Config
from .errors import BackendError, FsError, SbxError
from .guest import fscore
from .registry import Registry
from .util import ENV_NAME_RE, FILE_IMAGE_RE, IMAGE_REF_RE, CmdResult, validate_name

log = logging.getLogger("sandbox-mcp")

PORT_RE = re.compile(r"^(?:(\d{1,5}):)?(\d{1,5})(?:/(tcp|udp))?$")
LXC_IMAGE_RE = re.compile(r"^[a-z0-9._-]+/[A-Za-z0-9._-]+/[a-z0-9_]+(?:/[A-Za-z0-9._-]+)?$")
_FSCORE_SOURCE: str | None = None


def fscore_source() -> str:
    global _FSCORE_SOURCE
    if _FSCORE_SOURCE is None:
        with open(fscore.__file__, encoding="utf-8") as f:
            _FSCORE_SOURCE = f.read()
    return _FSCORE_SOURCE


class Manager:
    def __init__(self, cfg: Config, audit=None):
        self.cfg = cfg
        self.audit = audit
        self.reg = Registry(cfg.server.state_dir)
        self._backends: dict[str, Backend] = {}

    # ------------------------------------------------------------------ backends
    def backend(self, name: str) -> Backend:
        if name not in BACKENDS:
            raise SbxError(f"unknown backend {name!r} (choose from {', '.join(BACKENDS)})")
        if not self.cfg.backend_enabled(name):
            raise SbxError(f"backend {name!r} is disabled in the configuration")
        if name not in self._backends:
            self._backends[name] = make_backend(name, self.cfg, self.cfg.server.state_dir)
        return self._backends[name]

    def backends_info(self) -> list[dict[str, Any]]:
        out = []
        for n in BACKENDS:
            row: dict[str, Any] = {"backend": n, "enabled": self.cfg.backend_enabled(n)}
            if row["enabled"]:
                b = self.backend(n)
                ok, detail = b.available()
                row.update(available=ok, detail=detail, networks=list(b.networks),
                           ports_on=list(b.ports_networks), caveats=list(b.caveats))
            out.append(row)
        return out

    # ------------------------------------------------------------------- audit
    def _audit(self, event: str, **kw: Any) -> None:
        if self.audit:
            self.audit.log({"event": event, **kw})

    # -------------------------------------------------------------- spec handling
    def _image_allowed(self, backend: str, image: str) -> None:
        if backend == "docker":
            if not IMAGE_REF_RE.match(image):
                raise SbxError("invalid image reference")
            pats = self.cfg.images.docker
        elif backend == "lxc":
            if not LXC_IMAGE_RE.match(image):
                raise SbxError("lxc image must look like dist/release/arch (e.g. debian/bookworm/amd64)")
            pats = self.cfg.images.lxc
        else:
            if not FILE_IMAGE_RE.match(image):
                raise SbxError("invalid image name")
            return      # qemu images are admin-provided files / declared downloads; checked at create time
        if not any(fnmatch.fnmatchcase(image, p) for p in pats):
            raise SbxError(f"image {image!r} is not on the allow-list for {backend} "
                           f"(allowed: {', '.join(pats) or 'none'})")

    def parse_ports(self, items: list[str], network: str) -> list[PortMap]:
        lim = self.cfg.limits
        if not items:
            return []
        if not lim.allow_ports:
            raise SbxError("publishing ports is disabled ([limits] allow_ports = false)")
        if len(items) > lim.max_ports:
            raise SbxError(f"at most {lim.max_ports} ports per sandbox")
        out: list[PortMap] = []
        for raw in items:
            m = PORT_RE.match(str(raw).strip())
            if not m:
                raise SbxError(f"bad port {raw!r}: use [HOST:]GUEST[/tcp|udp]")
            host, guest, proto = int(m.group(1) or 0), int(m.group(2)), m.group(3) or "tcp"
            if not 1 <= guest <= 65535:
                raise SbxError(f"guest port out of range: {guest}")
            if host and not lim.host_port_min <= host <= lim.host_port_max:
                raise SbxError(f"host port {host} is outside the allowed range "
                               f"{lim.host_port_min}-{lim.host_port_max} (omit it to auto-assign)")
            out.append(PortMap(host=host, guest=guest, proto=proto, bind=lim.bind_address))
        keys = [(p.host, p.proto) for p in out if p.host]
        if len(keys) != len(set(keys)) or len({(p.guest, p.proto) for p in out}) != len(out):
            raise SbxError("duplicate port mapping")
        return out

    def resolve_mounts(self, names: list[str]) -> list[Mount]:
        """Turn declared mapping names into validated Mounts. The host folder is checked again NOW: it may have
        appeared, vanished or been replaced by a symlink since the config was read."""
        lim = self.cfg.limits
        if len(names) > lim.max_mounts:
            raise SbxError(f"at most {lim.max_mounts} folder mappings per sandbox")
        prot = mountslib.protected(self.cfg)
        out: list[Mount] = []
        for n in names:
            decl = self.cfg.mounts.get(n) if isinstance(n, str) else None
            if decl is None:
                raise SbxError(f"unknown folder mapping {n!r} (available: {', '.join(sorted(self.cfg.mounts)) or 'none'})")
            host = mountslib.check_host_dir(decl["host"], decl["mode"] == "rw", prot, n)
            out.append(Mount(host=host, guest=decl["guest"], mode=decl["mode"], name=n))
        if len({m.name for m in out}) != len(out):
            raise SbxError("a folder mapping was listed twice")
        if len({m.guest for m in out}) != len(out):
            raise SbxError("two folder mappings use the same path inside the sandbox")
        return mountslib.in_mount_order(out)

    def resolve_spec(self, overrides: dict[str, Any] | None = None) -> Spec:
        """defaults < profile < explicit request, then validated against backend capabilities and [limits]."""
        o = {k: v for k, v in (overrides or {}).items() if v is not None}
        cfg, lim, d = self.cfg, self.cfg.limits, self.cfg.sandbox
        profile_name = o.pop("profile", None) or d.profile
        prof: dict[str, Any] = {}
        if profile_name:
            if profile_name not in cfg.profiles:
                raise SbxError(f"unknown profile {profile_name!r} (available: {', '.join(cfg.profiles) or 'none'})")
            prof = cfg.profiles[profile_name]
        unknown = set(o) - set(PROFILE_KEYS)
        if unknown:
            raise SbxError(f"unknown option(s): {', '.join(sorted(unknown))}")
        if "mounts" in o and not lim.allow_mount_requests:
            if o["mounts"]:
                raise SbxError("choosing folder mappings is not enabled on this server; the administrator attaches "
                               "them to new sandboxes ([sandbox] mounts, a profile, or --mount)")
            del o["mounts"]          # an empty list must not be able to strip the administrator's mappings

        def pick(key: str) -> Any:
            return o[key] if key in o else prof[key] if key in prof else getattr(d, key)

        backend = pick("backend")
        if backend not in BACKENDS:
            raise SbxError(f"backend must be one of {', '.join(BACKENDS)}")
        be = self.backend(backend)
        image = o.get("image") or prof.get("image") or getattr(d, f"image_{backend}")
        env = dict(d.env)
        env.update(prof.get("env", {}))
        env.update(o.get("env", {}))
        ports_raw = o["ports"] if "ports" in o else prof["ports"] if "ports" in prof else d.ports
        network = pick("network")
        workdir = posixpath.normpath(str(pick("workdir")))
        ttl = int(pick("ttl_seconds"))
        spec = Spec(backend=backend, image=str(image), cpus=float(pick("cpus")), memory_mb=int(pick("memory_mb")),
                    disk_mb=int(pick("disk_mb")), pids=int(pick("pids")), network=network, env=env,
                    workdir=workdir, ttl_seconds=ttl, profile=profile_name or "")
        # ---- validation ----
        if network not in NETWORKS:
            raise SbxError(f"network must be one of {', '.join(NETWORKS)}")
        if network not in be.networks:
            raise SbxError(f"{backend} does not support network={network!r} (supports: {', '.join(be.networks)})")
        if network == "outbound" and not lim.allow_outbound:
            raise SbxError("network access is disabled ([limits] allow_outbound = false)")
        if not re.fullmatch(r"/[A-Za-z0-9._/-]+", workdir) or workdir == "/" or ".." in workdir.split("/"):
            raise SbxError("workdir must be an absolute path (letters, digits, . _ - /) other than /")
        if not 0.1 <= spec.cpus <= lim.max_cpus:
            raise SbxError(f"cpus must be between 0.1 and {lim.max_cpus:g}")
        if not 64 <= spec.memory_mb <= lim.max_memory_mb:
            raise SbxError(f"memory_mb must be between 64 and {lim.max_memory_mb}")
        if not 64 <= spec.disk_mb <= lim.max_disk_mb:
            raise SbxError(f"disk_mb must be between 64 and {lim.max_disk_mb}")
        if not 8 <= spec.pids <= lim.max_pids:
            raise SbxError(f"pids must be between 8 and {lim.max_pids}")
        if lim.max_ttl_seconds:
            if not 1 <= ttl <= lim.max_ttl_seconds:
                raise SbxError(f"ttl_seconds must be between 1 and {lim.max_ttl_seconds}")
        elif ttl < 0:
            raise SbxError("ttl_seconds must not be negative")
        if len(env) > lim.max_env_vars:
            raise SbxError(f"at most {lim.max_env_vars} environment variables")
        for k, v in env.items():
            if not ENV_NAME_RE.match(k):
                raise SbxError(f"invalid environment variable name {k!r}")
            if not isinstance(v, str) or "\n" in v or "\x00" in v or len(v.encode()) > lim.max_env_value_bytes:
                raise SbxError(f"invalid value for {k} (single line, at most {lim.max_env_value_bytes} bytes)")
        spec.mounts = self.resolve_mounts(list(pick("mounts")))
        spec.ports = self.parse_ports(list(ports_raw), network)
        if spec.ports and network not in be.ports_networks:
            raise SbxError(f"{backend} can publish ports only with network in: "
                           f"{', '.join(be.ports_networks) or 'none (unsupported)'}")
        self._image_allowed(backend, spec.image)
        be.validate(spec)
        return spec

    @staticmethod
    def risks(spec: Spec) -> list[str]:
        """Things a human may want to approve before the sandbox is created."""
        out = []
        if spec.network == "outbound":
            out.append("internet access from inside the sandbox")
        elif spec.network == "local":
            out.append("network device with published ports only")
        if spec.ports:
            out.append("published ports on the host: " + ", ".join(str(p) for p in spec.ports) if all(p.host for p in spec.ports)
                       else f"{len(spec.ports)} published port(s) on the host")
        for m in spec.mounts:
            out.append(f"the host folder {m.host} appears inside the sandbox at {m.guest} "
                       + ("as READ-WRITE: the sandbox can change or delete real files here" if m.rw else "(read-only)"))
        return out

    # ------------------------------------------------------------------ lifecycle
    def create(self, name: str | None, overrides: dict[str, Any] | None, start: bool = True) -> Record:
        self.reap_expired()
        spec = self.resolve_spec(overrides)
        be = self.backend(spec.backend)
        ok, detail = be.available()
        if not ok:
            raise BackendError(f"{spec.backend} is not usable here: {detail}")
        with self.reg.global_lock():
            rid = self.reg.new_id()
            name = validate_name(name) if name else f"sb-{rid}"
            if self.reg.exists(name):
                raise SbxError(f"a sandbox named {name!r} already exists")
            if len(self.reg.list()) >= self.cfg.limits.max_sandboxes:
                raise SbxError(f"sandbox limit reached ({self.cfg.limits.max_sandboxes}); destroy one first")
            taken = self.reg.used_host_ports()
            for p in spec.ports:
                if not p.host:
                    p.host = self.reg.pick_host_port(self.cfg.limits.host_port_min, self.cfg.limits.host_port_max,
                                                     p.bind, taken)
                elif p.host in taken:
                    raise SbxError(f"host port {p.host} is already used by another sandbox")
                taken.add(p.host)
            now = self.reg.now()
            rec = Record(name=name, id=rid, backend=spec.backend, spec=spec, state="creating", created_at=now,
                         expires_at=(now + spec.ttl_seconds) if spec.ttl_seconds else 0.0)
            self.reg.save(rec)
        try:
            with self.reg.lock(name):
                rec.data = be.create(rec)
                rec.state = "stopped"
                self.reg.save(rec)
                if start:
                    self._start_locked(rec, be)
        except BaseException as e:
            try:
                be.destroy(rec)
            except Exception as e2:  # noqa: BLE001
                log.warning("cleanup of failed sandbox %s: %s", name, e2)
            self.reg.delete(name)
            self._audit("sandbox_create_failed", sandbox=name, error=str(e)[:300])
            raise
        self._audit("sandbox_create", sandbox=name, backend=spec.backend, image=spec.image,
                    network=spec.network, ports=[str(p) for p in spec.ports],
                    mounts=[f"{m.host}->{m.guest}:{m.mode}" for m in spec.mounts], cpus=spec.cpus,
                    memory_mb=spec.memory_mb, ttl=spec.ttl_seconds)
        return rec

    def _start_locked(self, rec: Record, be: Backend) -> None:
        be.start(rec)
        rec.state = "running"
        rec.error = ""
        self.reg.save(rec)
        # uniform provisioning: make sure the working directory exists (cloud images / bare images lack it)
        r = be.exec(rec, ExecRequest(["mkdir", "-p", rec.spec.workdir], cwd="/", timeout=30))
        if not r.ok:
            raise BackendError(f"sandbox started but could not prepare {rec.spec.workdir}: {r.message(200)}")

    def start(self, name: str) -> Record:
        rec = self.get(name)
        be = self.backend(rec.backend)
        with self.reg.lock(name):
            rec = self.reg.get(name)
            if self.status(rec) != "running":
                self._start_locked(rec, be)
        self._audit("sandbox_start", sandbox=name)
        return rec

    def stop(self, name: str) -> Record:
        rec = self.get(name)
        be = self.backend(rec.backend)
        with self.reg.lock(name):
            rec = self.reg.get(name)
            be.stop(rec)
            rec.state = "stopped"
            self.reg.save(rec)
        self._audit("sandbox_stop", sandbox=name)
        return rec

    def destroy(self, name: str, *, reason: str = "requested") -> None:
        rec = self.reg.get(name)
        be = self.backend(rec.backend)
        with self.reg.lock(name):
            try:
                be.destroy(rec)
            except BackendError as e:
                rec.state, rec.error = "error", str(e)[:300]
                self.reg.save(rec)
                raise
            self.reg.delete(name)
        self._audit("sandbox_destroy", sandbox=name, reason=reason)

    def reap_expired(self) -> list[str]:
        gone = []
        now = self.reg.now()
        for rec in self.reg.list():
            if rec.expires_at and now > rec.expires_at and rec.state != "creating":
                try:
                    self.destroy(rec.name, reason="ttl expired")
                    gone.append(rec.name)
                except SbxError as e:
                    log.warning("could not reap %s: %s", rec.name, e)
        return gone

    def extend(self, name: str, seconds: int) -> Record:
        """Push the expiry out, but never beyond [limits] max_ttl_seconds counted from creation."""
        rec = self.get(name)
        with self.reg.lock(name):
            rec = self.reg.get(name)
            new = self.reg.now() + seconds
            if self.cfg.limits.max_ttl_seconds:
                new = min(new, rec.created_at + self.cfg.limits.max_ttl_seconds)
            rec.expires_at = max(new, rec.expires_at) if rec.expires_at else new
            self.reg.save(rec)
        self._audit("sandbox_extend", sandbox=name, seconds=seconds)
        return rec

    def get(self, name: str) -> Record:
        rec = self.reg.get(name)
        if rec.expires_at and self.reg.now() > rec.expires_at and rec.state != "creating":
            self.reap_expired()
            raise SbxError(f"sandbox {name!r} reached its time limit and was destroyed")
        return rec

    def status(self, rec: Record) -> str:
        return self.backend(rec.backend).status(rec)

    def describe(self, rec: Record, live: bool = True) -> dict[str, Any]:
        s = rec.spec
        d: dict[str, Any] = {
            "name": rec.name, "backend": rec.backend, "image": s.image, "state": rec.state,
            "cpus": s.cpus, "memory_mb": s.memory_mb, "disk_mb": s.disk_mb, "pids": s.pids,
            "network": s.network, "ports": [str(p) for p in s.ports], "workdir": s.workdir,
            "mounts": [mountslib.describe(m) for m in s.mounts],
            "profile": s.profile or None, "env_names": sorted(s.env),
            "expires_in_seconds": max(0, int(rec.expires_at - self.reg.now())) if rec.expires_at else None,
        }
        if rec.error:
            d["error"] = rec.error
        if live and rec.state != "creating":
            try:
                be = self.backend(rec.backend)
                st = be.status(rec)
                d["runtime_state"] = st
                if st == "running":
                    d.update(be.info(rec))
            except SbxError as e:
                d["runtime_state"] = f"unknown ({e})"
        return d

    # ------------------------------------------------------------------- execution
    def exec(self, rec: Record, req: ExecRequest) -> CmdResult:
        if rec.state != "running":
            raise SbxError(f"sandbox {rec.name!r} is {rec.state}; use sandbox_start first")
        req.timeout = min(req.timeout, self.cfg.limits.max_exec_seconds)
        be = self.backend(rec.backend)
        r = be.exec(rec, req)
        # the in-guest `timeout -s KILL` fired: coreutils re-raises SIGKILL on itself, so depending on the
        # transport that shows up as exit 137 (docker/lxc), 124 (busybox) or signal 9 (local/guest agent)
        if (r.exit_code in (137, 124) or r.signal == 9) and r.duration >= req.timeout - 1.0:
            r.timed_out = True
        if not r.ok and re.search(r"is not running|No such container|no such container", r.err()):
            with self.reg.lock(rec.name):
                fresh = self.reg.get(rec.name)
                fresh.state = "stopped"
                self.reg.save(fresh)
            raise SbxError(f"sandbox {rec.name!r} is not running anymore; use sandbox_start")
        return r

    def fs_call(self, rec: Record, tool: str, args: dict[str, Any], fs_cfg: dict[str, Any]) -> dict[str, Any]:
        """Run one filesystem operation INSIDE the sandbox using the shipped agent (needs python3 there)."""
        from .backends.base import GUEST_PYTHON
        payload = fscore.agent_payload(fscore_source(), {"tool": tool, "args": args, "cfg": fs_cfg})
        max_out = int(self.cfg.fs.max_transfer_bytes * 1.4) + (2 << 20)
        req = ExecRequest(["sh", "-c", GUEST_PYTHON, "sbx", fscore.BOOTSTRAP], cwd="/", stdin=payload,
                          timeout=self.cfg.fs.search_timeout_seconds + 40, max_output=max_out)
        r = self.exec(rec, req)
        if r.timed_out:
            raise FsError("the filesystem operation timed out inside the sandbox")
        if r.exit_code == 127:
            raise FsError("this sandbox image has no python3, which the filesystem tools need "
                          "(run_command still works; install python3 or pick an image that has it)")
        if r.truncated:
            raise FsError("result too large to return")
        try:
            reply = fscore.parse_agent_output(r.stdout)
        except FsError:
            raise FsError(f"filesystem agent failed in the sandbox: {r.message(200)}") from None
        if not reply.get("ok"):
            raise FsError(str(reply.get("error", "filesystem error")))
        return reply

    # ----------------------------------------------------------------------- images
    def list_images(self, backend: str) -> list[dict[str, Any]]:
        be = self.backend(backend)
        rows = be.list_images()
        if backend in ("docker", "lxc"):
            pats = getattr(self.cfg.images, backend)
            rows = [r for r in rows if any(fnmatch.fnmatchcase(r["ref"], p) for p in pats)]
        return rows

    def pull_image(self, backend: str, ref: str) -> str:
        if not self.cfg.images.allow_pull:
            raise SbxError("image downloads are disabled ([images] allow_pull = false)")
        self._image_allowed(backend, ref)
        msg = self.backend(backend).pull_image(ref)
        self._audit("image_pull", backend=backend, image=ref)
        return msg

    def remove_image(self, backend: str, ref: str) -> None:
        self._image_allowed(backend, ref)
        for r in self.reg.list():
            if r.backend == backend and r.spec.image == ref:
                raise SbxError(f"image is in use by sandbox {r.name!r}")
        self.backend(backend).remove_image(ref)
        self._audit("image_remove", backend=backend, image=ref)
