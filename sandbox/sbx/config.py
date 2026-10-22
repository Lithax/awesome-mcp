"""Configuration.

Precedence (lowest to highest):  built-in defaults  <  config file  <  CLI flags  <  --set KEY=VALUE.

Every key is validated against the dataclasses below. Unknown keys are rejected on purpose: a typo
in a security setting should be loud, not silently ignored.
"""
from __future__ import annotations

import argparse
import copy
import dataclasses
import os
import re
import tomllib
import typing
from dataclasses import dataclass, field
from typing import Any

from . import __version__, shellcore
from . import mounts as mountslib
from .errors import ConfigError

BACKENDS = ("docker", "lxc", "qemu")
NETWORKS = ("none", "local", "outbound")


# --------------------------------------------------------------------------- schema

@dataclass
class ServerCfg:
    name: str = "sandbox"
    transport: str = "stdio"                # "stdio" | "streamable-http"
    host: str = "127.0.0.1"
    port: int = 8767
    auth_token_env: str = "SANDBOX_MCP_TOKEN"
    no_auth: bool = False
    state_dir: str = ""                     # default: $XDG_STATE_HOME/sandbox-mcp


@dataclass
class ToolsCfg:
    sandbox: bool = True                    # sandbox_* and image_* lifecycle tools
    fs: bool = True                         # filesystem tools
    shell: bool = True                      # run_command / check_command
    default_sandbox: str = ""               # used when a tool call omits `sandbox`


@dataclass
class SandboxDefaults:
    """Defaults for new sandboxes. A profile ([profiles.NAME]) or the create call can override any of these."""
    backend: str = "docker"
    image: str = ""                         # "" = use the per-backend image below
    image_docker: str = "debian:12-slim"
    image_lxc: str = "debian/bookworm/amd64"
    image_qemu: str = "debian-12"
    cpus: float = 1.0
    memory_mb: int = 1024
    disk_mb: int = 4096                     # hard cap for qemu; best effort for docker; see README for lxc
    pids: int = 512
    network: str = "none"                   # none | local | outbound
    ports: list[str] = field(default_factory=list)   # "[HOST:]GUEST[/tcp|udp]"
    env: dict[str, str] = field(default_factory=dict)
    workdir: str = "/workspace"
    ttl_seconds: int = 3600                 # auto-destroy after this long (0 = never, if limits allow)
    profile: str = ""
    mounts: list[str] = field(default_factory=list)  # names of [mounts.*] attached to every new sandbox


PROFILE_KEYS = ("backend", "image", "cpus", "memory_mb", "disk_mb", "pids", "network", "ports", "env",
                "workdir", "ttl_seconds", "mounts")


@dataclass
class LimitsCfg:
    """Hard ceilings. Neither the model nor a profile can exceed these."""
    max_sandboxes: int = 5
    max_cpus: float = 4.0
    max_memory_mb: int = 4096
    max_disk_mb: int = 20480
    max_pids: int = 2048
    max_ttl_seconds: int = 86400            # 0 = sandboxes may live forever
    allow_outbound: bool = False            # may a sandbox have network access at all?
    confirm_outbound: bool = True           # ask the human (MCP elicitation) before granting it
    allow_ports: bool = False               # may sandboxes publish ports to the host?
    confirm_ports: bool = True
    host_port_min: int = 20000
    host_port_max: int = 29999
    max_ports: int = 8
    bind_address: str = "127.0.0.1"         # published ports bind here; non-loopback needs allow_public_bind
    allow_public_bind: bool = False
    max_env_vars: int = 64
    max_env_value_bytes: int = 4096
    max_exec_seconds: int = 3600            # ceiling for any single in-sandbox command
    max_mounts: int = 8                     # folder mappings per sandbox
    allow_mount_requests: bool = False      # may the model pick (by name) among the declared [mounts.*]?
    confirm_mounts: bool = True             # if so, ask a human each time


@dataclass
class DockerCfg:
    enabled: bool = True
    binary: str = "docker"                  # "podman" works too (same CLI)
    outbound_network: str = "bridge"        # docker network used for network="outbound" (admin-defined, e.g. a firewalled one)
    cap_drop: list[str] = field(default_factory=lambda: ["ALL"])
    cap_add: list[str] = field(default_factory=lambda: [
        "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "SETGID", "SETUID", "SETPCAP",
        "NET_BIND_SERVICE", "SYS_CHROOT"])
    read_only_rootfs: bool = False          # true: immutable image, writable /tmp + workdir tmpfs only
    user: str = ""                          # "" = image default (usually root, with the capability set above)
    storage_opt_size: bool = False          # pass --storage-opt size=<disk_mb> (needs overlay2 on xfs+pquota)
    mount_selinux: str = ""                 # "" | "shared" (:z) | "private" (:Z): relabel mapped folders on SELinux hosts
    log_max_size: str = "10m"
    shm_mb: int = 64
    nofile: int = 4096
    extra_args: list[str] = field(default_factory=list)   # admin-only extra `docker create` flags


@dataclass
class LxcCfg:
    enabled: bool = False
    lxcpath: str = ""                       # default: <state_dir>/lxc (keeps our containers apart from yours)
    base_config: str = ""                   # included first (idmap etc.); default ~/.config/lxc/default.conf or /etc/lxc/default.conf
    allow_privileged: bool = False          # permit running as root (privileged containers: much weaker isolation)
    outbound_bridge: str = "lxcbr0"
    extra_config: list[str] = field(default_factory=list)  # raw "key = value" lines appended to every container
    create_timeout: int = 600


@dataclass
class QemuCfg:
    enabled: bool = False
    arch: str = "x86_64"                    # x86_64 | aarch64
    binary: str = ""                        # default: qemu-system-<arch>
    img_binary: str = "qemu-img"
    machine: str = ""                       # default: q35 (x86_64) / virt (aarch64)
    accel: str = "auto"                     # auto | kvm | tcg
    images_dir: str = ""                    # default: <state_dir>/images
    firmware: str = ""                      # aarch64 UEFI image (-bios)
    seccomp_sandbox: bool = True            # -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny
    boot_timeout: int = 180                 # seconds to wait for the guest agent
    cloud_init: str = "auto"                # auto | on | off  (NoCloud seed ISO; needs genisoimage/xorriso/cloud-localds)
    systemd_scope: bool = False             # wrap qemu in `systemd-run --user --scope` for host-side cgroup caps
    extra_args: list[str] = field(default_factory=list)
    images: dict[str, Any] = field(default_factory=dict)   # [qemu.images.NAME] url / sha256 / format


@dataclass
class ImagesCfg:
    docker: list[str] = field(default_factory=lambda: [
        "debian:*", "ubuntu:*", "alpine:*", "python:*", "node:*", "golang:*", "rust:*"])
    lxc: list[str] = field(default_factory=lambda: ["debian/*", "ubuntu/*", "alpine/*"])
    allow_pull: bool = True                 # may image_pull download things at all?


@dataclass
class FsCfg:
    read_only: bool = True                  # write tools are not even registered when true
    allow_delete: bool = False
    delete_mode: str = "trash"
    use_default_deny: bool = True
    deny: list[str] = field(default_factory=list)
    write_deny: list[str] = field(default_factory=list)
    search_exclude: list[str] = field(default_factory=lambda: list(
        [".git", "node_modules", "__pycache__", ".venv", "venv", ".mcp-trash"]))
    guest_roots: list[str] = field(default_factory=lambda: ["/workspace", "/tmp"])
    max_read_bytes: int = 1048576
    max_write_bytes: int = 5242880
    max_copy_bytes: int = 536870912
    max_transfer_bytes: int = 67108864      # per transfer_files call
    max_image_bytes: int = 1048576
    max_image_input_bytes: int = 8388608
    max_entries: int = 2000
    max_search_results: int = 500
    search_timeout_seconds: int = 20


@dataclass
class HostCfg:
    """The host machine itself as a target (sandbox = "host"). Off by default: sandboxes are the point."""
    enabled: bool = False
    roots: list[str] = field(default_factory=list)
    fs_write: bool = False                  # even with [fs] read_only = false, the host stays read-only unless true
    shell: bool = False                     # allow run_command on the host (uses [shell.access] mode)


@dataclass
class AuditCfg:
    log_file: str = ""


@dataclass
class Config:
    server: ServerCfg = field(default_factory=ServerCfg)
    tools: ToolsCfg = field(default_factory=ToolsCfg)
    sandbox: SandboxDefaults = field(default_factory=SandboxDefaults)
    limits: LimitsCfg = field(default_factory=LimitsCfg)
    docker: DockerCfg = field(default_factory=DockerCfg)
    lxc: LxcCfg = field(default_factory=LxcCfg)
    qemu: QemuCfg = field(default_factory=QemuCfg)
    images: ImagesCfg = field(default_factory=ImagesCfg)
    fs: FsCfg = field(default_factory=FsCfg)
    host: HostCfg = field(default_factory=HostCfg)
    audit: AuditCfg = field(default_factory=AuditCfg)
    shell: dict[str, Any] = field(default_factory=dict)        # raw [shell.*] tables, see finalize()
    profiles: dict[str, Any] = field(default_factory=dict)
    mounts: dict[str, Any] = field(default_factory=dict)       # [mounts.NAME] host / guest / mode, see finalize()
    # ---- derived (not settable from the config file) ----
    config_path: str = ""
    shell_host: shellcore.Config | None = None
    shell_guest: shellcore.Config | None = None

    def backend_enabled(self, name: str) -> bool:
        return bool(getattr(self, name).enabled)


# ------------------------------------------------------------------- generic loader

def _coerce(v: Any, tp: Any, where: str) -> Any:
    origin = typing.get_origin(tp)
    if tp is bool:
        if not isinstance(v, bool):
            raise ConfigError(f"{where} must be true or false")
        return v
    if tp is int:
        if isinstance(v, bool) or not isinstance(v, int):
            raise ConfigError(f"{where} must be an integer")
        return v
    if tp is float:
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise ConfigError(f"{where} must be a number")
        return float(v)
    if tp is str:
        if not isinstance(v, str):
            raise ConfigError(f"{where} must be a string")
        return v
    if origin is list:
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            raise ConfigError(f"{where} must be a list of strings")
        return list(v)
    if origin is dict:
        args = typing.get_args(tp)
        if not isinstance(v, dict) or not all(isinstance(k, str) for k in v):
            raise ConfigError(f"{where} must be a table")
        if args and args[1] is str and not all(isinstance(x, str) for x in v.values()):
            raise ConfigError(f"{where} must be a table of strings")
        return dict(v)
    raise ConfigError(f"internal: unsupported type for {where}")  # pragma: no cover


def _build(cls: type, data: dict[str, Any], path: str, obj: Any = None) -> Any:
    hints = typing.get_type_hints(cls, globalns=globals())
    obj = obj if obj is not None else cls()
    skip = {"config_path", "shell_host", "shell_guest"} if cls is Config else set()
    for key, value in data.items():
        where = f"[{path}] {key}" if path else f"[{key}]"
        if key not in hints or key in skip:
            raise ConfigError(f"unknown setting {where}")
        tp = hints[key]
        if dataclasses.is_dataclass(tp):
            if not isinstance(value, dict):
                raise ConfigError(f"{key} must be a [{key}] table")
            _build(tp, value, f"{path}.{key}" if path else key, getattr(obj, key))
        else:
            setattr(obj, key, _coerce(value, tp, where))
    return obj


def merge(base: dict[str, Any], over: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def set_dotted(data: dict[str, Any], dotted: str, value: Any) -> None:
    keys = dotted.split(".")
    d = data
    for k in keys[:-1]:
        d = d.setdefault(k, {})
        if not isinstance(d, dict):
            raise ConfigError(f"--set {dotted}: {k} is not a table")
    d[keys[-1]] = value


def parse_value(text: str) -> Any:
    """--set values are TOML literals when they parse (true, 5, [\"a\"]), otherwise plain strings."""
    try:
        return tomllib.loads(f"v = {text}")["v"]
    except tomllib.TOMLDecodeError:
        return text


def default_config_path() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "sandbox-mcp", "config.toml")


def default_state_dir() -> str:
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return os.path.join(base, "sandbox-mcp")


def load_toml(path: str) -> dict[str, Any]:
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {path}") from None
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"invalid TOML in {path}: {e}") from None


# ------------------------------------------------------------------------ finalize

def _positive(cfg_obj: Any, names: tuple[str, ...], label: str) -> None:
    for n in names:
        if getattr(cfg_obj, n) <= 0:
            raise ConfigError(f"[{label}] {n} must be positive")


def check_profile(name: str, body: Any) -> dict[str, Any]:
    if not isinstance(body, dict):
        raise ConfigError(f"[profiles.{name}] must be a table")
    hints = typing.get_type_hints(SandboxDefaults, globalns=globals())
    out: dict[str, Any] = {}
    for k, v in body.items():
        if k not in PROFILE_KEYS:
            raise ConfigError(f"unknown setting [profiles.{name}] {k} (allowed: {', '.join(PROFILE_KEYS)})")
        out[k] = _coerce(v, hints[k], f"[profiles.{name}] {k}")
    return out


def finalize(cfg: Config) -> Config:
    s, lim = cfg.server, cfg.limits
    if s.transport not in ("stdio", "streamable-http"):
        raise ConfigError("[server] transport must be 'stdio' or 'streamable-http'")
    if not 1 <= s.port <= 65535:
        raise ConfigError("[server] port must be between 1 and 65535")
    s.state_dir = os.path.realpath(os.path.expanduser(s.state_dir or default_state_dir()))

    d = cfg.sandbox
    if d.backend not in BACKENDS:
        raise ConfigError(f"[sandbox] backend must be one of {', '.join(BACKENDS)}")
    if d.network not in NETWORKS:
        raise ConfigError(f"[sandbox] network must be one of {', '.join(NETWORKS)}")
    if not d.workdir.startswith("/") or ".." in d.workdir.split("/"):
        raise ConfigError("[sandbox] workdir must be an absolute path inside the guest")
    _positive(lim, ("max_sandboxes", "max_cpus", "max_memory_mb", "max_disk_mb", "max_pids", "max_ports",
                    "max_env_vars", "max_env_value_bytes", "max_exec_seconds"), "limits")
    if lim.max_ttl_seconds < 0 or d.ttl_seconds < 0:
        raise ConfigError("ttl values must not be negative")
    if not 1 <= lim.host_port_min <= lim.host_port_max <= 65535:
        raise ConfigError("[limits] host_port_min/max must satisfy 1 <= min <= max <= 65535")
    if lim.bind_address not in ("127.0.0.1", "::1", "localhost") and not lim.allow_public_bind:
        raise ConfigError("[limits] bind_address is not loopback; set allow_public_bind = true if you really "
                          "mean to expose sandbox ports to the network")

    for k in ("fs",):
        fs = cfg.fs
        if fs.delete_mode not in ("trash", "permanent"):
            raise ConfigError("[fs] delete_mode must be 'trash' or 'permanent'")
        if fs.allow_delete and fs.read_only:
            raise ConfigError("[fs] allow_delete requires read_only = false")
        for r in fs.guest_roots:
            if not r.startswith("/"):
                raise ConfigError(f"[fs] guest_roots must be absolute paths: {r}")
        if not fs.guest_roots:
            raise ConfigError("[fs] guest_roots must not be empty")
        _positive(fs, ("max_read_bytes", "max_write_bytes", "max_copy_bytes", "max_transfer_bytes",
                       "max_image_bytes", "max_image_input_bytes", "max_entries", "max_search_results",
                       "search_timeout_seconds"), "fs")

    if cfg.docker.mount_selinux not in ("", "shared", "private"):
        raise ConfigError("[docker] mount_selinux must be '', 'shared' or 'private'")
    if cfg.qemu.arch not in ("x86_64", "aarch64"):
        raise ConfigError("[qemu] arch must be x86_64 or aarch64")
    if cfg.qemu.accel not in ("auto", "kvm", "tcg"):
        raise ConfigError("[qemu] accel must be auto, kvm or tcg")
    if cfg.qemu.cloud_init not in ("auto", "on", "off"):
        raise ConfigError("[qemu] cloud_init must be auto, on or off")
    for iname, spec in cfg.qemu.images.items():
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", iname):
            raise ConfigError(f"[qemu.images.{iname}] invalid image name")
        if not isinstance(spec, dict) or set(spec) - {"url", "sha256", "format"}:
            raise ConfigError(f"[qemu.images.{iname}] allowed keys: url, sha256, format")
        if not str(spec.get("url", "")).startswith("https://"):
            raise ConfigError(f"[qemu.images.{iname}] url must be https://")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", str(spec.get("sha256", ""))):
            raise ConfigError(f"[qemu.images.{iname}] sha256 (64 hex chars) is required")
        if spec.get("format", "qcow2") not in ("qcow2", "raw"):
            raise ConfigError(f"[qemu.images.{iname}] format must be qcow2 or raw")
    cfg.qemu.images_dir = os.path.realpath(os.path.expanduser(cfg.qemu.images_dir or
                                                              os.path.join(s.state_dir, "images")))
    cfg.lxc.lxcpath = os.path.realpath(os.path.expanduser(cfg.lxc.lxcpath or os.path.join(s.state_dir, "lxc")))
    if cfg.lxc.base_config:
        cfg.lxc.base_config = os.path.expanduser(cfg.lxc.base_config)

    if not cfg.backend_enabled(d.backend):
        raise ConfigError(f"[sandbox] backend = {d.backend!r} but [{d.backend}] enabled = false")
    if d.network == "outbound" and not lim.allow_outbound:
        raise ConfigError("[sandbox] network = 'outbound' requires [limits] allow_outbound = true")
    if d.ports and not lim.allow_ports:
        raise ConfigError("[sandbox] ports requires [limits] allow_ports = true")
    if d.cpus > lim.max_cpus or d.memory_mb > lim.max_memory_mb or d.disk_mb > lim.max_disk_mb \
            or d.pids > lim.max_pids:
        raise ConfigError("[sandbox] defaults exceed the [limits] ceilings")
    if lim.max_ttl_seconds and (d.ttl_seconds == 0 or d.ttl_seconds > lim.max_ttl_seconds):
        raise ConfigError("[sandbox] ttl_seconds must be within 1..[limits] max_ttl_seconds")

    cfg.profiles = {n: check_profile(n, b) for n, b in cfg.profiles.items()}
    if d.profile and d.profile not in cfg.profiles:
        raise ConfigError(f"[sandbox] profile {d.profile!r} is not defined under [profiles]")
    if cfg.tools.default_sandbox and cfg.tools.default_sandbox != "host":
        from .util import validate_name
        try:
            validate_name(cfg.tools.default_sandbox)
        except Exception:
            raise ConfigError("[tools] default_sandbox must be 'host' or a valid sandbox name") from None

    if cfg.audit.log_file:
        cfg.audit.log_file = os.path.realpath(os.path.expanduser(cfg.audit.log_file))
    if cfg.config_path:
        cfg.config_path = os.path.realpath(cfg.config_path)

    # ---- folder mappings: needs the (resolved) state/config/audit paths above ------------------
    cfg.mounts = mountslib.finalize(cfg)

    # ---- shell: [shell.<section>] tables use shell_mcp's own keys -----------------------------
    updates = shellcore.apply_schema(cfg.shell, "shell.")
    bad = [k for k in cfg.shell if k in ("server", "audit")]
    if bad:
        raise ConfigError(f"[shell.{bad[0]}] is not used here; see [server] / [audit]")
    guest = shellcore.Config()
    for attr, value in updates.items():
        setattr(guest, attr, value)
    guest.audit_log = cfg.audit.log_file
    guest.auth_token_env = s.auth_token_env
    guest.path_policy = "off" if guest.path_policy == "auto" else guest.path_policy
    guest.roots = list(cfg.fs.guest_roots)
    cfg.shell_guest = shellcore.finalize(guest, host=False)
    cfg.shell_host = None
    if cfg.host.enabled:
        if not cfg.host.roots:
            raise ConfigError("[host] enabled = true needs [host] roots = [...]")
        if cfg.host.fs_write and cfg.fs.read_only:
            raise ConfigError("[host] fs_write = true needs [fs] read_only = false")
        host = shellcore.Config()
        for attr, value in updates.items():
            setattr(host, attr, value)
        host.audit_log = cfg.audit.log_file
        host.auth_token_env = s.auth_token_env
        host.roots = list(cfg.host.roots)
        if cfg.host.shell:
            cfg.shell_host = shellcore.finalize(host, host=True)
        cfg.host.roots = shellcore._resolve_roots(list(cfg.host.roots))
    elif cfg.host.shell or cfg.host.roots:
        raise ConfigError("[host] settings are present but enabled = false")
    return cfg


# ------------------------------------------------------------------------------ CLI

def add_cli_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--config", metavar="PATH", help=f"TOML config (default: $SANDBOX_MCP_CONFIG or {default_config_path()})")
    p.add_argument("--state-dir", metavar="DIR", help="where sandboxes, images and the registry live")
    g = p.add_argument_group("new-sandbox defaults (override [sandbox])")
    g.add_argument("--backend", choices=BACKENDS)
    g.add_argument("--image", metavar="REF", help="image for the default backend")
    g.add_argument("--network", choices=NETWORKS)
    g.add_argument("--cpus", type=float)
    g.add_argument("--memory-mb", type=int)
    g.add_argument("--disk-mb", type=int)
    g.add_argument("--pids", type=int)
    g.add_argument("--ttl", type=int, metavar="SEC", dest="ttl_seconds")
    g.add_argument("--workdir", metavar="PATH")
    g.add_argument("--port", action="append", metavar="[HOST:]GUEST[/PROTO]", dest="ports",
                   help="publish a port on every new sandbox (repeatable; needs --allow-ports)")
    g.add_argument("--env", action="append", metavar="KEY=VALUE", dest="envs")
    g.add_argument("--mount", action="append", metavar="HOST:GUEST[:ro|rw]", dest="mounts",
                   help="map a host folder into every new sandbox (repeatable; read-only unless :rw)")
    g = p.add_argument_group("limits")
    g.add_argument("--max-sandboxes", type=int)
    g.add_argument("--allow-outbound", action="store_true", default=None, help="permit network = outbound")
    g.add_argument("--allow-ports", action="store_true", default=None, help="permit published ports")
    g.add_argument("--no-confirm", action="store_true", default=None,
                   help="do not ask a human before granting outbound network / ports")
    g = p.add_argument_group("tools")
    g.add_argument("--tools", metavar="LIST", help="comma list of: sandbox,fs,shell (default: all)")
    g.add_argument("--default-sandbox", metavar="NAME", help="sandbox used when a call omits `sandbox`")
    mode = g.add_mutually_exclusive_group()
    mode.add_argument("--write", dest="read_only", action="store_false", default=None, help="enable fs write tools")
    mode.add_argument("--read-only", dest="read_only", action="store_true", help="force read-only fs tools")
    g.add_argument("--allow-delete", action="store_true", default=None)
    g.add_argument("--shell-mode", choices=("standard", "permissive"), help="classifier strictness inside sandboxes")
    g.add_argument("--host-root", action="append", metavar="DIR",
                   help="enable the host target (sandbox='host') limited to DIR (repeatable)")
    g = p.add_argument_group("server")
    g.add_argument("--transport", choices=("stdio", "streamable-http"))
    g.add_argument("--host", dest="bind_host")
    g.add_argument("--listen-port", type=int, dest="listen_port")
    g.add_argument("--auth-token-env", metavar="VAR")
    g.add_argument("--no-auth", action="store_true", default=None, help="HTTP without a token (loopback only)")
    g.add_argument("--audit-log", metavar="PATH")
    p.add_argument("--set", action="append", metavar="KEY=VALUE", dest="sets",
                   help="set any config key, e.g. --set docker.binary=podman --set limits.max_cpus=2")
    p.add_argument("--print-config", action="store_true", help="print the effective config and exit")
    p.add_argument("--init-config", nargs="?", const="", metavar="PATH", help="write a sample config and exit")
    p.add_argument("--doctor", action="store_true", help="check which backends work on this machine and exit")
    p.add_argument("--reap", action="store_true", help="destroy expired sandboxes and exit")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"sandbox-mcp {__version__}")


def _cli_overrides(a: argparse.Namespace) -> dict[str, Any]:
    o: dict[str, Any] = {}
    m = {"state_dir": "server.state_dir", "backend": "sandbox.backend", "network": "sandbox.network",
         "cpus": "sandbox.cpus", "memory_mb": "sandbox.memory_mb", "disk_mb": "sandbox.disk_mb",
         "pids": "sandbox.pids", "ttl_seconds": "sandbox.ttl_seconds", "workdir": "sandbox.workdir",
         "max_sandboxes": "limits.max_sandboxes", "allow_outbound": "limits.allow_outbound",
         "allow_ports": "limits.allow_ports", "default_sandbox": "tools.default_sandbox",
         "read_only": "fs.read_only", "allow_delete": "fs.allow_delete", "transport": "server.transport",
         "bind_host": "server.host", "listen_port": "server.port", "auth_token_env": "server.auth_token_env",
         "no_auth": "server.no_auth", "audit_log": "audit.log_file", "shell_mode": "shell.access.sandbox_mode"}
    for attr, dotted in m.items():
        v = getattr(a, attr, None)
        if v is not None:
            set_dotted(o, dotted, v)
    if a.image:
        set_dotted(o, "sandbox.image", a.image)
    if a.no_confirm:
        set_dotted(o, "limits.confirm_outbound", False)
        set_dotted(o, "limits.confirm_ports", False)
    if a.ports:
        set_dotted(o, "sandbox.ports", list(a.ports))
    if a.envs:
        env = {}
        for item in a.envs:
            k, sep, v = item.partition("=")
            if not sep:
                raise ConfigError(f"--env expects KEY=VALUE, got {item!r}")
            env[k] = v
        set_dotted(o, "sandbox.env", env)
    if a.tools is not None:
        names = {t.strip() for t in a.tools.split(",") if t.strip()}
        unknown = names - {"sandbox", "fs", "shell"}
        if unknown:
            raise ConfigError(f"--tools: unknown group(s) {', '.join(sorted(unknown))}")
        for g in ("sandbox", "fs", "shell"):
            set_dotted(o, f"tools.{g}", g in names)
    if a.host_root:
        set_dotted(o, "host.enabled", True)
        set_dotted(o, "host.roots", list(a.host_root))
    return o


def _cli_mounts(raw: dict[str, Any], items: list[str]) -> None:
    """--mount adds to (never replaces) the mappings attached by the config file."""
    if not items:
        return
    table = raw.setdefault("mounts", {})
    attached = raw.setdefault("sandbox", {}).setdefault("mounts", [])
    if not isinstance(table, dict) or not isinstance(attached, list):
        raise ConfigError("[mounts] must be a table and [sandbox] mounts a list")
    attached = list(attached)
    n = 0
    for item in items:
        n += 1
        while f"cli{n}" in table:
            n += 1
        table[f"cli{n}"] = mountslib.parse_cli(item)
        attached.append(f"cli{n}")
    raw["sandbox"]["mounts"] = attached


def build_config(a: argparse.Namespace) -> Config:
    explicit = a.config or os.environ.get("SANDBOX_MCP_CONFIG")
    path = explicit or default_config_path()
    raw: dict[str, Any] = {}
    cfg_path = ""
    if explicit or os.path.exists(path):
        raw = load_toml(path)
        cfg_path = path
    raw = merge(raw, _cli_overrides(a))
    _cli_mounts(raw, a.mounts or [])
    for item in a.sets or []:
        k, sep, v = item.partition("=")
        if not sep or not k:
            raise ConfigError(f"--set expects KEY=VALUE, got {item!r}")
        set_dotted(raw, k.strip(), parse_value(v.strip()))
    return from_dict(raw, cfg_path)


def from_dict(raw: dict[str, Any], config_path: str = "") -> Config:
    cfg = _build(Config, raw, "")
    cfg.config_path = config_path
    d = cfg.sandbox
    if "image" in raw.get("sandbox", {}):
        pass
    # `[sandbox] image = X` applies to the default backend only
    if d.image:
        setattr(d, f"image_{d.backend}", d.image)
    return finalize(cfg)


def effective(cfg: Config) -> dict[str, Any]:
    d = dataclasses.asdict(cfg)
    d.pop("shell_host", None)
    d["shell_guest"] = {k: v for k, v in dataclasses.asdict(cfg.shell_guest).items()
                        if k in ("sandbox_mode", "block_at", "confirm_at", "classifier_mode", "timeout_seconds",
                                 "max_timeout_seconds", "max_output_bytes", "rate_limit_per_minute", "max_concurrent")}
    d["shell_host"] = None if cfg.shell_host is None else {"mode": cfg.shell_host.mode, "roots": cfg.shell_host.roots}
    return d


SAMPLE_CONFIG = '''\
# sandbox-mcp configuration. Precedence: defaults < this file < CLI flags < --set KEY=VALUE.
# Unknown keys are rejected on purpose: a typo in a security setting should be loud.

[server]
name = "sandbox"
transport = "stdio"                 # "stdio" or "streamable-http"
host = "127.0.0.1"                  # streamable-http only; non-loopback hosts always need a token
port = 8767                         # served at http://HOST:PORT/mcp
auth_token_env = "SANDBOX_MCP_TOKEN"
# state_dir = "~/.local/state/sandbox-mcp"   # registry, sandbox disks, qemu base images, lxc containers

[tools]
sandbox = true                      # sandbox_create / list / start / stop / destroy, image_* ...
fs = true                           # read_file, write_file, ... each takes `sandbox = "<name>"`
shell = true                        # run_command / check_command, each takes `sandbox = "<name>"`
default_sandbox = ""                # used when a call omits `sandbox` ("host" is allowed if [host] is on)

# ---------------------------------------------------------------------------------------------
# Defaults for NEW sandboxes. The model may override cpus/memory/... in sandbox_create, but never
# beyond [limits]. A profile (below) is a named preset the model can pick instead.
[sandbox]
backend = "docker"                  # docker | lxc | qemu
image = ""                          # "" = the per-backend image below; or set one for the default backend
image_docker = "debian:12-slim"
image_lxc = "debian/bookworm/amd64" # dist/release/arch[/variant] from the LXC "download" template
image_qemu = "debian-12"            # a file in [qemu] images_dir, or a [qemu.images.*] entry
cpus = 1.0
memory_mb = 1024
disk_mb = 4096
pids = 512
network = "none"                    # none: no network at all | local: published ports only (qemu) | outbound: internet
ports = []                          # e.g. ["8080:80", "5432/tcp"]; needs [limits] allow_ports
env = {}                            # environment inside the sandbox (stored with the sandbox; avoid real secrets)
workdir = "/workspace"
ttl_seconds = 3600                  # auto-destroy after this long; 0 = never (only if limits allow)
mounts = []                         # names of [mounts.*] (below) attached to every new sandbox, e.g. ["project"]

[limits]
max_sandboxes = 5
max_cpus = 4.0
max_memory_mb = 4096
max_disk_mb = 20480
max_pids = 2048
max_ttl_seconds = 86400
allow_outbound = false              # may any sandbox get network access?
confirm_outbound = true             # if so, ask a human (MCP elicitation) each time
allow_ports = false                 # may sandboxes publish ports on the host?
confirm_ports = true
host_port_min = 20000               # published host ports come from this range
host_port_max = 29999
max_ports = 8
bind_address = "127.0.0.1"          # published ports listen here (loopback only unless allow_public_bind)
allow_public_bind = false
max_env_vars = 64
max_env_value_bytes = 4096
max_exec_seconds = 3600
max_mounts = 8                      # folder mappings per sandbox
allow_mount_requests = false        # may the model choose among the declared [mounts.*] in sandbox_create?
confirm_mounts = true               # if so, ask a human (MCP elicitation) each time

# ---------------------------------------------------------------------------------------------
# Folder mappings: make a folder of THIS machine appear inside sandboxes (docker/podman bind mount,
# lxc bind mount, qemu virtio-9p). Only you choose host paths; the model sees only the sandbox path and
# the mode. Attach them with [sandbox] mounts, a profile's `mounts`, or `--mount HOST:GUEST[:ro|rw]`.
#   host   absolute path on this machine (~ allowed). Must be an existing directory.
#   guest  absolute path inside the sandbox. File tools and run_command may use it even outside guest_roots.
#   mode   "ro" (default) or "rw". "rw" means the sandbox changes REAL files here, and run_command can do so
#          even while [fs] read_only = true (that setting only governs the file tools).
# Refused: folders that overlap the state dir, this config file, the audit log or the image/lxc dirs (and the
# server's code when rw), anything under /proc /sys /dev /run (except /run/media), and the filesystem root.
# [mounts.project]
# host = "~/projects/demo"
# guest = "/workspace/demo"
# mode = "rw"
# [mounts.datasets]
# host = "/data/datasets"
# guest = "/data"                   # mode defaults to "ro"

# [profiles.web]                    # sandbox_create(profile = "web")
# backend = "docker"
# image = "node:22-slim"
# cpus = 2.0
# memory_mb = 2048
# network = "outbound"
# ports = ["3000"]
# ttl_seconds = 7200

# ---------------------------------------------------------------------------------------------
[docker]
enabled = true
binary = "docker"                   # or "podman"
outbound_network = "bridge"         # network used for network = "outbound"; point it at a firewalled network if you have one
cap_drop = ["ALL"]
cap_add = ["CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "SETGID", "SETUID", "SETPCAP", "NET_BIND_SERVICE", "SYS_CHROOT"]
read_only_rootfs = false            # true: immutable image; only /tmp and the workdir are writable (tmpfs)
user = ""                           # "" = image default
storage_opt_size = false            # enforce disk_mb via --storage-opt (overlay2 on xfs with pquota only)
mount_selinux = ""                  # SELinux hosts: "shared" (:z) or "private" (:Z) relabels mapped folders
log_max_size = "10m"
shm_mb = 64
nofile = 4096
extra_args = []                     # admin-only extra `docker create` flags

[lxc]
enabled = false
# lxcpath = ""                      # default <state_dir>/lxc
# base_config = ""                  # default ~/.config/lxc/default.conf, else /etc/lxc/default.conf (idmap for unprivileged)
allow_privileged = false            # running as root makes PRIVILEGED containers: much weaker isolation
outbound_bridge = "lxcbr0"
extra_config = []                   # raw lines, e.g. ["lxc.apparmor.profile = generated"]
create_timeout = 600

[qemu]
enabled = false
arch = "x86_64"                     # x86_64 | aarch64
# binary = ""                       # default qemu-system-<arch>
img_binary = "qemu-img"
# machine = ""                      # default q35 / virt
accel = "auto"                      # auto (kvm if /dev/kvm is usable) | kvm | tcg
# images_dir = ""                   # default <state_dir>/images
# firmware = ""                     # aarch64: path to UEFI firmware (-bios)
seccomp_sandbox = true              # qemu's own seccomp filter
boot_timeout = 180
cloud_init = "auto"                 # auto | on | off  (seed ISO: sets hostname, makes sure the guest agent runs)
systemd_scope = false               # wrap qemu in a systemd --user scope so cpus/memory are also capped on the host
extra_args = []
# Images the model may download with image_pull. sha256 is mandatory; the model cannot pick URLs.
# [qemu.images.debian-12]
# url = "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2"
# sha256 = "<64 hex chars>"
# format = "qcow2"

[images]
docker = ["debian:*", "ubuntu:*", "alpine:*", "python:*", "node:*", "golang:*", "rust:*"]   # allowed image refs (globs)
lxc = ["debian/*", "ubuntu/*", "alpine/*"]
allow_pull = true

# ---------------------------------------------------------------------------------------------
[fs]
read_only = true                    # set false to enable write tools
allow_delete = false
delete_mode = "trash"               # trash | permanent
use_default_deny = true
deny = []
write_deny = []
guest_roots = ["/workspace", "/tmp"]   # where fs tools may operate INSIDE a sandbox
max_read_bytes = 1048576
max_write_bytes = 5242880
max_transfer_bytes = 67108864       # transfer_files size cap
max_entries = 2000
max_search_results = 500

# Shell tool policy: the same keys as shell_mcp, under [shell.<section>].
# Inside sandboxes the classifier still blocks/asks for dangerous commands, but the sandbox itself
# (resources, network, disposability) is the isolation boundary.
[shell.access]
sandbox_mode = "standard"           # standard | permissive      (readonly/allowlist: host target only)
mode = "readonly"                   # host target only (see [host])
[shell.commands]
deny = ["sudo", "su", "doas"]
confirm = ["git push", "npm publish"]
[shell.policy]
rate_limit_per_minute = 120
max_concurrent = 4
[shell.limits]
timeout_seconds = 60
max_timeout_seconds = 900
max_output_bytes = 200000
[shell.classifier]
mode = "rules"                      # off | rules | model | both
[shell.session]
enabled = true                      # cwd + exported env persist between run_command calls (per `session` name)
max_sessions = 8                    # named sessions per sandbox
max_env_bytes = 65536               # cap on environment changes one session may carry
[shell.output]
redact_secrets = true

# ---------------------------------------------------------------------------------------------
# The host machine as a target (sandbox = "host"). Off by default.
[host]
enabled = false
# roots = ["~/projects"]
fs_write = false
shell = false

[audit]
# Tamper-evident JSON-lines log of every tool call (each record carries the SHA-256 of the previous one).
# log_file = "~/.local/state/sandbox-mcp/audit.jsonl"
'''
