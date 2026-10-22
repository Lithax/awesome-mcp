"""Folder mappings ("mounts") between the host and a sandbox.

Only the administrator chooses host paths: they are declared under [mounts.NAME] in the config file (or with
--mount on the command line) and attached to new sandboxes through [sandbox] mounts, a profile, or - only when
[limits] allow_mount_requests is on, and after human approval - by *name* in sandbox_create. The model can never
supply a host path.

Rules enforced here (shared by the docker, lxc and qemu backends):
  * the host side must be an existing DIRECTORY (so sockets such as docker.sock can't be mapped) and must not be
    inside /proc, /sys, /dev or the runtime directory /run (except /run/media and /run/mnt, where removable
    drives live);
  * it must not overlap the server's own state directory, config file, audit log, LXC and QEMU image
    directories, nor (for writable mappings) the server's code: a sandbox that could rewrite those would
    control the host;
  * the guest side is a plain absolute path made of [A-Za-z0-9._/-] (no quoting problems in any backend);
  * the default mode is read-only.
"""
from __future__ import annotations

import os
import posixpath
import re
from typing import Any

from .errors import ConfigError, SbxError

MODES = ("ro", "rw")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
GUEST_RE = re.compile(r"^/[A-Za-z0-9._/-]+$")
# commas and quotes break docker's --mount and qemu's option syntax; control characters break everything
BAD_HOST_CHARS = re.compile(r'[,"\x00-\x1f\x7f]')
GUEST_FORBIDDEN = ("/proc", "/sys", "/dev")
HOST_FORBIDDEN = ("/proc", "/sys", "/dev")
HOST_RUNTIME_OK = ("/run/media", "/run/mnt")          # removable drives are mounted here
CODE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _under(path: str, base: str) -> bool:
    return path == base or path.startswith(base.rstrip("/") + "/")


def overlaps(a: str, b: str) -> bool:
    """True if one path equals, contains or sits inside the other."""
    return _under(a, b) or _under(b, a)


# ----------------------------------------------------------------------------- host side

def protected(cfg: Any) -> list[tuple[str, str, bool]]:
    """(real path, description, only-protected-when-writable) for everything a sandbox must not reach."""
    out = [(cfg.server.state_dir, "the server's state directory", False)]
    for path, what in ((cfg.config_path, "the server's config file"), (cfg.audit.log_file, "the audit log"),
                       (cfg.lxc.lxcpath, "the LXC container directory"),
                       (cfg.qemu.images_dir, "the QEMU image directory")):
        if path:
            out.append((os.path.realpath(path), what, False))
    out.append((os.path.realpath(CODE_DIR), "the server's own code", True))
    return out


def host_problem(real: str, rw: bool, prot: list[tuple[str, str, bool]]) -> str:
    """Why `real` (an already-resolved host path) may not be mapped, or '' if it may."""
    if real == "/":
        return "refusing to map the whole filesystem root"
    if any(_under(real, f) for f in HOST_FORBIDDEN):
        return "pseudo filesystems (/proc, /sys, /dev) cannot be mapped"
    if _under(real, "/run") and not any(_under(real, ok) for ok in HOST_RUNTIME_OK):
        return ("/run holds sockets of host services (docker, dbus, ssh-agent...) that would become reachable "
                "from the sandbox; map a different folder")
    for path, what, rw_only in prot:
        if (rw_only and not rw) or not overlaps(real, path):
            continue
        return (f"it overlaps {what} ({path}); a sandbox must not be able to read or change that. "
                "Map a narrower folder that neither contains nor sits inside it")
    return ""


def clean_host_path(raw: str, where: str) -> str:
    """Syntax check + resolution of a configured host path. Raises ConfigError."""
    if not isinstance(raw, str) or not raw:
        raise ConfigError(f"{where} must be a non-empty string")
    p = os.path.expanduser(raw)
    if not os.path.isabs(p):
        raise ConfigError(f"{where} must be an absolute path (or start with ~): {raw!r}")
    if BAD_HOST_CHARS.search(p):
        raise ConfigError(f"{where}: commas, double quotes and control characters are not supported in host paths")
    return os.path.realpath(p)


def check_host_dir(host: str, rw: bool, prot: list[tuple[str, str, bool]], name: str = "") -> str:
    """Create-time re-check (the folder may have appeared, vanished or been swapped for a symlink since the
    config was read). Returns the resolved path. Raises SbxError."""
    real = os.path.realpath(host)
    label = f" {name!r}" if name else ""
    if not os.path.isdir(real):
        raise SbxError(f"the host folder for mapping{label} ({host}) does not exist or is not a directory")
    why = host_problem(real, rw, prot)
    if why:
        raise SbxError(f"the host folder for mapping{label} cannot be used: {why}")
    return real


# ---------------------------------------------------------------------------- guest side

def clean_guest_path(raw: str, where: str) -> str:
    if not isinstance(raw, str) or not raw.startswith("/"):
        raise ConfigError(f"{where} must be an absolute path inside the sandbox: {raw!r}")
    if ".." in raw.split("/"):
        raise ConfigError(f"{where} must not contain '..'")
    p = "/" + posixpath.normpath(raw).lstrip("/")
    if p == "/":
        raise ConfigError(f"{where} cannot be '/'")
    if not GUEST_RE.match(p):
        raise ConfigError(f"{where}: only letters, digits and . _ - / are allowed in sandbox paths: {raw!r}")
    if any(_under(p, f) for f in GUEST_FORBIDDEN):
        raise ConfigError(f"{where}: nothing may be mapped inside {', '.join(GUEST_FORBIDDEN)}")
    return p


# ---------------------------------------------------------------------------- declarations

def normalize(name: str, body: Any, prot: list[tuple[str, str, bool]]) -> dict[str, str]:
    """Validate one [mounts.NAME] table; returns {'host': <real path>, 'guest': ..., 'mode': 'ro'|'rw'}."""
    where = f"[mounts.{name}]"
    if not NAME_RE.match(name):
        raise ConfigError(f"{where}: names use letters, digits, . _ - (max 32 chars, start with a letter or digit)")
    if not isinstance(body, dict):
        raise ConfigError(f"{where} must be a table with host, guest and (optionally) mode")
    bad = sorted(set(body) - {"host", "guest", "mode"})
    if bad:
        raise ConfigError(f"unknown setting {where} {bad[0]} (allowed: host, guest, mode)")
    for key in ("host", "guest"):
        if key not in body:
            raise ConfigError(f"{where} needs '{key}'")
    mode = body.get("mode", "ro")
    if mode not in MODES:
        raise ConfigError(f"{where} mode must be 'ro' or 'rw'")
    host = clean_host_path(body["host"], f"{where} host")
    why = host_problem(host, mode == "rw", prot)
    if why:
        raise ConfigError(f"{where} host = {body['host']!r}: {why}")
    return {"host": host, "guest": clean_guest_path(body["guest"], f"{where} guest"), "mode": mode}


def parse_cli(item: str) -> dict[str, str]:
    """--mount HOST:GUEST[:ro|rw]  (default ro). Host paths containing ':' must use the config file."""
    parts = item.split(":")
    mode = "ro"
    if len(parts) >= 3 and parts[-1] in MODES:
        mode = parts.pop()
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ConfigError(f"--mount expects HOST:GUEST[:ro|rw], got {item!r}")
    return {"host": parts[0], "guest": parts[1], "mode": mode}


def finalize(cfg: Any) -> dict[str, dict[str, str]]:
    """Validate every [mounts.*] table and every reference to them. Called last from config.finalize()."""
    prot = protected(cfg)
    out = {name: normalize(name, body, prot) for name, body in cfg.mounts.items()}
    refs = [("[sandbox] mounts", cfg.sandbox.mounts)]
    refs += [(f"[profiles.{n}] mounts", p["mounts"]) for n, p in cfg.profiles.items() if "mounts" in p]
    for where, names in refs:
        if len(names) > cfg.limits.max_mounts:
            raise ConfigError(f"{where}: at most {cfg.limits.max_mounts} mappings per sandbox ([limits] max_mounts)")
        if len(set(names)) != len(names):
            raise ConfigError(f"{where} lists a mapping twice")
        for n in names:
            if n not in out:
                raise ConfigError(f"{where}: unknown mapping {n!r} (declare it under [mounts.{n}])")
        guests = [out[n]["guest"] for n in names]
        if len(set(guests)) != len(guests):
            raise ConfigError(f"{where}: two mappings use the same sandbox path")
    return out


def in_mount_order(mounts: list) -> list:
    """Parents before children, so nested mappings mount in a sane order in every backend."""
    return sorted(mounts, key=lambda m: (m.guest.count("/"), m.guest))


def describe(m: Any) -> dict[str, str]:
    """What the model may know about a mapping: where it appears and whether it is writable. Never the host path."""
    return {"name": m.name, "guest": m.guest, "mode": m.mode}
