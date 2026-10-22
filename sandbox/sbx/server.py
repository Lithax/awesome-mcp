"""Server assembly, HTTP transport, and the command line."""
from __future__ import annotations

import argparse
import hmac
import ipaddress
import json
import logging
import os
import sys
import threading
import time

from mcp.server.fastmcp import FastMCP

from . import __version__, shellcore as sc
from .config import SAMPLE_CONFIG, Config, add_cli_args, build_config, default_config_path, effective
from .errors import ConfigError, SbxError
from .manager import Manager
from .tools import Hub, register_fs_tools, register_sandbox_tools, register_shell_tools

log = logging.getLogger("sandbox-mcp")


def instructions(cfg: Config) -> str:
    t = cfg.tools
    parts = ["Isolated sandboxes (containers / VMs) for running code and editing files safely."]
    if t.sandbox:
        parts.append("Create one with sandbox_create (network access is OFF unless requested and permitted; "
                     "resources are capped and sandboxes expire automatically); inspect with sandbox_list / "
                     "sandbox_info; delete with sandbox_destroy.")
    where = []
    if t.fs:
        where.append("file tools (read_file, write_file, edit_file, grep, ...)")
    if t.shell:
        where.append("run_command")
    if where:
        parts.append(f"{' and '.join(where).capitalize()} take a `sandbox` argument naming where to act"
                     + (f" (default: {t.default_sandbox!r})" if t.default_sandbox else "")
                     + ". Relative paths resolve against the sandbox's working directory"
                       f" ({cfg.sandbox.workdir} by default).")
    if t.fs:
        parts.append("File tools need python3 inside the sandbox image; run_command does not. Use transfer_files "
                     "to copy files or directories between the host and sandboxes. Secrets (.env, SSH keys) are hidden.")
    if cfg.mounts:
        parts.append("Some sandboxes have folders of the user's machine mapped in (see `mounts` in sandbox_info). "
                     "A 'rw' mapping is the user's real files: edits and deletions there are not disposable.")
    if t.shell:
        parts.append("Every run_command is a fresh, stateless shell: cd/export do not persist, so pass cwd. "
                     "Commands are classified first; if one is refused the reason is returned, so adjust the "
                     "approach rather than disguising the command. check_command dry-runs a command.")
    return " ".join(parts)


def build_server(cfg: Config) -> tuple[FastMCP, Hub]:
    audit = sc.Audit(cfg.audit.log_file or None)
    mgr = Manager(cfg, audit)
    hub = Hub(cfg, mgr, audit)
    mcp = FastMCP(cfg.server.name, instructions=instructions(cfg), host=cfg.server.host, port=cfg.server.port)
    if cfg.tools.sandbox:
        register_sandbox_tools(mcp, hub)
    if cfg.tools.fs:
        register_fs_tools(mcp, hub)
    if cfg.tools.shell:
        register_shell_tools(mcp, hub)
    return mcp, hub


def start_reaper(mgr: Manager, interval: float = 30.0) -> threading.Thread:
    def loop() -> None:
        while True:
            time.sleep(interval)
            try:
                for n in mgr.reap_expired():
                    log.info("sandbox %s expired and was destroyed", n)
            except Exception:  # noqa: BLE001
                log.exception("reaper failed")
    t = threading.Thread(target=loop, name="sbx-reaper", daemon=True)
    t.start()
    return t


# ------------------------------------------------------------------------------ HTTP

class BearerAuth:
    """Minimal ASGI middleware: constant-time bearer token check on every HTTP request."""

    def __init__(self, app, token: str):
        self.app, self._expected = app, f"Bearer {token}".encode()

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            supplied = dict(scope["headers"]).get(b"authorization", b"")
            if not hmac.compare_digest(supplied, self._expected):
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"text/plain"), (b"www-authenticate", b"Bearer")]})
                await send({"type": "http.response.body", "body": b"unauthorized"})
                return
        await self.app(scope, receive, send)


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def serve_http(mcp: FastMCP, cfg: Config) -> None:
    import uvicorn
    s = cfg.server
    token = None
    if s.no_auth:
        if not _is_loopback(s.host):
            raise ConfigError("--no-auth is only allowed on a loopback host")
        log.warning("HTTP without auth: any local process can create sandboxes and run commands through this server.")
    else:
        token = os.environ.get(s.auth_token_env, "")
        if len(token) < 16:
            raise ConfigError(f"set ${s.auth_token_env} to a secret of at least 16 characters "
                              "(e.g. `openssl rand -hex 24`), or use --no-auth on loopback")
    app = mcp.streamable_http_app()
    if token:
        app = BearerAuth(app, token)
    log.info("serving on http://%s:%d/mcp", s.host, s.port)
    uvicorn.run(app, host=s.host, port=s.port, log_level="warning")


# ------------------------------------------------------------------------------ doctor

def doctor(cfg: Config) -> int:
    mgr = Manager(cfg)
    print(f"sandbox-mcp {__version__}  state_dir={cfg.server.state_dir}  config={cfg.config_path or '(defaults)'}")
    print(f"running as uid {os.getuid()}" + ("  [WARNING: root; qemu/lxc/docker work best unprivileged]" if os.getuid() == 0 else ""))
    bad = 0
    for row in mgr.backends_info():
        if not row["enabled"]:
            print(f"  {row['backend']:7} disabled in config")
            continue
        mark = "ok  " if row["available"] else "FAIL"
        bad += not row["available"]
        print(f"  {row['backend']:7} {mark} {row['detail']}")
        print(f"          networks: {', '.join(row['networks'])}; ports on: {', '.join(row['ports_on']) or 'none'}")
        for c in row["caveats"]:
            print(f"          note: {c}")
    print(f"  default backend: {cfg.sandbox.backend}; default network: {cfg.sandbox.network}; "
          f"outbound allowed: {cfg.limits.allow_outbound}; ports allowed: {cfg.limits.allow_ports}")
    if cfg.mounts:
        attached = set(cfg.sandbox.mounts)
        print(f"  folder mappings (model may request: {cfg.limits.allow_mount_requests}):")
        for n, m in sorted(cfg.mounts.items()):
            ok = os.path.isdir(m["host"])
            bad += not ok
            print(f"    {'ok  ' if ok else 'FAIL'} {n}: {m['host']} -> {m['guest']} ({m['mode']})"
                  + ("  [attached to every new sandbox]" if n in attached else "")
                  + ("" if ok else "  <- host folder does not exist"))
    return 1 if bad else 0


# ------------------------------------------------------------------------------- main

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sandbox-mcp", description="MCP server for sandboxed environments "
                                 "(Docker / LXC / QEMU) with filesystem and shell tools.")
    add_cli_args(ap)
    args = ap.parse_args(argv)
    # stdout is the MCP channel in stdio mode: all logging goes to stderr.
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, stream=sys.stderr,
                        format="sandbox-mcp %(levelname)s: %(message)s")
    try:
        if args.init_config is not None:
            target = args.init_config or default_config_path()
            if os.path.exists(target):
                raise ConfigError(f"refusing to overwrite existing file: {target}")
            os.makedirs(os.path.dirname(os.path.abspath(target)), exist_ok=True)
            with open(target, "x", encoding="utf-8") as f:
                f.write(SAMPLE_CONFIG)
            print(f"wrote sample config to {target}")
            return 0
        cfg = build_config(args)
        if args.print_config:
            print(json.dumps(effective(cfg), indent=2, default=str))
            return 0
        if args.doctor:
            return doctor(cfg)
        if args.reap:
            gone = Manager(cfg).reap_expired()
            print("destroyed: " + (", ".join(gone) if gone else "nothing expired"))
            return 0
        mcp, hub = build_server(cfg)
        start_reaper(hub.mgr)
        log.info("backends=%s default=%s tools=%s transport=%s", [b for b in ("docker", "lxc", "qemu")
                 if cfg.backend_enabled(b)], cfg.sandbox.backend,
                 [g for g in ("sandbox", "fs", "shell") if getattr(cfg.tools, g)], cfg.server.transport)
        if cfg.server.transport == "stdio":
            mcp.run(transport="stdio")
        else:
            serve_http(mcp, cfg)
        return 0
    except ConfigError as e:
        print(f"sandbox-mcp: config error: {e}", file=sys.stderr)
        return 2
    except SbxError as e:
        print(f"sandbox-mcp: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
