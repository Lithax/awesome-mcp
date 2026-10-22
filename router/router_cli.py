"""
router_cli: manage the router's servers.json from the command line.

    python router.py add 127.0.0.1:9000                 # scan a running HTTP/SSE server
    python router.py add https://host/mcp/foo           # explicit URL
    python router.py add --stdio -- npx -y pkg /dir     # scan a stdio server by launching it
    python router.py list
    python router.py remove NAME
    python router.py check NAME                         # dry-run the launch checks for a managed server

`add` probes the target, works out the transport (streamable HTTP vs legacy SSE),
detects whether it needs auth, connects, lists the tools, flags destructive-looking
ones, and asks only for what it can't work out itself. Pass --yes to accept defaults
(non-interactive); anything it can't decide on its own becomes an error instead.

Secrets are never written to servers.json in plaintext unless you pass
--inline-secret: they're stored as ${ENV_VAR} references and you export the
variable in the environment where the router runs.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import http.client
import ipaddress
import json
import os
import re
import shutil
import sys
import tempfile
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import router_launch

# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------


def say(*a: Any) -> None:
    print(*a, flush=True)


def slug(text: str, fallback: str = "server") -> str:
    s = re.sub(r"[^a-z0-9]+", "_", (text or "").lower()).strip("_")
    return s or fallback


def short_error(exc: BaseException) -> str:
    """Boil nested ExceptionGroups / chained errors down to one useful line."""
    leaves: list[str] = []

    def walk(e: BaseException) -> None:
        subs = getattr(e, "exceptions", None)
        if subs:
            for s in subs:
                walk(s)
        else:
            msg = str(e).strip().splitlines()
            leaves.append(f"{type(e).__name__}: {msg[0] if msg else ''}".rstrip(": "))

    walk(exc)
    return "; ".join(dict.fromkeys(leaves)) or repr(exc)


class Prompter:
    """Asks questions when attached to a terminal; otherwise returns defaults."""

    def __init__(self, assume_yes: bool) -> None:
        self.interactive = sys.stdin.isatty() and sys.stdout.isatty() and not assume_yes

    def ask(self, question: str, default: str = "") -> str:
        if not self.interactive:
            return default
        suffix = f" [{default}]" if default else ""
        try:
            return input(f"{question}{suffix}: ").strip() or default
        except EOFError:
            return default

    def confirm(self, question: str, default: bool = True) -> bool:
        if not self.interactive:
            return default
        hint = "Y/n" if default else "y/N"
        try:
            ans = input(f"{question} [{hint}] ").strip().lower()
        except EOFError:
            return default
        return default if not ans else ans.startswith("y")

    def secret(self, question: str) -> str:
        if not self.interactive:
            return ""
        return getpass.getpass(f"{question} (hidden): ").strip()


# --------------------------------------------------------------------------
# Config file I/O (atomic, with backup, preserves unrelated keys)
# --------------------------------------------------------------------------


def load_raw(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (whole_file, servers_dict) where servers_dict is a live view into it."""
    if not path.exists():
        raw: dict[str, Any] = {"mcpServers": {}}
        return raw, raw["mcpServers"]
    raw = json.loads(path.read_text() or "{}")
    if "mcpServers" in raw:
        return raw, raw["mcpServers"]
    if not raw:
        raw["mcpServers"] = {}
        return raw, raw["mcpServers"]
    return raw, raw  # flat layout: {"name": {...}} (router accepts both)


def save_raw(path: Path, raw: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = 0o600
    if path.exists():
        mode = path.stat().st_mode & 0o777
        shutil.copy2(path, path.with_name(path.name + ".bak"))
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(raw, f, indent=2)
            f.write("\n")
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


# --------------------------------------------------------------------------
# Scanning an HTTP endpoint (stdlib only, so there are no extra dependencies)
# --------------------------------------------------------------------------

_INIT = json.dumps(
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "router-scan", "version": "1"},
        },
    }
).encode()


@dataclass
class Endpoint:
    url: str
    kind: str  # "http" | "sse" | "auth" | "none" | "down"
    status: int | None = None
    www_authenticate: str = ""
    detail: str = ""
    transport: str = "http"  # for kind == "auth": which transport answered 401/403

    def describe(self) -> str:
        return {
            "http": "MCP server (streamable HTTP)",
            "sse": "MCP server (legacy SSE)",
            "auth": f"needs authentication (HTTP {self.status})",
            "none": f"not an MCP endpoint ({self.detail})",
            "down": self.detail,
        }[self.kind]


def _request(method: str, url: str, headers: dict[str, str], body: bytes | None, timeout: float):
    u = urlparse(url)
    cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
    conn = cls(u.hostname, u.port, timeout=timeout)
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    try:
        conn.request(method, path, body=body, headers=headers)
        r = conn.getresponse()  # headers only; we never read (SSE bodies don't end)
        return r.status, {k.lower(): v for k, v in r.getheaders()}
    finally:
        conn.close()


def classify(url: str, extra: dict[str, str], timeout: float) -> Endpoint:
    post_headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        **extra,
    }
    try:
        st, h = _request("POST", url, post_headers, _INIT, timeout)
    except (OSError, http.client.HTTPException) as e:
        return Endpoint(url, "down", detail=f"{type(e).__name__}: {e}")
    ctype = h.get("content-type", "")
    if st == 200 and ("json" in ctype or "event-stream" in ctype):
        return Endpoint(url, "http", st)
    if st in (401, 403):
        return Endpoint(url, "auth", st, h.get("www-authenticate", ""), transport="http")

    # Not streamable HTTP: is it a legacy SSE endpoint?
    try:
        st2, h2 = _request("GET", url, {"Accept": "text/event-stream", **extra}, None, timeout)
    except (OSError, http.client.HTTPException):
        return Endpoint(url, "none", st, detail=f"HTTP {st}")
    if st2 == 200 and "event-stream" in h2.get("content-type", ""):
        return Endpoint(url, "sse", st2)
    if st2 in (401, 403):
        return Endpoint(url, "auth", st2, h2.get("www-authenticate", ""), transport="sse")
    return Endpoint(url, "none", st, detail=f"HTTP {st}")


def _is_local(host: str) -> bool:
    if host in ("localhost", "::1") or "." not in host and ":" not in host:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private
    except ValueError:
        return False


def candidate_urls(target: str) -> list[str]:
    if "://" not in target:
        host = urlparse("//" + target).hostname or target
        target = ("http://" if _is_local(host) else "https://") + target
    u = urlparse(target)
    if u.path in ("", "/"):
        return [urlunparse(u._replace(path=p)) for p in ("/mcp", "/sse", "/mcp/", "/")]
    return [target]


def expand_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k: os.path.expandvars(v) for k, v in headers.items()}


def unresolved_vars(headers: dict[str, str]) -> list[str]:
    out: list[str] = []
    for v in expand_headers(headers).values():
        out += re.findall(r"\$\{(\w+)\}", v)
    return out


# --------------------------------------------------------------------------
# Scanning a server's contents with a real MCP client
# --------------------------------------------------------------------------

RISKY_TOKENS = {
    "delete", "remove", "rm", "drop", "destroy", "kill", "terminate", "wipe", "purge",
    "truncate", "format", "overwrite", "write", "exec", "execute", "eval", "shell",
    "bash", "sudo", "command", "install", "uninstall",
}


@dataclass
class ToolInfo:
    name: str
    description: str
    read_only: bool | None = None
    destructive: bool | None = None

    @property
    def risky(self) -> bool:
        if self.read_only:
            return False
        if self.destructive:
            return True
        words = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", self.name).lower()
        return bool(RISKY_TOKENS & set(re.split(r"[^a-z0-9]+", words)))


@dataclass
class Scan:
    name: str = ""
    version: str = ""
    instructions: str = ""
    tools: list[ToolInfo] = field(default_factory=list)


def _hint(tool: Any, snake: str, camel: str) -> bool | None:
    ann = getattr(tool, "annotations", None)
    if ann is None:
        return None
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        v = getattr(ann, snake, None)
        return v if v is not None else getattr(ann, camel, None)


async def scan_server(cfg: dict[str, Any], timeout: float) -> Scan:
    import router  # shares make_transport (and ${VAR} expansion) with the server
    from fastmcp import Client

    client = Client(router.make_transport(cfg), timeout=timeout)
    await asyncio.wait_for(client.__aenter__(), timeout=timeout)
    try:
        info = client.server_info
        tools = await router._all_tools(client)
        return Scan(
            name=getattr(info, "title", None) or getattr(info, "name", "") or "",
            version=getattr(info, "version", "") or "",
            instructions=client.instructions or "",
            tools=[
                ToolInfo(
                    t.name,
                    (t.description or "").strip(),
                    _hint(t, "read_only_hint", "readOnlyHint"),
                    _hint(t, "destructive_hint", "destructiveHint"),
                )
                for t in tools
            ],
        )
    finally:
        try:
            await client.__aexit__(None, None, None)
        except Exception:  # noqa: BLE001
            pass


# --------------------------------------------------------------------------
# Secrets: keep tokens out of servers.json
# --------------------------------------------------------------------------

SECRET_NAME = re.compile(r"(token|key|secret|password|passwd|auth)", re.I)
AUTH_SCHEME = re.compile(r"^(Bearer|Basic|Token)\s+(.+)$", re.I)


def externalize(
    name: str, value: str, default_var: str, p: Prompter, inline: bool, exports: dict[str, str]
) -> str:
    """Return what to store in servers.json for a secret-looking value."""
    if "${" in value or inline or not value:
        return value
    scheme = ""
    secret = value
    if (m := AUTH_SCHEME.match(value)):
        scheme, secret = m.group(1) + " ", m.group(2)
    var = default_var
    if p.interactive:
        var = re.sub(r"\W", "_", p.ask(f"Env var name to hold the secret for '{name}'", default_var)).upper()
    os.environ[var] = secret  # so this scan can use it
    exports[var] = secret
    return f"{scheme}${{{var}}}"


def protect_headers(
    headers: dict[str, str], default_var: str, p: Prompter, inline: bool, exports: dict[str, str]
) -> dict[str, str]:
    out = {}
    for k, v in headers.items():
        out[k] = externalize(k, v, default_var, p, inline, exports) if SECRET_NAME.search(k) else v
    return out


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def parse_kv(items: list[str], sep: str, what: str) -> dict[str, str]:
    out = {}
    for item in items or []:
        if sep not in item:
            raise SystemExit(f"error: {what} must look like 'NAME{sep}VALUE': {item!r}")
        k, v = item.split(sep, 1)
        out[k.strip()] = v.strip()
    return out


def default_var_for(target: str) -> str:
    host = urlparse(target if "://" in target else "//" + target)
    label = (host.hostname or "mcp").split(".")[0]
    if _is_local(host.hostname or "") or label.replace("-", "").isdigit():
        label = f"mcp_{host.port}" if host.port else "mcp"
    return slug(label).upper() + "_TOKEN"


def find_endpoint(target: str, headers: dict[str, str], timeout: float) -> Endpoint:
    results: list[Endpoint] = []
    for url in candidate_urls(target):
        ep = classify(url, expand_headers(headers), timeout)
        say(f"  {'✓' if ep.kind in ('http', 'sse', 'auth') else '·'} {url} — {ep.describe()}")
        if ep.kind in ("http", "sse", "auth"):
            return ep
        results.append(ep)
    # Nothing matched: prefer reporting "reachable but not MCP" over "connection refused"
    return next((e for e in results if e.kind == "none"), results[-1])


def choose_tool_filters(scan: Scan, args: argparse.Namespace, p: Prompter) -> dict[str, list[str]]:
    if args.allow or args.deny:
        out: dict[str, list[str]] = {}
        if args.allow:
            out["allow_tools"] = list(args.allow)
        if args.deny:
            out["deny_tools"] = list(args.deny)
        return out
    if args.allow_all:
        return {}
    risky = [t.name for t in scan.tools if t.risky]
    if not risky:
        return {}
    say(f"\n{len(risky)} tool(s) look destructive or able to run code/modify things:")
    for n in risky:
        say(f"  ! {n}")
    if p.confirm("Block them (deny_tools)? You can edit servers.json later", default=True):
        return {"deny_tools": risky}
    return {}


def write_entry(args: argparse.Namespace, name: str, entry: dict[str, Any], exports: dict[str, str], cfg_path: Path) -> int:
    raw, servers = load_raw(cfg_path)
    p = Prompter(args.yes)
    if name in servers and not args.force:
        if p.interactive:
            say(f"\nA server named '{name}' already exists.")
            if not p.confirm("Overwrite it?", default=False):
                name = p.ask("Choose another name", name + "_2")
                if name in servers:
                    say(f"error: '{name}' exists too; aborting.")
                    return 1
        else:
            say(f"error: '{name}' already exists in {cfg_path}. Use --name to pick another or --force to overwrite.")
            return 1
    servers[name] = entry

    say("\nEntry to save:")
    say(json.dumps({name: entry}, indent=2))
    if args.dry_run:
        say("\n(dry run: nothing written)")
        return 0
    if not p.confirm(f"Save to {cfg_path}?", default=True):
        say("Not saved.")
        return 1
    save_raw(cfg_path, raw)
    say(f"\n✓ Added '{name}' to {cfg_path}")
    say("  The router re-reads this file on every call, so no restart is needed.")
    say(f"  Try it:  list_tools(server=\"{name}\")")
    needed = [v for v in exports if "${" + v + "}" in json.dumps(entry)]  # ignore rejected attempts
    if needed:
        say("\n  The router process needs these environment variables set:")
        for var in needed:
            say(f"    export {var}=<your secret>")
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    import router

    p = Prompter(args.yes)
    cfg_path = Path(args.config) if args.config else router.CONFIG_PATH
    exports: dict[str, str] = {}
    timeout = args.timeout

    # ---- Build the connection config for the target -----------------------
    if args.stdio:
        cmd = args.target
        if not shutil.which(cmd[0]):
            say(f"error: command not found: {cmd[0]}")
            return 1
        env = parse_kv(args.env, "=", "--env")
        for k in list(env):
            if SECRET_NAME.search(k):
                env[k] = externalize(k, env[k], k.upper(), Prompter(True), args.inline_secret, exports)
        cfg: dict[str, Any] = {"command": cmd[0], "args": cmd[1:]}
        if env:
            cfg["env"] = env
        say(f"Launching {' '.join(cmd)} to scan it …")
        label = Path(cmd[-1]).stem if len(cmd) > 1 else cmd[0]
    else:
        if len(args.target) != 1:
            say("error: give exactly one URL/host:port (use --stdio for commands)")
            return 2
        target = args.target[0]
        headers = parse_kv(args.header, ":", "--header")
        var = default_var_for(target)
        headers = protect_headers(headers, var, p, args.inline_secret, exports)
        say(f"Scanning {target} …")
        ep = find_endpoint(target, headers, timeout)

        tries = 0
        user_supplied = bool(headers)  # credentials came from --header flags
        while ep.kind == "auth":
            hint = ep.www_authenticate.lower()
            if "resource_metadata" in hint or "oauth" in hint:
                say("\n  Note: this server advertises OAuth. The router only supports static tokens/headers,")
                say("  so you'll need a personal access token or API key from the service.")
            if user_supplied or tries >= 2:
                say("error: the server rejected the credentials provided.")
                if missing := unresolved_vars(headers):
                    say(f"  (environment variable(s) not set in this shell: {', '.join(missing)})")
                return 1
            if not p.interactive:
                say("error: server requires authentication. Re-run with e.g.")
                say(f"  --header 'Authorization: Bearer ${{{var}}}'   (with {var} exported)")
                return 1
            say("\nThis server requires authentication.")
            hname = p.ask("Header name", "Authorization")
            token = p.secret(f"Value for {hname} (e.g. 'Bearer abc123' or just the token)")
            if not token:
                say("No credential given; aborting.")
                return 1
            if hname.lower() == "authorization" and not AUTH_SCHEME.match(token):
                token = f"Bearer {token}"
            headers = protect_headers({hname: token}, var, p, args.inline_secret, exports)
            say(f"Re-checking {ep.url} …")
            ep = classify(ep.url, expand_headers(headers), timeout)
            say(f"  {'✓' if ep.kind in ('http', 'sse') else '·'} {ep.describe()}")
            tries += 1
        if ep.kind not in ("http", "sse"):
            say(f"\nerror: nothing answering MCP at {target}.")
            say("  Check the port/path, that the server is running, and whether it needs a different path.")
            return 1
        cfg = {"url": ep.url}
        if ep.kind == "sse":
            cfg["transport"] = "sse"
        if headers:
            cfg["headers"] = headers
        label = urlparse(ep.url).hostname or "server"

    # ---- Connect and list tools ------------------------------------------
    say("Connecting and listing tools …")
    try:
        scan = asyncio.run(scan_server(cfg, timeout))
    except KeyboardInterrupt:
        raise
    except BaseException as e:  # noqa: BLE001
        say(f"\nerror: connected but the MCP handshake failed: {short_error(e)}")
        if args.stdio:
            say("  (stdio servers often need env vars: retry with --env KEY=VALUE)")
        return 1

    say(f"\n✓ {scan.name or 'server'}" + (f" v{scan.version}" if scan.version else "") + f" — {len(scan.tools)} tool(s)")
    for t in scan.tools[:15]:
        first = t.description.splitlines()[0][:70] if t.description else ""
        say(f"    {t.name}" + (f" — {first}" if first else ""))
    if len(scan.tools) > 15:
        say(f"    … and {len(scan.tools) - 15} more")
    if scan.instructions:
        say(f"\n  Server says: {scan.instructions.strip().splitlines()[0][:120]}")

    # ---- Ask only what we can't infer ------------------------------------
    name = args.name or p.ask("\nName for this server in the router", slug(scan.name or label))
    name = slug(name)
    desc_default = ""
    if scan.instructions.strip():
        desc_default = scan.instructions.strip().splitlines()[0][:100]
    elif scan.name:
        desc_default = scan.name
    description = args.description if args.description is not None else p.ask("One-line description", desc_default)

    entry: dict[str, Any] = {}
    if description:
        entry["description"] = description
    entry.update(cfg)
    entry.update(choose_tool_filters(scan, args, p))
    if args.disabled:
        entry["disabled"] = True
    return write_entry(args, name, entry, exports, cfg_path)


def cmd_list(args: argparse.Namespace) -> int:
    import router

    path = Path(args.config) if args.config else router.CONFIG_PATH
    _, servers = load_raw(path)
    servers = {k: v for k, v in servers.items() if isinstance(v, dict)}
    if not servers:
        say(f"No servers configured in {path}")
        return 0
    say(f"{path}\n")
    for name, c in servers.items():
        kind = c.get("transport", "http") if "url" in c else "stdio"
        flags = []
        if c.get("disabled"):
            flags.append("disabled")
        if c.get("deny_tools"):
            flags.append(f"deny {len(c['deny_tools'])}")
        if c.get("allow_tools") is not None:
            flags.append(f"allow {len(c['allow_tools'])}")
        if "path" in c:
            flags.append("managed")
        say(f"  {name:<20} {kind:<6} {c.get('description', '')[:50]}" + (f"  [{', '.join(flags)}]" if flags else ""))
    return 0


def cmd_remove(args: argparse.Namespace) -> int:
    import router

    path = Path(args.config) if args.config else router.CONFIG_PATH
    raw, servers = load_raw(path)
    if args.name not in servers:
        say(f"error: no server named '{args.name}' in {path}")
        return 1
    if not args.yes:
        p = Prompter(False)
        if not p.interactive:
            say("error: not a terminal; pass --yes to confirm removal.")
            return 1
        if not p.confirm(f"Remove '{args.name}' from {path}?", default=False):
            say("Cancelled.")
            return 1
    del servers[args.name]
    save_raw(path, raw)
    say(f"✓ Removed '{args.name}' (backup: {path.name}.bak)")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Run every launch-time security check for a managed server, without launching it."""
    import router

    path = Path(args.config) if args.config else router.CONFIG_PATH
    _, servers = load_raw(path)
    cfg = servers.get(args.name)
    if not isinstance(cfg, dict):
        say(f"error: no server named '{args.name}' in {path}")
        return 1
    if "path" not in cfg:
        say(f"'{args.name}' has no 'path', so the router doesn't manage its process.")
        return 0
    try:
        if "url" in cfg:
            host, port = router_launch.loopback_target(cfg["url"])
            say(f"  ✓ url is loopback ({host}:{port})")
        launch = asyncio.run(router_launch.resolve_launch(cfg, path))
    except router_launch.LaunchError as e:
        say(f"✗ would NOT start: {e}")
        return 1
    say("  ✓ config file, project dir, entry script and interpreter all pass")
    say(f"\nWould run ({launch.interpreter} python):")
    say(f"  {' '.join(launch.argv)}")
    say(f"  cwd: {launch.cwd}")
    say(f"  env vars passed: {', '.join(sorted(launch.env))}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="router.py", description="mcp-router: serve, or manage servers.json")
    sub = ap.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", help="path to servers.json (default: $ROUTER_CONFIG or next to router.py)")
    common.add_argument("-y", "--yes", action="store_true", help="non-interactive: accept defaults, never prompt")

    a = sub.add_parser("add", parents=[common], help="scan a running MCP server and add it")
    a.add_argument("target", nargs="+", help="URL or host:port (or, with --stdio, a command and its args after --)")
    a.add_argument("--stdio", action="store_true", help="target is a command to launch, not a URL")
    a.add_argument("--name", help="name to register it under (default: from the server's own name)")
    a.add_argument("--description", help="one-line description shown by list_servers")
    a.add_argument("--header", action="append", metavar="'Name: value'", help="HTTP header, repeatable. Use ${VAR} for secrets")
    a.add_argument("--env", action="append", metavar="KEY=VALUE", help="env var for a stdio server, repeatable")
    a.add_argument("--allow", action="append", metavar="GLOB", help="only expose tools matching this glob (repeatable)")
    a.add_argument("--deny", action="append", metavar="GLOB", help="hide tools matching this glob (repeatable)")
    a.add_argument("--allow-all", action="store_true", help="don't offer to block destructive-looking tools")
    a.add_argument("--inline-secret", action="store_true", help="store secrets in plaintext instead of ${ENV_VAR} references")
    a.add_argument("--disabled", action="store_true", help="save it but disabled")
    a.add_argument("--force", action="store_true", help="overwrite an existing entry with the same name")
    a.add_argument("--dry-run", action="store_true", help="scan and show the entry, but don't write")
    a.add_argument("--timeout", type=float, default=15.0, help="seconds per network step (default 15)")
    a.set_defaults(fn=cmd_add)

    l = sub.add_parser("list", parents=[common], help="show configured servers")
    l.set_defaults(fn=cmd_list)

    r = sub.add_parser("remove", parents=[common], help="remove a server from servers.json")
    r.add_argument("name")
    r.set_defaults(fn=cmd_remove)

    c = sub.add_parser("check", parents=[common], help="dry-run the launch checks for a managed server")
    c.add_argument("name")
    c.set_defaults(fn=cmd_check)
    return ap


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except KeyboardInterrupt:
        say("\nCancelled.")
        return 130
