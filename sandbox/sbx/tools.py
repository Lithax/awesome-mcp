"""The MCP tools. Three groups share one Hub:

  * sandbox  - sandbox_* and image_* lifecycle tools
  * fs       - the fs_mcp tool set; every tool takes `sandbox` (a sandbox name, or "host")
  * shell    - run_command / check_command / shell_info; every tool takes `sandbox`

A tool call never reaches a runtime directly: it names a sandbox, the Hub resolves it to a registry
record, and the Manager does the validated work. Errors that are safe to show are SbxError subclasses;
everything else is reported as a generic internal error (details go to the server log only).
"""
from __future__ import annotations

import base64
import dataclasses
import errno
import functools
import inspect
import io
import json
import logging
import os
import threading
import time
from typing import Annotated, Any

import anyio
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp import Image as McpImage
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from . import shellcore as sc
from .backends.base import ExecRequest
from .config import Config
from .errors import FsError, SbxError, ShellError
from .guest.fscore import FsCore
from .manager import Manager
from . import session as ses

log = logging.getLogger("sandbox-mcp")

IMAGE_MAX_DIM = 1568
IMAGE_MAX_PIXELS = 50_000_000
GUEST_SHELL = ('if command -v bash >/dev/null 2>&1; then exec bash --noprofile --norc -c "$1"; '
               'else exec sh -c "$1"; fi')

SandboxArg = Annotated[str | None, Field(
    description="Which sandbox to act in (see sandbox_list). Use 'host' for the host machine if it is enabled. "
                "Omit to use the server's default sandbox.")]


def P(description: str):
    """Annotated[str, Field(description=...)] - module level so FastMCP can resolve string annotations."""
    return Annotated[str, Field(description=description)]


class ConfirmRisky(BaseModel):
    approve: bool = Field(default=False, description="Tick to approve.")


class EditOp(BaseModel):
    old_text: str = Field(description="Exact text to find (must match once unless replace_all).")
    new_text: str = Field(description="Replacement text (may be empty to delete).")
    replace_all: bool = Field(default=False, description="Replace every occurrence.")


# ----------------------------------------------------------------------------- hub

@dataclasses.dataclass
class Target:
    kind: str                 # "host" | "sandbox"
    name: str
    rec: Any = None           # Record for sandboxes


class ShellRuntime:
    """Everything needed to judge and run commands for one target."""

    def __init__(self, kind: str, cfg: sc.Config, engine: sc.Engine, executor: sc.Executor | None = None):
        self.kind, self.cfg, self.engine, self.executor = kind, cfg, engine, executor
        self.strict = kind == "host" and cfg.mode in ("readonly", "allowlist")


class Hub:
    def __init__(self, cfg: Config, mgr: Manager, audit: sc.Audit):
        self.cfg, self.mgr, self.audit = cfg, mgr, audit
        g = cfg.shell_guest
        self.limiter = sc.RateLimiter(g.rate_limit_per_minute)
        self.slots = threading.BoundedSemaphore(g.max_concurrent)
        self.redact = sc.Redactor(g)
        self._rt: dict[str, ShellRuntime] = {}
        self.sessions = ses.SessionStore()
        self._lock = threading.Lock()
        self.protected = [p for p in (cfg.config_path, cfg.audit.log_file, cfg.server.state_dir,
                                      os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) if p]

    # -- targets --------------------------------------------------------------------
    def target(self, name: str | None) -> Target:
        name = name or self.cfg.tools.default_sandbox
        if not name:
            names = [r.name for r in self.mgr.reg.list()]
            raise SbxError("no sandbox specified and no default is configured. "
                           + (f"Existing sandboxes: {', '.join(names)}." if names else
                              "Create one with sandbox_create first."))
        if name == "host":
            if not self.cfg.host.enabled:
                raise SbxError("the host target is disabled; use a sandbox")
            return Target("host", "host")
        return Target("sandbox", name, self.mgr.get(name))

    def guest_roots(self, spec) -> list[str]:
        """Directories the file/shell tools may use inside a sandbox: its workdir, [fs] guest_roots, and every
        mapped folder (mapping one is the administrator's way of saying the tools should reach it)."""
        roots = [spec.workdir]
        for r in [*self.cfg.fs.guest_roots, *(m.guest for m in spec.mounts)]:
            if r not in roots:
                roots.append(r)
        return roots

    def fs_cfg(self, t: Target) -> dict[str, Any]:
        f = self.cfg.fs
        d: dict[str, Any] = dict(
            allow_delete=f.allow_delete, delete_mode=f.delete_mode, use_default_deny=f.use_default_deny,
            deny=f.deny, write_deny=f.write_deny, search_exclude=f.search_exclude,
            max_read_bytes=f.max_read_bytes, max_write_bytes=f.max_write_bytes, max_copy_bytes=f.max_copy_bytes,
            max_transfer_bytes=f.max_transfer_bytes, max_image_input_bytes=f.max_image_input_bytes,
            max_entries=f.max_entries, max_search_results=f.max_search_results,
            search_timeout_seconds=f.search_timeout_seconds, label=t.name)
        if t.kind == "host":
            d.update(roots=list(self.cfg.host.roots), read_only=f.read_only or not self.cfg.host.fs_write,
                     protected=self.protected)
        else:
            d.update(roots=self.guest_roots(t.rec.spec), read_only=f.read_only, protected=[])
        return d

    def fs(self, sandbox: str | None, tool: str, **args: Any) -> dict[str, Any]:
        t = self.target(sandbox)
        cfg = self.fs_cfg(t)
        if t.kind == "host":
            return FsCore(cfg).call(tool, args)
        return self.mgr.fs_call(t.rec, tool, args, cfg)

    # -- shell ------------------------------------------------------------------------
    def shell_runtime(self, t: Target) -> ShellRuntime:
        key = t.name if t.kind == "host" else f"{t.name}:{t.rec.id}"
        with self._lock:
            if key in self._rt:
                return self._rt[key]
            if t.kind == "host":
                if self.cfg.shell_host is None:
                    raise ShellError("run_command is disabled for the host target ([host] shell = false)")
                eng = sc.Engine(self.cfg.shell_host)
                rt = ShellRuntime("host", self.cfg.shell_host, eng, sc.Executor(self.cfg.shell_host, eng.guard))
            else:
                s = t.rec.spec
                gcfg = dataclasses.replace(
                    self.cfg.shell_guest, roots=self.guest_roots(s),
                    allow_network=s.network != "none", mode=self.cfg.shell_guest.sandbox_mode)
                rt = ShellRuntime("sandbox", gcfg, sc.Engine(gcfg, sc.GuestPathGuard(gcfg)))
            self._rt[key] = rt
            return rt

    def forget(self, name: str) -> None:
        self.sessions.reset(name)
        with self._lock:
            for k in [k for k in self._rt if k.split(":")[0] == name]:
                del self._rt[k]


# ------------------------------------------------------------------------ helpers

def _prepare_image(data: bytes, fmt: str, limit: int) -> tuple[bytes, str]:
    """Downscale/re-encode oversized images when Pillow is available; else enforce the cap."""
    try:
        from PIL import Image as PILImage
    except ImportError:
        if len(data) > limit:
            raise FsError(f"image is {len(data) // 1024} KB (limit {limit // 1024} KB); install Pillow "
                          "(`pip install pillow`) to enable automatic downscaling") from None
        return data, fmt
    PILImage.MAX_IMAGE_PIXELS = IMAGE_MAX_PIXELS
    try:
        im = PILImage.open(io.BytesIO(data))
        if im.size[0] * im.size[1] > IMAGE_MAX_PIXELS:
            raise FsError("image has too many pixels")
        im.load()
        if max(im.size) <= IMAGE_MAX_DIM and len(data) <= limit:
            return data, fmt
        im.thumbnail((IMAGE_MAX_DIM, IMAGE_MAX_DIM))
        out = io.BytesIO()
        if im.mode in ("RGBA", "LA", "P") and ("A" in im.getbands() or "transparency" in im.info):
            im.convert("RGBA").save(out, "PNG", optimize=True)
            fmt = "png"
        else:
            im.convert("RGB").save(out, "JPEG", quality=85, optimize=True)
            fmt = "jpeg"
    except FsError:
        raise
    except Exception:  # noqa: BLE001
        raise FsError("could not decode image (corrupt, unsupported, or too many pixels)") from None
    if out.tell() > limit:
        raise FsError("image is still too large after downscaling")
    return out.getvalue(), fmt


def _fail(fn_name: str, e: BaseException) -> ToolError:
    if isinstance(e, ToolError):
        return e
    if isinstance(e, (SbxError, FsError)):
        return ToolError(str(e))
    if isinstance(e, OSError):
        return ToolError(f"{errno.errorcode.get(e.errno or 0, 'OSError')}: {e.strerror or 'OS error'}")
    log.exception("unexpected error in %s", fn_name)
    return ToolError(f"internal error ({type(e).__name__})")


def make_tool(mcp: FastMCP):
    def tool(*, read_only: bool, destructive: bool = False, enabled: bool = True, open_world: bool = False):
        def deco(fn):
            @functools.wraps(fn)
            async def wrapper(*args, **kwargs):
                try:
                    if inspect.iscoroutinefunction(fn):
                        return await fn(*args, **kwargs)
                    return await anyio.to_thread.run_sync(functools.partial(fn, *args, **kwargs))
                except BaseException as e:  # noqa: BLE001
                    if isinstance(e, (KeyboardInterrupt, SystemExit, anyio.get_cancelled_exc_class())):
                        raise
                    raise _fail(fn.__name__, e) from None
            if not enabled:
                return wrapper
            ann = ToolAnnotations(readOnlyHint=read_only, destructiveHint=None if read_only else destructive,
                                  idempotentHint=read_only, openWorldHint=open_world)
            return mcp.tool(name=fn.__name__, annotations=ann)(wrapper)
        return deco
    return tool


async def confirm(ctx: Context, message: str) -> None:
    try:
        res = await ctx.elicit(message=message, schema=ConfirmRisky)
    except Exception:  # noqa: BLE001 - client without elicitation support
        raise SbxError("this needs human approval, but the client cannot ask (elicitation unsupported). "
                       "Nothing was done. An administrator can adjust [limits] confirm_* if this is intended.") from None
    if res.action != "accept" or not getattr(res.data, "approve", False):
        raise SbxError("DECLINED by the user; nothing was done.")


# ------------------------------------------------------------------ sandbox tools

def register_sandbox_tools(mcp: FastMCP, hub: Hub) -> None:
    tool, mgr, cfg = make_tool(mcp), hub.mgr, hub.cfg

    @tool(read_only=True)
    def sandbox_backends() -> str:
        """Show which sandbox backends (docker, lxc, qemu) are enabled and working here, which network modes
        each supports, their limitations, and the configured resource ceilings."""
        lim = cfg.limits
        return json.dumps({
            "backends": mgr.backends_info(),
            "defaults": {"backend": cfg.sandbox.backend, "network": cfg.sandbox.network, "cpus": cfg.sandbox.cpus,
                         "memory_mb": cfg.sandbox.memory_mb, "disk_mb": cfg.sandbox.disk_mb,
                         "ttl_seconds": cfg.sandbox.ttl_seconds, "workdir": cfg.sandbox.workdir},
            "ceilings": {"max_sandboxes": lim.max_sandboxes, "max_cpus": lim.max_cpus,
                         "max_memory_mb": lim.max_memory_mb, "max_disk_mb": lim.max_disk_mb,
                         "max_pids": lim.max_pids, "max_ttl_seconds": lim.max_ttl_seconds,
                         "network_access": lim.allow_outbound, "published_ports": lim.allow_ports,
                         "host_port_range": [lim.host_port_min, lim.host_port_max]},
            "profiles": sorted(cfg.profiles),
            "requestable_folder_mappings": (
                {n: {"guest": m["guest"], "mode": m["mode"]} for n, m in sorted(cfg.mounts.items())}
                if lim.allow_mount_requests else "not enabled: the administrator attaches mappings to new sandboxes"),
        }, indent=2)

    @tool(read_only=False)
    async def sandbox_create(
        ctx: Context,
        name: Annotated[str | None, Field(description="Name (a-z, 0-9, '-'; starts with a letter). Auto-generated if omitted.")] = None,
        profile: Annotated[str | None, Field(description="A named preset from the server configuration.")] = None,
        backend: Annotated[str | None, Field(description="docker | lxc | qemu (default: server default).")] = None,
        image: Annotated[str | None, Field(description="Image reference; must be on the server's allow-list. See image_list.")] = None,
        cpus: Annotated[float | None, Field(description="CPU limit, e.g. 0.5 or 2.", gt=0)] = None,
        memory_mb: Annotated[int | None, Field(description="Memory limit in MiB (no swap).", ge=64)] = None,
        disk_mb: Annotated[int | None, Field(description="Disk size in MiB (hard cap for qemu; best effort elsewhere).", ge=64)] = None,
        pids: Annotated[int | None, Field(description="Maximum number of processes.", ge=8)] = None,
        network: Annotated[str | None, Field(description="none (default, no network) | local (published ports only, qemu) | outbound (internet). May need human approval.")] = None,
        ports: Annotated[list[str] | None, Field(description="Publish guest ports on 127.0.0.1: '[HOST:]GUEST[/tcp|udp]'. May need human approval.")] = None,
        env: Annotated[dict[str, str] | None, Field(description="Environment variables for commands in the sandbox. Do not put real secrets here.")] = None,
        mounts: Annotated[list[str] | None, Field(description="Names of administrator-declared host-folder mappings to attach (see sandbox_backends). Only if the server allows it; a human is asked to approve. Omit to get the server's default mappings.")] = None,
        ttl_seconds: Annotated[int | None, Field(description="Auto-destroy after this many seconds.", ge=0)] = None,
        workdir: Annotated[str | None, Field(description="Working directory inside the sandbox (default /workspace).")] = None,
        start: Annotated[bool, Field(description="Start it immediately.")] = True,
    ) -> str:
        """Create an isolated sandbox (container or VM) you can then run commands and file operations in.
        Resources are capped; anything beyond the server's ceilings is refused. Network access is OFF
        unless you ask for it (and the administrator allows it)."""
        overrides = {"profile": profile, "backend": backend, "image": image, "cpus": cpus, "memory_mb": memory_mb,
                     "disk_mb": disk_mb, "pids": pids, "network": network, "ports": ports, "env": env,
                     "mounts": mounts, "ttl_seconds": ttl_seconds, "workdir": workdir}
        spec = await anyio.to_thread.run_sync(mgr.resolve_spec, overrides)
        lim = cfg.limits
        if ((spec.network != "none" and lim.confirm_outbound) or (spec.ports and lim.confirm_ports)
                or (mounts and lim.confirm_mounts)):           # mappings the ADMIN attached need no prompt
            await confirm(ctx, "An AI agent wants to create a sandbox with:\n- " + "\n- ".join(mgr.risks(spec))
                          + f"\n\nbackend={spec.backend} image={spec.image} network={spec.network}")
        rec = await anyio.to_thread.run_sync(mgr.create, name, overrides, start)
        hub.forget(rec.name)
        return json.dumps(await anyio.to_thread.run_sync(mgr.describe, rec), indent=2)

    @tool(read_only=True)
    def sandbox_list() -> str:
        """List sandboxes with their state, limits, network and time left."""
        mgr.reap_expired()
        rows = []
        for rec in mgr.reg.list():
            d = mgr.describe(rec, live=False)
            try:
                d["runtime_state"] = mgr.status(rec) if rec.state != "creating" else "creating"
            except SbxError as e:
                d["runtime_state"] = f"unknown ({e})"
            rows.append(d)
        return json.dumps(rows or "no sandboxes", indent=2)

    @tool(read_only=True)
    def sandbox_info(name: Annotated[str, Field(description="Sandbox name.")]) -> str:
        """Detailed state of one sandbox: limits, network, ports, folder mappings (a 'rw' mapping is real
        files on the user's machine), IP, live resource usage."""
        return json.dumps(mgr.describe(mgr.get(name)), indent=2)

    @tool(read_only=False)
    def sandbox_start(name: Annotated[str, Field(description="Sandbox name.")]) -> str:
        """Start a stopped sandbox (its files are kept)."""
        rec = mgr.start(name)
        hub.sessions.reset(name)
        return json.dumps(mgr.describe(rec), indent=2)

    @tool(read_only=False)
    def sandbox_stop(name: Annotated[str, Field(description="Sandbox name.")]) -> str:
        """Stop a sandbox but keep its disk. Use sandbox_start to resume."""
        mgr.stop(name)
        hub.sessions.reset(name)
        return f"stopped {name}"

    @tool(read_only=False, destructive=True)
    def sandbox_destroy(name: Annotated[str, Field(description="Sandbox name.")]) -> str:
        """Destroy a sandbox and everything in it. This cannot be undone."""
        mgr.destroy(name)
        hub.forget(name)
        return f"destroyed {name}"

    @tool(read_only=False)
    def sandbox_extend(name: Annotated[str, Field(description="Sandbox name.")],
                       seconds: Annotated[int, Field(description="Make it live this many more seconds from now.", ge=1)]) -> str:
        """Extend a sandbox's time limit (never beyond the server's maximum lifetime)."""
        rec = mgr.extend(name, seconds)
        return f"{name} now expires in {int(rec.expires_at - mgr.reg.now())}s"

    @tool(read_only=True)
    def image_list(backend: Annotated[str, Field(description="docker | lxc | qemu")]) -> str:
        """List images available for a backend (only those on the server's allow-list)."""
        return json.dumps(mgr.list_images(backend), indent=2)

    @tool(read_only=False, open_world=True)
    def image_pull(backend: Annotated[str, Field(description="docker | lxc | qemu")],
                   image: Annotated[str, Field(description="docker: 'debian:12'. lxc: 'debian/bookworm/amd64'. "
                                                           "qemu: the name of a declared image.")]) -> str:
        """Download an image so sandboxes can use it. Only allow-listed (docker/lxc) or admin-declared,
        checksum-verified (qemu) images can be fetched."""
        return mgr.pull_image(backend, image)

    @tool(read_only=False, destructive=True)
    def image_remove(backend: Annotated[str, Field(description="docker | lxc | qemu")],
                     image: Annotated[str, Field(description="Image reference.")]) -> str:
        """Remove a downloaded image (refused while a sandbox uses it)."""
        mgr.remove_image(backend, image)
        return f"removed {image}"


# ----------------------------------------------------------------------- fs tools

def register_fs_tools(mcp: FastMCP, hub: Hub) -> None:
    cfg, audit = hub.cfg, hub.audit
    ro = cfg.fs.read_only
    base = make_tool(mcp)

    def tool(*, write: bool = False, destructive: bool = False, enabled: bool = True):
        return base(read_only=not write, destructive=destructive, enabled=enabled and not (write and ro))

    def run(tool_name: str, sandbox: str | None, log_args: dict[str, Any], **args: Any) -> dict[str, Any]:
        t0, err = time.monotonic(), None
        try:
            return hub.fs(sandbox, tool_name, **args)
        except BaseException as e:  # noqa: BLE001
            err = str(e)[:300]
            raise
        finally:
            audit.log({"tool": tool_name, "sandbox": sandbox or cfg.tools.default_sandbox, "args": log_args,
                       "ok": err is None, "error": err, "ms": round((time.monotonic() - t0) * 1000, 1)})

    def text(tool_name: str, sandbox: str | None, **args: Any) -> str:
        return run(tool_name, sandbox, args, **args)["text"]

    @tool()
    def list_allowed_directories(sandbox: SandboxArg = None) -> str:
        """Show the directories file tools can access in a sandbox, its mode, and limits."""
        return text("list_allowed_directories", sandbox)

    @tool()
    def list_directory(path: P("Directory path (relative paths resolve against the sandbox workdir).") = ".",
                       details: Annotated[bool, Field(description="Include sizes and modified times.")] = False,
                       sandbox: SandboxArg = None) -> str:
        """List a directory's entries (directories first)."""
        return text("list_directory", sandbox, path=path, details=details)

    @tool()
    def directory_tree(path: P("Directory path.") = ".",
                       max_depth: Annotated[int, Field(description="How many levels to show.", ge=1, le=10)] = 3,
                       sandbox: SandboxArg = None) -> str:
        """Show a directory as a tree (bounded; skips .git, node_modules, ...)."""
        return text("directory_tree", sandbox, path=path, max_depth=max_depth)

    @tool()
    def file_info(path: P("File or directory path."),
                  include_hash: Annotated[bool, Field(description="Also compute SHA-256.")] = False,
                  sandbox: SandboxArg = None) -> str:
        """Type, size, modification time, mode (and optionally SHA-256) of a path."""
        return text("file_info", sandbox, path=path, include_hash=include_hash)

    @tool()
    def read_file(path: P("File path."),
                  start_line: Annotated[int, Field(description="First line to return (1-based).", ge=1)] = 1,
                  max_lines: Annotated[int | None, Field(description="Maximum number of lines.", ge=1)] = None,
                  encoding: Annotated[str, Field(description="'utf-8' for text, 'base64' for raw bytes.")] = "utf-8",
                  sandbox: SandboxArg = None) -> str:
        """Read a text file (size-capped; use start_line/max_lines to page through big files)."""
        return text("read_file", sandbox, path=path, start_line=start_line, max_lines=max_lines, encoding=encoding)

    @tool()
    def read_multiple_files(paths: Annotated[list[str], Field(description="Up to 20 file paths.", max_length=20)],
                            sandbox: SandboxArg = None) -> str:
        """Read several small text files in one call."""
        return text("read_multiple_files", sandbox, paths=paths)

    @tool()
    def view_image(path: P("Path of a png, jpeg, gif or webp image."), sandbox: SandboxArg = None) -> McpImage:
        """Look at an image file (large images are downscaled when Pillow is installed)."""
        res = run("view_image", sandbox, {"path": path}, path=path)
        data, fmt = _prepare_image(base64.b64decode(res["image_b64"]), res["format"], cfg.fs.max_image_bytes)
        return McpImage(data=data, format=fmt)

    @tool()
    def search_files(pattern: P("Name pattern: a glob ('*.py') or a plain substring."),
                     path: P("Where to start.") = ".",
                     max_results: Annotated[int, Field(description="Result cap.", ge=1)] = 100,
                     sandbox: SandboxArg = None) -> str:
        """Find files and directories by name (bounded, deny-aware)."""
        return text("search_files", sandbox, pattern=pattern, path=path, max_results=max_results)

    @tool()
    def grep(pattern: P("Text or regular expression to search for."), path: P("File or directory.") = ".",
             file_glob: P("Only search files whose name matches this glob.") = "*",
             regex: Annotated[bool, Field(description="Treat pattern as a regular expression.")] = False,
             case_sensitive: bool = False,
             max_matches: Annotated[int, Field(description="Match cap.", ge=1)] = 100,
             sandbox: SandboxArg = None) -> str:
        """Search file contents (skips binaries, huge files and protected paths)."""
        return text("grep", sandbox, pattern=pattern, path=path, file_glob=file_glob, regex=regex,
                    case_sensitive=case_sensitive, max_matches=max_matches)

    @tool(write=True)
    def write_file(path: P("File path."), content: P("Full file contents (UTF-8)."),
                   overwrite: Annotated[bool, Field(description="Replace the file if it exists.")] = False,
                   create_parents: bool = True, sandbox: SandboxArg = None) -> str:
        """Create a file atomically. Refuses to overwrite unless overwrite=true."""
        return run("write_file", sandbox, {"path": path, "content_bytes": len(content.encode())}, path=path,
                   content=content, overwrite=overwrite, create_parents=create_parents)["text"]

    @tool(write=True)
    def append_file(path: P("File path."), content: P("Text to append."), create: bool = True,
                    sandbox: SandboxArg = None) -> str:
        """Append text to a file."""
        return run("append_file", sandbox, {"path": path, "content_bytes": len(content.encode())}, path=path,
                   content=content, create=create)["text"]

    @tool(write=True)
    def edit_file(path: P("File path."), edits: Annotated[list[EditOp], Field(description="Edits applied in order.")],
                  dry_run: Annotated[bool, Field(description="Show the diff without writing.")] = False,
                  sandbox: SandboxArg = None) -> str:
        """Targeted find-and-replace edits; returns a unified diff. Prefer this to rewriting whole files."""
        return run("edit_file", sandbox, {"path": path, "edits": len(edits)}, path=path,
                   edits=[e.model_dump() for e in edits], dry_run=dry_run)["text"]

    @tool(write=True)
    def create_directory(path: P("Directory path."), sandbox: SandboxArg = None) -> str:
        """Create a directory (and parents)."""
        return text("create_directory", sandbox, path=path)

    @tool(write=True)
    def move_path(source: P("Existing path."), destination: P("New path."), overwrite: bool = False,
                  sandbox: SandboxArg = None) -> str:
        """Move or rename a file or directory inside one sandbox."""
        return text("move_path", sandbox, source=source, destination=destination, overwrite=overwrite)

    @tool(write=True)
    def copy_path(source: P("Existing path."), destination: P("New path."), overwrite: bool = False,
                  sandbox: SandboxArg = None) -> str:
        """Copy a file or directory tree inside one sandbox (symlinks and protected entries are skipped)."""
        return text("copy_path", sandbox, source=source, destination=destination, overwrite=overwrite)

    @tool(write=True, destructive=True, enabled=cfg.fs.allow_delete)
    def delete_path(path: P("Path to delete."),
                    recursive: Annotated[bool, Field(description="Required for non-empty directories.")] = False,
                    sandbox: SandboxArg = None) -> str:
        """Delete a file or directory (moved to .mcp-trash/ unless the server is set to delete permanently)."""
        return text("delete_path", sandbox, path=path, recursive=recursive)

    @tool(write=True)
    def transfer_files(
            source_path: P("Path to copy FROM (a file or a directory tree)."),
            destination_path: P("Full path to copy TO (it is created; the source's name is not appended)."),
            source_sandbox: Annotated[str | None, Field(description="Sandbox name or 'host' to copy from.")] = None,
            destination_sandbox: Annotated[str | None, Field(description="Sandbox name or 'host' to copy to.")] = None,
            overwrite: bool = False) -> str:
        """Copy files or directory trees between the host and sandboxes, or between two sandboxes. Symlinks,
        devices and protected files are not copied; sizes are capped."""
        t0, err = time.monotonic(), None
        try:
            packed = hub.fs(source_sandbox, "pack_path", path=source_path)
            msg = hub.fs(destination_sandbox, "unpack_path", path=destination_path, kind=packed["kind"],
                         tar_b64=packed["tar_b64"], overwrite=overwrite)["text"]
            skipped = f" ({packed['skipped']} entries skipped)" if packed.get("skipped") else ""
            return f"{source_sandbox or 'default'}:{packed['path']} -> {msg}{skipped}"
        except BaseException as e:  # noqa: BLE001
            err = str(e)[:300]
            raise
        finally:
            audit.log({"tool": "transfer_files", "from": [source_sandbox, source_path],
                       "to": [destination_sandbox, destination_path], "ok": err is None, "error": err,
                       "ms": round((time.monotonic() - t0) * 1000, 1)})


# --------------------------------------------------------------------- shell tools

def _guest_cwd(guard: sc.GuestPathGuard, raw: str | None, roots: list[str]) -> str:
    raw = raw or "."
    if "\x00" in raw:
        raise ShellError("invalid cwd")
    real = guard.real(raw, roots[0])
    root = guard.root_of(real)
    if root is None:
        raise ShellError("cwd is outside the allowed directories of this sandbox: " + ", ".join(roots))
    rel = os.path.relpath(real, root)
    if rel != os.curdir and guard.deny.hit(sc._parts(rel)):
        raise ShellError("cwd is protected by a deny rule")
    return real


def _to_exec_result(r) -> sc.ExecResult:
    return sc.ExecResult(r.exit_code, r.out(), r.err(), r.truncated, r.timed_out, r.flooded, r.duration, r.signal)


def register_shell_tools(mcp: FastMCP, hub: Hub) -> None:
    audit, mgr = hub.audit, hub.mgr
    tool = make_tool(mcp)

    def record(command: str, tgt: str, cwd: str, outcome: str, ev, ms: float, **extra: Any) -> None:
        d = ev.decision if ev else None
        audit.log({"tool": "run_command", "sandbox": tgt, "command": sc._short(command, 2000), "cwd": cwd,
                   "outcome": outcome, "level": sc.LEVELS[d.level] if d else None,
                   "rules": sorted({f.rule for f in d.findings}) if d else [],
                   "violations": d.violations if d else [], "ms": round(ms, 1), **extra})

    @tool(read_only=False, destructive=True, open_world=True)
    async def run_command(
        command: Annotated[str, Field(description="The shell command line to run (bash).")],
        ctx: Context,
        cwd: Annotated[str | None, Field(description="Working directory. Default: wherever the previous command "
                                         "in this session left off (initially the sandbox workdir).")] = None,
        timeout_seconds: Annotated[int | None, Field(description="Override the default timeout.", ge=1)] = None,
        stdin: Annotated[str | None, Field(description="Text to feed to standard input.")] = None,
        sandbox: SandboxArg = None,
        session: Annotated[str, Field(description="Shell session name. Commands in the same session share their "
                                      "working directory and exported environment variables.")] = "default",
    ) -> str:
        """Run a command inside a sandbox after it has been parsed and classified. Refused commands return the
        reason. The working directory and exported environment variables (cd, export, unset, PATH) persist between
        calls in the same session; shell functions, aliases, unexported variables and background jobs do not. A
        command that times out leaves the session as it was. Output is size-capped and scrubbed for credentials."""
        started = time.monotonic()
        ms = lambda: (time.monotonic() - started) * 1000  # noqa: E731
        tgt = await anyio.to_thread.run_sync(hub.target, sandbox)
        rt = hub.shell_runtime(tgt)
        c = rt.cfg
        if not hub.limiter.allow():
            record(command, tgt.name, cwd, "rate_limited", None, ms())
            raise ShellError("rate limit exceeded; slow down")
        sess = None
        note = ""
        if rt.kind == "sandbox" and c.session_enabled:
            sess = hub.sessions.get(tgt.name, tgt.rec.id, session, c.session_max)
        if rt.kind == "host":
            real_cwd = sc.resolve_cwd(rt.engine.guard, cwd or ".", c.roots)
        elif cwd is None and sess is not None and sess.cwd:
            try:
                real_cwd = _guest_cwd(rt.engine.guard, sess.cwd, c.roots)
            except ShellError:
                real_cwd = _guest_cwd(rt.engine.guard, ".", c.roots)
                note = f"[session: {sess.cwd} is no longer allowed or available; using {real_cwd}]"
                with sess.lock:
                    sess.cwd = None
        else:
            real_cwd = _guest_cwd(rt.engine.guard, cwd or ".", c.roots)
        timeout = min(timeout_seconds or c.timeout_seconds, c.max_timeout_seconds)
        data = stdin.encode() if stdin is not None else None
        if data is not None and len(data) > c.max_stdin_bytes:
            raise ShellError(f"stdin exceeds {c.max_stdin_bytes} bytes")

        ev = await anyio.to_thread.run_sync(rt.engine.evaluate, command, real_cwd)
        d = ev.decision
        approved = False
        if d.action == "block":
            record(command, tgt.name, real_cwd, "blocked", ev, ms())
            raise ShellError("BLOCKED (" + sc.LEVELS[d.level] + "): " + "; ".join(d.reasons)
                             + (" | model: " + "; ".join(d.notes) if any("model" in n for n in d.notes) else ""))
        if d.action == "confirm":
            if c.confirmation == "deny":
                record(command, tgt.name, real_cwd, "needs_confirmation_denied", ev, ms())
                raise ShellError("REFUSED: this command is risky (" + sc.LEVELS[d.level] + ") and needs human "
                                 "approval, but confirmation is disabled. " + "; ".join(d.reasons))
            msg = (f"An AI agent wants to run a {sc.LEVELS[d.level].upper()}-risk command in sandbox "
                   f"'{tgt.name}':\n\n{sc._short(command)}\n\nin {real_cwd}\n\nWhy it was flagged:\n- "
                   + "\n- ".join(d.reasons))
            try:
                res = await ctx.elicit(message=msg, schema=ConfirmRisky)
            except Exception:  # noqa: BLE001
                record(command, tgt.name, real_cwd, "confirmation_unavailable", ev, ms())
                raise ShellError("REFUSED: this command needs human approval but the client could not ask "
                                 "(elicitation unsupported). Not run. " + "; ".join(d.reasons)) from None
            if res.action != "accept" or not getattr(res.data, "approve", False):
                record(command, tgt.name, real_cwd, "declined_by_user", ev, ms())
                raise ShellError("DECLINED by the user; the command was not run.")
            approved = True
        if not hub.slots.acquire(blocking=False):
            raise ShellError("too many commands are already running; try again shortly")
        try:
            if rt.kind == "host":
                if rt.strict:
                    res_exec = await anyio.to_thread.run_sync(rt.executor.run_plan, ev.analysis.script, real_cwd,
                                                              float(timeout), data)
                else:
                    res_exec = await anyio.to_thread.run_sync(rt.executor.run_shell, command, real_cwd,
                                                              float(timeout), data)
            else:
                base = {"TERM": "dumb", "PAGER": "cat", "GIT_PAGER": "cat", "LANG": "C.UTF-8"}
                if sess is None:
                    req = ExecRequest(["sh", "-c", GUEST_SHELL, "sbx", command], cwd=real_cwd, env={**base, **c.env_set},
                                      stdin=data, timeout=float(timeout), max_output=c.max_output_bytes)
                    res_exec = _to_exec_result(await anyio.to_thread.run_sync(mgr.exec, tgt.rec, req))
                else:
                    prep = ses.prepare(sess, base, c.env_set)
                    req = ExecRequest(["sh", "-c", ses.GUEST_SESSION_SHELL, "sbx", command, prep.token, prep.unset],
                                      cwd=real_cwd, env=prep.env, stdin=data, timeout=float(timeout),
                                      max_output=c.max_output_bytes + ses.TRAILER_HEADROOM)
                    raw = await anyio.to_thread.run_sync(mgr.exec, tgt.rec, req)
                    raw.stdout, cap = ses.split_output(raw.stdout, prep.token)
                    lim = c.max_output_bytes
                    if len(raw.stdout) > lim or len(raw.stderr) > lim:
                        raw.stdout, raw.stderr, raw.truncated = raw.stdout[:lim], raw.stderr[:lim], True
                    res_exec = _to_exec_result(raw)
                    if cap is not None:
                        notes = ses.absorb(sess, cap, c.env_set, c.session_max_env_bytes)
                        if notes:
                            note = (note + "\n" if note else "") + "\n".join(f"[session: {n}]" for n in notes)
        except ShellError as e:
            record(command, tgt.name, real_cwd, "exec_refused", ev, ms(), error=str(e))
            raise
        finally:
            hub.slots.release()
        record(command, tgt.name, real_cwd, "ran_after_approval" if approved else "ran", ev, ms(),
               session=sess.name if sess else None,
               exit_code=res_exec.exit_code, signal=res_exec.signal, timed_out=res_exec.timed_out,
               truncated=res_exec.truncated)
        out = sc.format_result(res_exec, timeout, c, hub.redact)
        return out + ("\n" + note if note else "")

    @tool(read_only=False)
    def reset_shell_session(
        session: Annotated[str | None, Field(description="Session to reset; omit to reset all sessions of the sandbox.")] = None,
        sandbox: SandboxArg = None,
    ) -> str:
        """Forget the working directory and environment changes of a shell session (back to a fresh shell)."""
        tgt = hub.target(sandbox)
        if tgt.kind != "sandbox":
            raise ShellError("sessions only exist for sandbox targets")
        n = hub.sessions.reset(tgt.name, session)
        return f"reset {n} session(s) in {tgt.name}"

    @tool(read_only=True)
    def check_command(
        command: Annotated[str, Field(description="Command line to classify. Nothing is executed.")],
        cwd: Annotated[str, Field(description="Working directory.")] = ".",
        sandbox: SandboxArg = None,
    ) -> str:
        """Dry-run: show how run_command would treat this command (allow / needs approval / block) and why."""
        if not hub.limiter.allow():
            raise ShellError("rate limit exceeded; slow down")
        tgt = hub.target(sandbox)
        rt = hub.shell_runtime(tgt)
        real_cwd = (sc.resolve_cwd(rt.engine.guard, cwd, rt.cfg.roots) if rt.kind == "host"
                    else _guest_cwd(rt.engine.guard, cwd, rt.cfg.roots))
        ev = rt.engine.evaluate(command, real_cwd)
        d = ev.decision.to_dict()
        d["would"] = {"allow": "run", "confirm": "ask a human first", "block": "refuse"}[ev.decision.action]
        d["parsed_commands"] = ev.analysis.names
        audit.log({"tool": "check_command", "sandbox": tgt.name, "command": sc._short(command, 2000),
                   "outcome": ev.decision.action, "level": sc.LEVELS[ev.decision.level]})
        return json.dumps(d, indent=2)

    @tool(read_only=True)
    def shell_info(sandbox: SandboxArg = None) -> str:
        """Show the shell policy that applies to a sandbox: mode, network, limits, deny/confirm lists."""
        tgt = hub.target(sandbox)
        rt = hub.shell_runtime(tgt)
        c = rt.cfg
        info: dict[str, Any] = {
            "target": tgt.name, "mode": c.mode if rt.kind == "host" else c.sandbox_mode, "roots": c.roots,
            "default_cwd": c.roots[0], "network": c.allow_network,
            "classifier": {"mode": c.classifier_mode},
            "thresholds": {"confirm_at": c.confirm_at, "block_at": c.block_at, "confirmation": c.confirmation},
            "limits": {"timeout_seconds": c.timeout_seconds, "max_timeout_seconds": c.max_timeout_seconds,
                       "max_output_bytes": c.max_output_bytes, "rate_limit_per_minute": c.rate_limit_per_minute},
            "deny_list": c.deny, "confirm_list": c.confirm,
        }
        if rt.kind == "sandbox":
            info["sessions"] = {"enabled": c.session_enabled, "max": c.session_max, "open": [
                {"name": x.name, "cwd": x.cwd or c.roots[0], "env_changed": sorted(x.env_set),
                 "env_unset": sorted(x.env_unset), "commands": x.runs}      # names only, never values
                for x in hub.sessions.peek(tgt.name, tgt.rec.id)]}
        return json.dumps(info, indent=2)
