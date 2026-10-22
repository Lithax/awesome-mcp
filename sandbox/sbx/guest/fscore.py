"""fscore - the filesystem engine, as a plain library (no MCP, standard library only).

This single file is used in two places:

  * in-process, for the "host" target (the original fs_mcp behaviour), and
  * shipped INTO a sandbox (docker / lxc / qemu) and executed there by `python3`, so every
    path is resolved against the guest's own filesystem and symlinks can never be used to
    steer the host. See `agent_main` at the bottom for the wire protocol.

Keep it self-contained and conservative: Python 3.8+, no third-party imports.

Security model (unchanged from fs_mcp):
  * Every path is resolved (symlinks followed) and must land inside a configured root.
  * Deny rules hide secrets from reads, listings and searches; write-deny rules protect
    code-execution footholds. Writes are atomic, size-capped and never overwrite unless asked.
  * Deletes go to an in-root trash by default. Write tools refuse to run in read-only mode
    even if they are somehow called (defence in depth; the MCP layer also doesn't register them).
"""
from __future__ import annotations

import base64
import contextlib
import datetime as dt
import difflib
import errno
import fnmatch
import hashlib
import io
import json
import os
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import time
from typing import Any, NamedTuple

TRASH_NAME = ".mcp-trash"
BINARY_SNIFF_BYTES = 8192
GREP_MAX_FILE_BYTES = 5 * 1024 * 1024
HASH_MAX_BYTES = 256 * 1024 * 1024
MAX_WALK_VISITS = 200_000
MAX_TAR_MEMBERS = 50_000
SENTINEL = b"@@SBX@@"

DEFAULT_DENY = [
    ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".config/gcloud", ".git/config",
    ".env", ".env.*", "!.env.example", "!.env.sample", "!.env.template",
    "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore", "*.kdbx",
    "id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*",
    ".netrc", "_netrc", ".npmrc", ".pypirc", ".pgpass", ".git-credentials",
    "*.tfstate", "*.tfstate.backup",
    ".bash_history", ".zsh_history", ".python_history",
]
DEFAULT_WRITE_DENY = [
    ".git", ".gitconfig", "authorized_keys",
    ".bashrc", ".bash_profile", ".bash_login", ".profile",
    ".zshrc", ".zprofile", ".zshenv", ".zlogin",
]
DEFAULT_SEARCH_EXCLUDE = [".git", "node_modules", "__pycache__", ".venv", "venv", TRASH_NAME]

DEFAULT_CFG: dict[str, Any] = {
    "label": "sandbox",
    "roots": [],
    "read_only": True,
    "allow_delete": False,
    "delete_mode": "trash",
    "use_default_deny": True,
    "deny": [],
    "write_deny": [],
    "search_exclude": list(DEFAULT_SEARCH_EXCLUDE),
    "protected": [],            # absolute paths (files or directories) that are never writable
    "max_read_bytes": 1 * 1024 * 1024,
    "max_write_bytes": 5 * 1024 * 1024,
    "max_copy_bytes": 512 * 1024 * 1024,
    "max_transfer_bytes": 64 * 1024 * 1024,
    "max_image_input_bytes": 8 * 1024 * 1024,
    "max_entries": 2000,
    "max_search_results": 500,
    "search_timeout_seconds": 20,
}

WRITE_TOOLS = {"write_file", "append_file", "edit_file", "create_directory", "move_path",
               "copy_path", "delete_path", "unpack_path"}


class FsError(Exception):
    """A user-facing error: the message is returned to the model as-is."""


# ------------------------------------------------------------------- path policy

class PatternSet:
    """Case-insensitive glob matching on path segments (and 'a/b' sequences)."""

    def __init__(self, patterns: list[str]):
        pos: list[str] = []
        neg: list[str] = []
        self._paths: list[str] = []
        for raw in patterns:
            p = raw.strip().lower().replace("\\", "/").strip("/")
            if not p:
                continue
            if p.startswith("!"):
                neg.append(p[1:])
            elif "/" in p:
                self._paths.append(p)
            else:
                pos.append(p)
        self._pos = re.compile("|".join(fnmatch.translate(x) for x in pos)) if pos else None
        self._neg = re.compile("|".join(fnmatch.translate(x) for x in neg)) if neg else None

    def hit(self, parts: list[str], last_only: bool = False) -> bool:
        if self._pos:
            for part in (parts[-1:] if last_only else parts):
                if self._pos.match(part) and not (self._neg and self._neg.match(part)):
                    return True
        n = len(parts)
        if self._paths and n:
            for i in range(n):
                for j in ([n] if last_only else range(i + 1, n + 1)):
                    seq = "/".join(parts[i:j])
                    if any(fnmatch.fnmatchcase(seq, pat) for pat in self._paths):
                        return True
        return False


class Target(NamedTuple):
    path: str   # fully resolved absolute path
    root: str   # the allowed root containing it


def _within(child: str, parent: str) -> bool:
    c, p = os.path.normcase(child), os.path.normcase(parent).rstrip("/")
    return c == p or c.startswith(p + "/") or p == ""


def _parts(rel: str) -> list[str]:
    return [s.lower() for s in re.split(r"[\\/]+", rel) if s]


def fmt_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%d B" % n if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024
    return "%s B" % n


def _iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


class Cfg:
    """Validated settings; attribute access with defaults for anything not supplied."""

    def __init__(self, raw: dict[str, Any]):
        unknown = set(raw) - set(DEFAULT_CFG)
        if unknown:
            raise FsError("unknown fs setting(s): " + ", ".join(sorted(unknown)))
        merged = dict(DEFAULT_CFG)
        merged.update(raw)
        self.__dict__.update(merged)
        if self.delete_mode not in ("trash", "permanent"):
            raise FsError("delete_mode must be 'trash' or 'permanent'")
        for k in ("max_read_bytes", "max_write_bytes", "max_copy_bytes", "max_transfer_bytes",
                  "max_image_input_bytes", "max_entries", "max_search_results",
                  "search_timeout_seconds"):
            v = getattr(self, k)
            if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
                raise FsError("%s must be a positive integer" % k)
        self.search_exclude = [s.lower() for s in self.search_exclude]


class Guard:
    """The single place where paths are validated. Every tool goes through it."""

    def __init__(self, c: Cfg):
        self.c = c
        roots: list[str] = []
        for r in c.roots:
            if not isinstance(r, str) or not os.path.isabs(r):
                raise FsError("roots must be absolute paths")
            real = os.path.realpath(r)
            if os.path.isdir(real) and real not in roots:
                roots.append(real)
        if not roots:
            raise FsError("none of the configured roots exist or are directories: " + ", ".join(c.roots))
        self.roots = roots
        deny = (DEFAULT_DENY if c.use_default_deny else []) + list(c.deny)
        wdeny = (DEFAULT_WRITE_DENY if c.use_default_deny else []) + list(c.write_deny)
        self.deny = PatternSet(deny)
        self.write_deny = PatternSet(wdeny)
        self.protected = [os.path.normcase(os.path.realpath(p)) for p in c.protected if p]

    def is_protected(self, path: str) -> bool:
        n = os.path.normcase(path)
        return any(n == p or n.startswith(p.rstrip("/") + "/") for p in self.protected)

    def root_of(self, real: str) -> str | None:
        best = None
        for r in self.roots:
            if _within(real, r) and (best is None or len(r) > len(best)):
                best = r
        return best

    def denied(self, path: str, root: str, write: bool = False) -> bool:
        rel = os.path.relpath(path, root)
        if rel == os.curdir:
            return False
        parts = _parts(rel)
        if self.deny.hit(parts):
            return True
        return write and (self.write_deny.hit(parts) or self.is_protected(path))

    def resolve(self, raw: Any, *, follow: bool = True, write: bool = False) -> Target:
        """Resolve `raw` to a real path inside a root, or raise FsError.

        follow=False keeps a final symlink as-is (for delete/move/copy-destination),
        so we operate on the link itself rather than whatever it points to.
        """
        if not isinstance(raw, str) or not raw.strip():
            raise FsError("path must be a non-empty string")
        if "\x00" in raw:
            raise FsError("invalid path")
        p = raw if os.path.isabs(raw) else os.path.join(self.roots[0], raw)
        if follow:
            real = os.path.realpath(p)
        else:
            stripped = p.rstrip("/\\") or p
            parent, name = os.path.split(stripped)
            if name in ("", os.curdir, os.pardir):
                raise FsError("ambiguous path: end it with a real name, not '.' or '..'")
            real = os.path.join(os.path.realpath(parent), name)
        root = self.root_of(real)
        if root is None:
            raise FsError("access denied: path is outside the allowed directories")
        if self.denied(real, root, write):
            raise FsError("access denied: path is protected by a deny rule"
                          + (" (read-only name)" if write and not self.denied(real, root) else ""))
        return Target(real, root)

    def forbid_root_or_trash(self, t: Target) -> None:
        if os.path.normcase(t.path) in {os.path.normcase(r) for r in self.roots}:
            raise FsError("refusing to modify an allowed root directory itself")
        if os.path.normcase(t.path) == os.path.normcase(os.path.join(t.root, TRASH_NAME)):
            raise FsError("refusing to modify the trash directory itself")


# ------------------------------------------------------------------ file helpers

def _open_regular(real: str) -> int:
    """Open read-only without following a final symlink; refuse FIFOs/devices (no hangs)."""
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
             | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0))
    fd = os.open(real, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise FsError("not a regular file")
    except BaseException:
        os.close(fd)
        raise
    return fd


def _atomic_write(real: str, data: bytes, mode: int | None = None) -> None:
    parent = os.path.dirname(real)
    if mode is None:
        try:
            mode = stat.S_IMODE(os.stat(real).st_mode)
        except FileNotFoundError:
            mode = 0o644
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".fsmcp-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        with contextlib.suppress(OSError):
            os.chmod(tmp, mode)
        os.replace(tmp, real)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


class Walk:
    """Bounded, symlink-skipping, deny-aware recursive walk."""

    def __init__(self, g: Guard, top: Target, exclude: list[str], timeout: float):
        self.g, self.top, self.exclude = g, top, set(exclude)
        self.deadline = time.monotonic() + timeout
        self.reason: str | None = None
        rel = os.path.relpath(top.path, top.root)
        self.start_parts = [] if rel == os.curdir else _parts(rel)

    def __iter__(self):
        visits = 0
        stack = [(self.top.path, self.start_parts)]
        while stack:
            d, parts = stack.pop()
            try:
                with os.scandir(d) as it:
                    entries = sorted(it, key=lambda e: e.name)
            except OSError:
                continue
            subdirs = []
            for e in entries:
                visits += 1
                if visits > MAX_WALK_VISITS:
                    self.reason = "visit limit reached"
                    return
                if (visits & 255) == 0 and time.monotonic() > self.deadline:
                    self.reason = "time limit reached"
                    return
                eparts = parts + [e.name.lower()]
                if self.g.deny.hit(eparts, last_only=True):
                    continue
                if e.is_symlink():
                    continue
                full = os.path.join(d, e.name)
                if e.is_dir(follow_symlinks=False):
                    if e.name.lower() in self.exclude:
                        continue
                    subdirs.append((full, eparts))
                    yield full, e.name, True
                else:
                    yield full, e.name, False
            stack.extend(reversed(subdirs))


def sniff_image(head: bytes) -> str | None:
    """Identify an image by its magic bytes (never trust the file extension)."""
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head[:4] == b"GIF8":
        return "gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    return None


def _check_int(name: str, v: Any, lo: int = 0, hi: int | None = None) -> int:
    if not isinstance(v, int) or isinstance(v, bool) or v < lo or (hi is not None and v > hi):
        raise FsError("%s must be an integer >= %d" % (name, lo))
    return v


def _check_str(name: str, v: Any) -> str:
    if not isinstance(v, str):
        raise FsError("%s must be a string" % name)
    return v


# --------------------------------------------------------------------- the engine

class FsCore:
    def __init__(self, cfg: dict[str, Any]):
        self.c = Cfg(cfg)
        self.g = Guard(self.c)

    # -- dispatch ----------------------------------------------------------------
    def call(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        fn = getattr(self, "t_" + tool, None) if re.fullmatch(r"[a-z_]+", tool or "") else None
        if fn is None:
            raise FsError("unknown filesystem operation: %r" % (tool,))
        if tool in WRITE_TOOLS and self.c.read_only:
            raise FsError("this filesystem target is read-only")
        if tool == "delete_path" and not self.c.allow_delete:
            raise FsError("delete is disabled")
        if not isinstance(args, dict):
            raise FsError("arguments must be an object")
        try:
            res = fn(**args)
        except TypeError as e:
            raise FsError("bad arguments for %s: %s" % (tool, e)) from None
        return res if isinstance(res, dict) else {"text": res}

    # -- info ------------------------------------------------------------------
    def t_list_allowed_directories(self) -> str:
        c = self.c
        return json.dumps({
            "target": c.label, "roots": self.g.roots, "default_root_for_relative_paths": self.g.roots[0],
            "mode": "read-only" if c.read_only else "read-write",
            "delete": (c.delete_mode if c.allow_delete else "disabled"),
            "limits": {"max_read_bytes": c.max_read_bytes, "max_write_bytes": c.max_write_bytes,
                       "max_entries": c.max_entries, "max_search_results": c.max_search_results},
        }, indent=2)

    # -- read tools ------------------------------------------------------------
    def t_list_directory(self, path: str = ".", details: bool = False) -> str:
        g, c = self.g, self.c
        t = g.resolve(path)
        if not os.path.isdir(t.path):
            raise FsError("not a directory")
        rows, hidden, over = [], 0, False
        with os.scandir(t.path) as it:
            for e in it:
                if g.denied(os.path.join(t.path, e.name), t.root):
                    hidden += 1
                    continue
                if len(rows) >= c.max_entries:
                    over = True
                    break
                link = e.is_symlink()
                isdir = (not link) and e.is_dir(follow_symlinks=False)
                size = mtime = None
                if details:
                    with contextlib.suppress(OSError):
                        st = e.stat(follow_symlinks=False)
                        size, mtime = st.st_size, st.st_mtime
                rows.append((isdir, e.name, link, size, mtime))
        rows.sort(key=lambda r: (not r[0], r[1].lower()))
        lines = ["%s  (%d entries)" % (t.path, len(rows))]
        for isdir, name, link, size, mtime in rows:
            tag = "[LINK]" if link else "[DIR] " if isdir else "[FILE]"
            line = "%s %s%s" % (tag, name, "/" if isdir else "")
            if details and size is not None and not isdir:
                line += "  " + fmt_size(size)
            if details and mtime is not None:
                line += "  " + _iso(mtime)
            lines.append(line)
        if over:
            lines.append("[truncated at %d entries]" % c.max_entries)
        if hidden:
            lines.append("[%d protected entries hidden]" % hidden)
        return "\n".join(lines)

    def t_directory_tree(self, path: str = ".", max_depth: int = 3) -> str:
        g, c = self.g, self.c
        t = g.resolve(path)
        if not os.path.isdir(t.path):
            raise FsError("not a directory")
        depth = max(1, min(_check_int("max_depth", max_depth, 1), 10))
        lines = [t.path + "/"]
        budget = [c.max_entries]
        rel = os.path.relpath(t.path, t.root)
        base = [] if rel == os.curdir else _parts(rel)

        def rec(d: str, prefix: str, level: int, parts: list[str]) -> None:
            try:
                with os.scandir(d) as it:
                    entries = sorted(it, key=lambda e: (not e.is_dir(follow_symlinks=False), e.name.lower()))
            except OSError:
                return
            entries = [e for e in entries if not g.deny.hit(parts + [e.name.lower()], last_only=True)]
            for i, e in enumerate(entries):
                if budget[0] <= 0:
                    return
                budget[0] -= 1
                last = i == len(entries) - 1
                link = e.is_symlink()
                isdir = (not link) and e.is_dir(follow_symlinks=False)
                skip = isdir and e.name.lower() in c.search_exclude
                lines.append("%s%s%s%s%s%s" % (prefix, "`-- " if last else "|-- ", e.name,
                                               "/" if isdir else "", " -> (link)" if link else "",
                                               " (skipped)" if skip else ""))
                if isdir and not skip and level < depth:
                    rec(os.path.join(d, e.name), prefix + ("    " if last else "|   "),
                        level + 1, parts + [e.name.lower()])

        rec(t.path, "", 1, base)
        if budget[0] <= 0:
            lines.append("[truncated at %d entries]" % c.max_entries)
        return "\n".join(lines)

    def t_file_info(self, path: str, include_hash: bool = False) -> str:
        g = self.g
        t = g.resolve(path, follow=False)
        st = os.lstat(t.path)
        kind = ("symlink" if stat.S_ISLNK(st.st_mode) else "directory" if stat.S_ISDIR(st.st_mode)
                else "file" if stat.S_ISREG(st.st_mode) else "other")
        info: dict[str, Any] = {"path": t.path, "type": kind, "size": st.st_size,
                                "modified": _iso(st.st_mtime), "mode": oct(stat.S_IMODE(st.st_mode))}
        if kind == "symlink":
            target = os.path.realpath(t.path)
            info["link_target"] = target if g.root_of(target) else "<outside allowed directories>"
        if include_hash and kind == "file":
            if st.st_size > HASH_MAX_BYTES:
                raise FsError("file too large to hash")
            h = hashlib.sha256()
            with os.fdopen(_open_regular(t.path), "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            info["sha256"] = h.hexdigest()
        return json.dumps(info, indent=2)

    def _read_window(self, real: str, start_line: int, max_lines: int | None, budget: int) -> str:
        with os.fdopen(_open_regular(real), "rb") as f:
            if b"\x00" in f.read(BINARY_SNIFF_BYTES):
                raise FsError("file looks binary; use encoding='base64' to fetch its bytes")
            f.seek(0)
            out: list[bytes] = []
            total = lineno = 0
            more = None
            while True:
                raw = f.readline(budget + 1)
                if not raw:
                    break
                lineno += 1
                if lineno < start_line:
                    continue
                if max_lines is not None and len(out) >= max_lines:
                    more = "line limit"
                    break
                if total + len(raw) > budget:
                    more = "%d-byte limit" % budget
                    break
                out.append(raw)
                total += len(raw)
        text = b"".join(out).decode("utf-8", errors="replace")
        if more:
            text += "\n\n[truncated at %s; continue with start_line=%d]" % (more, start_line + len(out))
        return text

    def t_read_file(self, path: str, start_line: int = 1, max_lines: int | None = None,
                    encoding: str = "utf-8") -> str:
        t = self.g.resolve(path)
        start_line = _check_int("start_line", start_line, 1)
        if max_lines is not None:
            max_lines = _check_int("max_lines", max_lines, 1)
        lim = self.c.max_read_bytes
        if encoding == "base64":
            with os.fdopen(_open_regular(t.path), "rb") as f:
                data = f.read(lim + 1)
            if len(data) > lim:
                raise FsError("file exceeds max_read_bytes (%d) for base64 reads" % lim)
            return base64.b64encode(data).decode("ascii")
        if encoding != "utf-8":
            raise FsError("encoding must be 'utf-8' or 'base64'")
        return self._read_window(t.path, start_line, max_lines, lim)

    def t_read_multiple_files(self, paths: list[str]) -> str:
        if not isinstance(paths, list) or len(paths) > 20:
            raise FsError("paths must be a list of at most 20 entries")
        budget = self.c.max_read_bytes
        parts = []
        for p in paths:
            if budget <= 0:
                parts.append("=== %s ===\n[skipped: output budget exhausted]" % p)
                continue
            try:
                body = self._read_window(self.g.resolve(p).path, 1, None, budget)
                budget -= len(body.encode("utf-8", errors="replace"))
            except FsError as e:
                body = "[error: %s]" % e
            except OSError as e:
                body = "[error: %s]" % (e.strerror or "OS error")
            parts.append("=== %s ===\n%s" % (p, body))
        return "\n\n".join(parts)

    def t_view_image(self, path: str) -> dict[str, Any]:
        """Return the raw image bytes (the host downscales if Pillow is available)."""
        t = self.g.resolve(path)
        lim = self.c.max_image_input_bytes
        with os.fdopen(_open_regular(t.path), "rb") as f:
            if os.fstat(f.fileno()).st_size > lim:
                raise FsError("image file is larger than %s" % fmt_size(lim))
            data = f.read(lim + 1)
        fmt = sniff_image(data[:16])
        if fmt is None:
            raise FsError("not a supported image (png, jpeg, gif, webp)")
        return {"image_b64": base64.b64encode(data).decode("ascii"), "format": fmt}

    def t_search_files(self, pattern: str, path: str = ".", max_results: int = 100) -> str:
        g, c = self.g, self.c
        _check_str("pattern", pattern)
        t = g.resolve(path)
        if not os.path.isdir(t.path):
            raise FsError("not a directory")
        pat = pattern.lower() if any(ch in pattern for ch in "*?[") else "*%s*" % pattern.lower()
        limit = max(1, min(_check_int("max_results", max_results, 1), c.max_search_results))
        walk = Walk(g, t, c.search_exclude, c.search_timeout_seconds)
        hits = []
        for full, name, isdir in walk:
            if fnmatch.fnmatchcase(name.lower(), pat):
                hits.append(full + ("/" if isdir else ""))
                if len(hits) >= limit:
                    walk.reason = "result limit (%d) reached" % limit
                    break
        footer = "\n[stopped: %s]" % walk.reason if walk.reason else ""
        return ("\n".join(hits) if hits else "no matches") + footer

    def t_grep(self, pattern: str, path: str = ".", file_glob: str = "*", regex: bool = False,
               case_sensitive: bool = False, max_matches: int = 100) -> str:
        g, c = self.g, self.c
        if not pattern:
            raise FsError("pattern must not be empty")
        _check_str("pattern", pattern)
        try:
            rx = re.compile(pattern if regex else re.escape(pattern), 0 if case_sensitive else re.I)
        except re.error as e:
            raise FsError("invalid regex: %s" % e) from None
        t = g.resolve(path)
        limit = max(1, min(_check_int("max_matches", max_matches, 1), c.max_search_results))
        glob = _check_str("file_glob", file_glob).lower()
        deadline = time.monotonic() + c.search_timeout_seconds
        out: list[str] = []
        stats = {"files": 0, "binary": 0, "big": 0}

        def scan(full: str) -> str | None:
            try:
                fd = _open_regular(full)
            except (OSError, FsError):
                return None
            with os.fdopen(fd, "rb") as f:
                if os.fstat(f.fileno()).st_size > GREP_MAX_FILE_BYTES:
                    stats["big"] += 1
                    return None
                if b"\x00" in f.read(BINARY_SNIFF_BYTES):
                    stats["binary"] += 1
                    return None
                f.seek(0)
                stats["files"] += 1
                text = io.TextIOWrapper(f, encoding="utf-8", errors="replace")
                try:
                    for n, line in enumerate(text, 1):
                        if (n & 1023) == 0 and time.monotonic() > deadline:
                            return "time limit reached"
                        if rx.search(line):
                            out.append("%s:%d: %s" % (full, n, line.rstrip()[:300]))
                            if len(out) >= limit:
                                return "match limit (%d) reached" % limit
                finally:
                    text.detach()  # the enclosing `with` owns closing the raw file
            return None

        reason: str | None = None
        if os.path.isfile(t.path):
            reason = scan(t.path)
        else:
            walk = Walk(g, t, c.search_exclude, c.search_timeout_seconds)
            for full, name, isdir in walk:
                if isdir or not fnmatch.fnmatchcase(name.lower(), glob):
                    continue
                reason = scan(full)
                if reason:
                    break
            reason = reason or walk.reason
        summary = ("[%d matches; scanned %d files, skipped %d binary / %d large"
                   % (len(out), stats["files"], stats["binary"], stats["big"])
                   + ("; stopped: %s" % reason if reason else "") + "]")
        return "\n".join(out + [summary])

    # -- write tools -------------------------------------------------------------
    def _data(self, content: Any) -> bytes:
        data = _check_str("content", content).encode("utf-8")
        if len(data) > self.c.max_write_bytes:
            raise FsError("content is %d bytes; limit is %d" % (len(data), self.c.max_write_bytes))
        return data

    def t_write_file(self, path: str, content: str, overwrite: bool = False,
                     create_parents: bool = True) -> str:
        data = self._data(content)
        t = self.g.resolve(path, write=True)
        exists = os.path.lexists(t.path)
        if exists:
            if not os.path.isfile(t.path):
                raise FsError("path exists and is not a regular file")
            if not overwrite:
                raise FsError("file already exists; pass overwrite=true to replace it, or use edit_file")
        parent = os.path.dirname(t.path)
        if not os.path.isdir(parent):
            if not create_parents:
                raise FsError("parent directory does not exist")
            os.makedirs(parent, exist_ok=True)
        _atomic_write(t.path, data)
        return "%s %s (%d bytes)" % ("overwrote" if exists else "created", t.path, len(data))

    def t_append_file(self, path: str, content: str, create: bool = True) -> str:
        data = self._data(content)
        t = self.g.resolve(path, write=True)
        if not os.path.lexists(t.path):
            if not create:
                raise FsError("file does not exist")
            os.makedirs(os.path.dirname(t.path), exist_ok=True)
        flags = (os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
        fd = os.open(t.path, flags, 0o644)
        with os.fdopen(fd, "ab") as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                raise FsError("not a regular file")
            f.write(data)
        return "appended %d bytes to %s" % (len(data), t.path)

    def t_edit_file(self, path: str, edits: list[dict[str, Any]], dry_run: bool = False) -> str:
        c = self.c
        if not isinstance(edits, list) or not edits:
            raise FsError("edits must be a non-empty list")
        t = self.g.resolve(path, write=True)
        with os.fdopen(_open_regular(t.path), "rb") as f:
            raw = f.read(c.max_write_bytes + 1)
        if len(raw) > c.max_write_bytes:
            raise FsError("file is larger than max_write_bytes; cannot edit in place")
        if b"\x00" in raw[:BINARY_SNIFF_BYTES]:
            raise FsError("file looks binary")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise FsError("file is not valid UTF-8") from None
        crlf = "\r\n" in text
        if crlf and "\n" in text.replace("\r\n", ""):
            raise FsError("file has mixed line endings; use write_file instead")
        before = text.replace("\r\n", "\n")
        after = before
        for i, ed in enumerate(edits, 1):
            if not isinstance(ed, dict) or not isinstance(ed.get("old_text"), str) \
                    or not isinstance(ed.get("new_text"), str):
                raise FsError("edit %d: needs string old_text and new_text" % i)
            old, new = ed["old_text"].replace("\r\n", "\n"), ed["new_text"].replace("\r\n", "\n")
            replace_all = bool(ed.get("replace_all", False))
            if not old:
                raise FsError("edit %d: old_text must not be empty" % i)
            n = after.count(old)
            if n == 0:
                raise FsError("edit %d: old_text not found" % i)
            if n > 1 and not replace_all:
                raise FsError("edit %d: old_text matches %d places; add context or set replace_all" % (i, n))
            after = after.replace(old, new) if replace_all else after.replace(old, new, 1)
        diff = "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                            "before", "after", n=2))
        lines = diff.splitlines()
        if len(lines) > 200:
            diff = "\n".join(lines[:200]) + "\n[diff truncated: %d more lines]" % (len(lines) - 200)
        if after == before:
            return "no changes (replacement text equals original)"
        if dry_run:
            return "[dry run - nothing written]\n" + diff
        out = (after.replace("\n", "\r\n") if crlf else after).encode("utf-8")
        if len(out) > c.max_write_bytes:
            raise FsError("result would exceed max_write_bytes")
        _atomic_write(t.path, out)
        return diff

    def t_create_directory(self, path: str) -> str:
        t = self.g.resolve(path, write=True)
        if os.path.lexists(t.path) and not os.path.isdir(t.path):
            raise FsError("a non-directory already exists at that path")
        os.makedirs(t.path, exist_ok=True)
        return "directory ready: " + t.path

    def t_move_path(self, source: str, destination: str, overwrite: bool = False) -> str:
        g = self.g
        s = g.resolve(source, follow=False, write=True)
        d = g.resolve(destination, follow=False, write=True)
        g.forbid_root_or_trash(s)
        if not os.path.lexists(s.path):
            raise FsError("source does not exist")
        if _within(d.path, s.path):
            raise FsError("destination is the source or inside it")
        if os.path.lexists(d.path):
            if not overwrite:
                raise FsError("destination exists; pass overwrite=true to replace a file")
            if os.path.isdir(d.path) and not os.path.islink(d.path):
                raise FsError("destination is a directory; refusing to overwrite it")
        os.makedirs(os.path.dirname(d.path), exist_ok=True)
        try:
            os.replace(s.path, d.path)
        except OSError as e:
            if e.errno != errno.EXDEV:
                raise
            shutil.move(s.path, d.path)
        return "moved %s -> %s" % (s.path, d.path)

    def t_copy_path(self, source: str, destination: str, overwrite: bool = False) -> str:
        g, c = self.g, self.c
        s = g.resolve(source)
        d = g.resolve(destination, follow=False, write=True)
        if _within(d.path, s.path):
            raise FsError("destination is the source or inside it")
        if os.path.lexists(d.path):
            if not overwrite:
                raise FsError("destination exists; pass overwrite=true to replace a file")
            if os.path.isdir(d.path) and not os.path.islink(d.path):
                raise FsError("destination is a directory; refusing to overwrite it")
        os.makedirs(os.path.dirname(d.path), exist_ok=True)
        skipped = [0]
        copied = [0]

        def copy_file(src: str, dst: str) -> None:
            if copied[0] > c.max_copy_bytes:
                raise FsError("copy exceeds max_copy_bytes (%d)" % c.max_copy_bytes)
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(dst), prefix=".fsmcp-", suffix=".tmp")
            try:
                with os.fdopen(_open_regular(src), "rb") as fin, os.fdopen(fd, "wb") as fout:
                    shutil.copyfileobj(fin, fout, 1 << 20)
                shutil.copystat(src, tmp)
                os.replace(tmp, dst)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)
                raise
            copied[0] += os.path.getsize(dst)

        def copy_tree(src: str, dst: str) -> None:
            os.makedirs(dst, exist_ok=True)
            for e in sorted(os.scandir(src), key=lambda x: x.name):
                full = os.path.join(src, e.name)
                if e.is_symlink() or g.denied(full, s.root, write=True):
                    skipped[0] += 1
                    continue
                if e.is_dir(follow_symlinks=False):
                    copy_tree(full, os.path.join(dst, e.name))
                elif e.is_file(follow_symlinks=False):
                    copy_file(full, os.path.join(dst, e.name))

        if os.path.isdir(s.path):
            copy_tree(s.path, d.path)
        elif os.path.isfile(s.path):
            copy_file(s.path, d.path)
        else:
            raise FsError("source does not exist or is not a file/directory")
        return ("copied %s -> %s (%s)" % (s.path, d.path, fmt_size(copied[0]))
                + ("; skipped %d protected/symlink entries" % skipped[0] if skipped[0] else ""))

    def t_delete_path(self, path: str, recursive: bool = False) -> str:
        g, c = self.g, self.c
        t = g.resolve(path, follow=False, write=True)
        g.forbid_root_or_trash(t)
        if not os.path.lexists(t.path):
            raise FsError("path does not exist")
        trash = os.path.join(t.root, TRASH_NAME)
        if _within(t.path, trash):
            raise FsError("already in trash; remove it manually outside this server")
        isdir = os.path.isdir(t.path) and not os.path.islink(t.path)
        if isdir and not recursive and os.listdir(t.path):
            raise FsError("directory is not empty; pass recursive=true")
        if c.delete_mode == "trash":
            os.makedirs(trash, mode=0o700, exist_ok=True)
            stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S")
            dest = os.path.join(trash, "%s__%s" % (stamp, os.path.basename(t.path)))
            n = 1
            while os.path.lexists(dest):
                n += 1
                dest = os.path.join(trash, "%s_%d__%s" % (stamp, n, os.path.basename(t.path)))
            try:
                os.rename(t.path, dest)
            except OSError as e:
                if e.errno != errno.EXDEV:
                    raise
                shutil.move(t.path, dest)
            return "moved to trash: " + dest
        if isdir:
            if recursive:
                for full, _name, _isdir in Walk(g, t, [], c.search_timeout_seconds):
                    if g.denied(full, t.root, write=True):
                        raise FsError("directory contains protected entries; refusing permanent delete")
                shutil.rmtree(t.path)
            else:
                os.rmdir(t.path)
        else:
            os.unlink(t.path)
        return "permanently deleted " + t.path

    # -- transfer primitives (used by the host to move data between targets) ----------
    def t_pack_path(self, path: str) -> dict[str, Any]:
        """Tar a file or directory tree. Symlinks, devices and protected entries are skipped."""
        g, c = self.g, self.c
        s = g.resolve(path)
        buf = io.BytesIO()
        skipped = [0]
        total = [0]
        members = [0]
        limit = c.max_transfer_bytes

        def add_file(tf: tarfile.TarFile, full: str, arc: str) -> None:
            fd = _open_regular(full)
            with os.fdopen(fd, "rb") as f:
                st = os.fstat(f.fileno())
                total[0] += st.st_size
                members[0] += 1
                if total[0] > limit or members[0] > MAX_TAR_MEMBERS:
                    raise FsError("transfer exceeds the limit (%s / %d entries)"
                                  % (fmt_size(limit), MAX_TAR_MEMBERS))
                ti = tarfile.TarInfo(arc)
                ti.size = st.st_size
                ti.mode = stat.S_IMODE(st.st_mode) & 0o777
                ti.mtime = int(st.st_mtime)
                tf.addfile(ti, f)

        with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
            if os.path.isfile(s.path):
                kind = "file"
                add_file(tf, s.path, "f")
            elif os.path.isdir(s.path):
                kind = "dir"
                for dirpath, dirnames, filenames in os.walk(s.path, followlinks=False):
                    keep = []
                    for dn in sorted(dirnames):
                        full = os.path.join(dirpath, dn)
                        if os.path.islink(full) or g.denied(full, s.root):
                            skipped[0] += 1
                            continue
                        keep.append(dn)
                        ti = tarfile.TarInfo(os.path.relpath(full, s.path).replace(os.sep, "/"))
                        ti.type = tarfile.DIRTYPE
                        ti.mode = 0o755
                        tf.addfile(ti)
                    dirnames[:] = keep
                    for fn in sorted(filenames):
                        full = os.path.join(dirpath, fn)
                        if os.path.islink(full) or g.denied(full, s.root) or not os.path.isfile(full):
                            skipped[0] += 1
                            continue
                        add_file(tf, full, os.path.relpath(full, s.path).replace(os.sep, "/"))
            else:
                raise FsError("source does not exist or is not a file/directory")
        data = buf.getvalue()
        return {"kind": kind, "tar_b64": base64.b64encode(data).decode("ascii"),
                "bytes": total[0], "skipped": skipped[0], "path": s.path}

    def t_unpack_path(self, path: str, kind: str, tar_b64: str, overwrite: bool = False) -> str:
        """Safely materialise a tar made by pack_path at `path` (the full destination path)."""
        g, c = self.g, self.c
        if kind not in ("file", "dir"):
            raise FsError("kind must be 'file' or 'dir'")
        d = g.resolve(path, follow=False, write=True)
        g.forbid_root_or_trash(d)
        if os.path.lexists(d.path) and not overwrite:
            raise FsError("destination exists; pass overwrite=true")
        if os.path.lexists(d.path) and kind == "dir" and not os.path.isdir(d.path):
            raise FsError("destination exists and is not a directory")
        if os.path.lexists(d.path) and kind == "file" and not os.path.isfile(d.path):
            raise FsError("destination exists and is not a regular file")
        try:
            raw = base64.b64decode(_check_str("tar_b64", tar_b64), validate=True)
        except Exception:  # noqa: BLE001
            raise FsError("corrupt transfer payload") from None
        total = members = skipped = 0
        os.makedirs(os.path.dirname(d.path), exist_ok=True)
        try:
            tf = tarfile.open(fileobj=io.BytesIO(raw), mode="r:")
        except tarfile.TarError:
            raise FsError("corrupt transfer payload") from None
        with tf:
            if kind == "dir":
                os.makedirs(d.path, exist_ok=True)
            for m in tf:
                members += 1
                if members > MAX_TAR_MEMBERS:
                    raise FsError("too many entries in transfer")
                if kind == "file":
                    if not m.isreg() or m.name != "f":
                        raise FsError("unexpected entry in file transfer")
                    target = d.path
                else:
                    name = m.name.replace("\\", "/")
                    if name.startswith("/") or ".." in name.split("/") or "\x00" in name:
                        raise FsError("unsafe path in transfer: %r" % name)
                    target = os.path.join(d.path, *[p for p in name.split("/") if p and p != "."])
                    real_parent = os.path.realpath(os.path.dirname(target))
                    if not _within(real_parent, d.path) and real_parent != os.path.realpath(d.path):
                        raise FsError("unsafe path in transfer: %r" % name)
                    if g.denied(target, d.root, write=True):
                        skipped += 1
                        continue
                if m.isdir():
                    if os.path.lexists(target) and (os.path.islink(target) or not os.path.isdir(target)):
                        raise FsError("a non-directory is in the way at %s" % name)
                    os.makedirs(target, exist_ok=True)
                    continue
                if not m.isreg():
                    skipped += 1
                    continue
                total += m.size
                if total > c.max_transfer_bytes:
                    raise FsError("transfer exceeds the limit (%s)" % fmt_size(c.max_transfer_bytes))
                if os.path.lexists(target) and not os.path.isfile(target):
                    raise FsError("a non-file is in the way at %s" % target)
                if os.path.lexists(target) and not overwrite and kind == "dir":
                    skipped += 1
                    continue
                f = tf.extractfile(m)
                data = f.read() if f else b""
                os.makedirs(os.path.dirname(target), exist_ok=True)
                _atomic_write(target, data, mode=(m.mode & 0o755) | 0o600)
        return "wrote %s (%s)%s" % (d.path, fmt_size(total),
                                    "; skipped %d protected/non-regular entries" % skipped if skipped else "")


# ----------------------------------------------------------------- guest agent entry

def agent_main(stdin, stdout) -> None:
    """Wire protocol used inside sandboxes.

    The host starts `python3 -c <bootstrap>` in the guest, writes this file's source followed by
    ONE json line {"tool":..., "args":{...}, "cfg":{...}} on stdin, and reads ONE reply line
    from stdout: SENTINEL + json. Nothing is written to disk in the guest, and the policy (cfg)
    always comes from the host with the request.
    """
    try:
        req = json.loads(stdin.readline().decode("utf-8"))
        core = FsCore(req["cfg"])
        out: dict[str, Any] = dict(core.call(req["tool"], req.get("args") or {}), ok=True)
    except FsError as e:
        out = {"ok": False, "kind": "fs", "error": str(e)}
    except OSError as e:
        out = {"ok": False, "kind": "os",
               "error": "%s: %s" % (errno.errorcode.get(e.errno or 0, "OSError"), e.strerror or "OS error")}
    except Exception as e:  # noqa: BLE001 - never leak internals
        out = {"ok": False, "kind": "internal", "error": "agent error (%s)" % type(e).__name__}
    stdout.write(SENTINEL + json.dumps(out).encode("utf-8") + b"\n")
    stdout.flush()


# Bootstrap executed with `python3 -c`: reads "<N>\n<N bytes of this file>" then calls agent_main.
BOOTSTRAP = (
    "import sys\n"
    "i=sys.stdin.buffer\n"
    "n=int(i.readline())\n"
    "g={'__name__':'sbx_agent'}\n"
    "exec(compile(i.read(n).decode('utf-8'),'<sbx-agent>','exec'),g)\n"
    "g['agent_main'](i,sys.stdout.buffer)\n"
)


def agent_payload(source: str, request: dict[str, Any]) -> bytes:
    """Build the stdin for the bootstrap: length-prefixed source, then the request line."""
    src = source.encode("utf-8")
    return str(len(src)).encode() + b"\n" + src + json.dumps(request).encode("utf-8") + b"\n"


def parse_agent_output(stdout: bytes) -> dict[str, Any]:
    idx = stdout.rfind(SENTINEL)
    if idx < 0:
        raise FsError("sandbox agent returned no reply")
    try:
        return json.loads(stdout[idx + len(SENTINEL):].decode("utf-8"))
    except ValueError:
        raise FsError("sandbox agent returned a malformed reply") from None


if __name__ == "__main__":  # `python3 fscore.py` reads the request from stdin (handy for debugging)
    agent_main(sys.stdin.buffer, sys.stdout.buffer)
