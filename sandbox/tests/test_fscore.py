import base64
import io
import json
import os
import subprocess
import sys
import tarfile

import pytest

from sbx.guest import fscore
from sbx.guest.fscore import FsCore, FsError


@pytest.fixture
def root(tmp_path):
    r = tmp_path / "ws"
    r.mkdir()
    return r


def core(root, **kw):
    cfg = {"roots": [str(root)], "read_only": False, "allow_delete": True}
    cfg.update(kw)
    return FsCore(cfg)


def call(c, tool, **args):
    return c.call(tool, args)["text"]


# ------------------------------------------------------------------------ guard

def test_relative_paths_resolve_against_first_root(root):
    c = core(root)
    call(c, "write_file", path="a.txt", content="hi")
    assert (root / "a.txt").read_text() == "hi"


def test_outside_root_denied(root, tmp_path):
    (tmp_path / "secret.txt").write_text("x")
    c = core(root)
    with pytest.raises(FsError, match="outside"):
        call(c, "read_file", path=str(tmp_path / "secret.txt"))
    with pytest.raises(FsError, match="outside"):
        call(c, "read_file", path="../secret.txt")


def test_symlink_escape_denied(root, tmp_path):
    (tmp_path / "secret.txt").write_text("x")
    os.symlink(tmp_path / "secret.txt", root / "link")
    os.symlink(tmp_path, root / "dirlink")
    c = core(root)
    with pytest.raises(FsError, match="outside"):
        call(c, "read_file", path="link")
    with pytest.raises(FsError, match="outside"):
        call(c, "read_file", path="dirlink/secret.txt")


def test_deny_rules_hide_secrets(root):
    (root / ".env").write_text("TOKEN=1")
    (root / ".env.example").write_text("TOKEN=")
    (root / "id_rsa").write_text("k")
    c = core(root)
    with pytest.raises(FsError, match="deny"):
        call(c, "read_file", path=".env")
    assert call(c, "read_file", path=".env.example") == "TOKEN="
    listing = call(c, "list_directory")
    assert ".env.example" in listing and "id_rsa" not in listing and "protected entries hidden" in listing
    assert "id_rsa" not in call(c, "search_files", pattern="id_")


def test_write_deny_and_protected(root):
    (root / "keep").mkdir()
    c = core(root, protected=[str(root / "keep")])
    with pytest.raises(FsError, match="read-only name"):
        call(c, "write_file", path=".bashrc", content="x")
    with pytest.raises(FsError, match="deny"):
        call(c, "write_file", path="keep/a.txt", content="x")


def test_read_only_enforced_inside_core(root):
    c = core(root, read_only=True)
    for tool, args in (("write_file", {"path": "a", "content": "x"}), ("create_directory", {"path": "d"}),
                       ("delete_path", {"path": "a"})):
        with pytest.raises(FsError, match="read-only"):
            c.call(tool, args)


def test_delete_disabled(root):
    c = core(root, allow_delete=False)
    (root / "a").write_text("x")
    with pytest.raises(FsError, match="delete is disabled"):
        c.call("delete_path", {"path": "a"})


def test_missing_roots_error(tmp_path):
    with pytest.raises(FsError, match="none of the configured roots"):
        FsCore({"roots": [str(tmp_path / "nope")]})
    with pytest.raises(FsError, match="absolute"):
        FsCore({"roots": ["relative"]})


def test_unknown_cfg_key_and_tool(root):
    with pytest.raises(FsError, match="unknown fs setting"):
        FsCore({"roots": [str(root)], "typo": 1})
    with pytest.raises(FsError, match="unknown filesystem operation"):
        core(root).call("__init__", {})
    with pytest.raises(FsError, match="bad arguments"):
        core(root).call("read_file", {"nope": 1})


# ------------------------------------------------------------------- read tools

def test_read_windows_and_binary(root):
    (root / "t.txt").write_text("".join(f"line{i}\n" for i in range(1, 11)))
    (root / "b.bin").write_bytes(b"\x00\x01\x02")
    c = core(root)
    out = call(c, "read_file", path="t.txt", start_line=3, max_lines=2)
    assert out.startswith("line3\nline4\n") and "continue with start_line=5" in out
    with pytest.raises(FsError, match="binary"):
        call(c, "read_file", path="b.bin")
    assert base64.b64decode(call(c, "read_file", path="b.bin", encoding="base64")) == b"\x00\x01\x02"


def test_read_budget_truncates(root):
    (root / "big.txt").write_text("x" * 100 + "\n" + "y" * 100 + "\n")
    out = call(core(root, max_read_bytes=150), "read_file", path="big.txt")
    assert "truncated" in out


def test_list_tree_search_grep(root):
    (root / "src").mkdir()
    (root / "src" / "a.py").write_text("import os\nprint('Hello')\n")
    (root / "src" / "b.txt").write_text("hello world\n")
    (root / "node_modules").mkdir()
    (root / "node_modules" / "x.py").write_text("hello\n")
    c = core(root)
    assert "[DIR]  src/" in call(c, "list_directory")
    tree = call(c, "directory_tree", max_depth=2)
    assert "a.py" in tree and "(skipped)" in tree
    assert str(root / "src" / "a.py") in call(c, "search_files", pattern="*.py")
    assert "node_modules" not in call(c, "search_files", pattern="*.py")
    g = call(c, "grep", pattern="hello")
    assert "b.txt:1" in g and "a.py:2" in g and "node_modules" not in g
    assert "a.py" not in call(c, "grep", pattern="hello", file_glob="*.txt")
    assert "[1 matches" in call(c, "grep", pattern=r"import \w+", regex=True, case_sensitive=True)
    with pytest.raises(FsError, match="invalid regex"):
        call(c, "grep", pattern="(", regex=True)


def test_file_info_hash_and_symlink(root, tmp_path):
    (root / "f").write_text("abc")
    os.symlink(tmp_path, root / "l")
    c = core(root)
    info = json.loads(call(c, "file_info", path="f", include_hash=True))
    assert info["type"] == "file" and info["sha256"].startswith("ba7816bf")
    assert json.loads(call(c, "file_info", path="l"))["link_target"] == "<outside allowed directories>"


def test_view_image_returns_bytes_and_sniffs(root):
    png = b"\x89PNG\r\n\x1a\n" + b"0" * 20
    (root / "i.png").write_bytes(png)
    (root / "x.png").write_bytes(b"not an image at all")
    c = core(root)
    res = c.call("view_image", {"path": "i.png"})
    assert res["format"] == "png" and base64.b64decode(res["image_b64"]) == png
    with pytest.raises(FsError, match="not a supported image"):
        c.call("view_image", {"path": "x.png"})
    with pytest.raises(FsError, match="larger than"):
        core(root, max_image_input_bytes=10).call("view_image", {"path": "i.png"})


def test_fifo_is_refused_not_hung(root):
    os.mkfifo(root / "pipe")
    with pytest.raises(FsError, match="not a regular file"):
        call(core(root), "read_file", path="pipe")


# ------------------------------------------------------------------ write tools

def test_write_semantics(root):
    c = core(root)
    call(c, "write_file", path="d/e/f.txt", content="one")
    with pytest.raises(FsError, match="already exists"):
        call(c, "write_file", path="d/e/f.txt", content="two")
    call(c, "write_file", path="d/e/f.txt", content="two", overwrite=True)
    with pytest.raises(FsError, match="parent directory"):
        call(c, "write_file", path="zz/q.txt", content="x", create_parents=False)
    with pytest.raises(FsError, match="limit"):
        call(core(root, max_write_bytes=3), "write_file", path="big", content="abcd")
    call(c, "append_file", path="d/e/f.txt", content="+more")
    assert (root / "d/e/f.txt").read_text() == "two+more"
    assert not [p for p in (root / "d/e").iterdir() if p.name.startswith(".fsmcp-")]


def test_edit_file(root):
    (root / "c.py").write_text("a = 1\nb = 2\na = 1\n")
    c = core(root)
    with pytest.raises(FsError, match="matches 2 places"):
        call(c, "edit_file", path="c.py", edits=[{"old_text": "a = 1", "new_text": "a = 9"}])
    out = call(c, "edit_file", path="c.py", edits=[{"old_text": "a = 1", "new_text": "a = 9", "replace_all": True}])
    assert "-a = 1" in out and (root / "c.py").read_text() == "a = 9\nb = 2\na = 9\n"
    assert "dry run" in call(c, "edit_file", path="c.py", dry_run=True,
                             edits=[{"old_text": "b = 2", "new_text": "b = 3"}])
    assert "b = 2" in (root / "c.py").read_text()
    with pytest.raises(FsError, match="not found"):
        call(c, "edit_file", path="c.py", edits=[{"old_text": "zzz", "new_text": ""}])
    (root / "crlf.txt").write_bytes(b"a\r\nb\r\n")
    call(c, "edit_file", path="crlf.txt", edits=[{"old_text": "a", "new_text": "A"}])
    assert (root / "crlf.txt").read_bytes() == b"A\r\nb\r\n"


def test_move_copy_delete(root):
    c = core(root)
    (root / "a.txt").write_text("A")
    (root / "dir").mkdir()
    (root / "dir" / "x.txt").write_text("X")
    (root / "dir" / ".env").write_text("SECRET")
    call(c, "move_path", source="a.txt", destination="b.txt")
    assert not (root / "a.txt").exists() and (root / "b.txt").read_text() == "A"
    with pytest.raises(FsError, match="exists"):
        call(c, "copy_path", source="dir", destination="b.txt")
    out = call(c, "copy_path", source="dir", destination="dir2")
    assert (root / "dir2" / "x.txt").exists() and not (root / "dir2" / ".env").exists() and "skipped 1" in out
    with pytest.raises(FsError, match="inside it"):
        call(c, "move_path", source="dir", destination="dir/sub")
    with pytest.raises(FsError, match="not empty"):
        call(c, "delete_path", path="dir")
    assert "moved to trash" in call(c, "delete_path", path="dir", recursive=True)
    assert (root / ".mcp-trash").is_dir() and not (root / "dir").exists()
    with pytest.raises(FsError, match="root directory itself"):
        call(c, "delete_path", path=str(root))
    with pytest.raises(FsError, match="trash directory itself"):
        call(c, "delete_path", path=".mcp-trash")


def test_permanent_delete_refuses_protected_contents(root):
    (root / "d").mkdir()
    (root / "d" / ".git").mkdir()
    c = core(root, delete_mode="permanent")
    with pytest.raises(FsError, match="protected entries"):
        call(c, "delete_path", path="d", recursive=True)
    (root / "f").write_text("x")
    assert "permanently deleted" in call(c, "delete_path", path="f")


# --------------------------------------------------------------------- transfers

def _make_tar(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, kind, data in members:
            ti = tarfile.TarInfo(name)
            if kind == "dir":
                ti.type = tarfile.DIRTYPE
                tf.addfile(ti)
            elif kind == "link":
                ti.type = tarfile.SYMTYPE
                ti.linkname = data
                tf.addfile(ti)
            else:
                ti.size = len(data)
                ti.mode = 0o4755  # setuid must be stripped
                tf.addfile(ti, io.BytesIO(data))
    return base64.b64encode(buf.getvalue()).decode()


def test_pack_unpack_roundtrip_dir_and_file(root, tmp_path):
    src = core(root)
    (root / "proj" / "sub").mkdir(parents=True)
    (root / "proj" / "a.txt").write_text("A")
    (root / "proj" / "sub" / "b.sh").write_text("#!/bin/sh\n")
    os.chmod(root / "proj" / "sub" / "b.sh", 0o755)
    (root / "proj" / ".env").write_text("SECRET")
    os.symlink("/etc/passwd", root / "proj" / "lnk")
    packed = src.call("pack_path", {"path": "proj"})
    assert packed["kind"] == "dir" and packed["skipped"] == 2
    root2 = tmp_path / "ws2"
    root2.mkdir()
    dst = core(root2)
    dst.call("unpack_path", {"path": "copy", "kind": "dir", "tar_b64": packed["tar_b64"]})
    assert (root2 / "copy" / "a.txt").read_text() == "A"
    assert os.access(root2 / "copy" / "sub" / "b.sh", os.X_OK)
    assert not (root2 / "copy" / ".env").exists() and not (root2 / "copy" / "lnk").exists()
    with pytest.raises(FsError, match="exists"):
        dst.call("unpack_path", {"path": "copy", "kind": "dir", "tar_b64": packed["tar_b64"]})
    f = src.call("pack_path", {"path": "proj/a.txt"})
    dst.call("unpack_path", {"path": "one.txt", "kind": "file", "tar_b64": f["tar_b64"]})
    assert (root2 / "one.txt").read_text() == "A"


@pytest.mark.parametrize("members", [
    [("../evil", "file", b"x")],
    [("/abs/evil", "file", b"x")],
    [("a/../../evil", "file", b"x")],
])
def test_unpack_rejects_traversal(root, members):
    c = core(root)
    with pytest.raises(FsError, match="unsafe path"):
        c.call("unpack_path", {"path": "out", "kind": "dir", "tar_b64": _make_tar(members)})
    assert not (root.parent / "evil").exists()


def test_unpack_symlink_member_not_created_and_setuid_stripped(root):
    c = core(root)
    out = c.call("unpack_path", {"path": "out", "kind": "dir", "tar_b64": _make_tar(
        [("ln", "link", "/etc/passwd"), ("f", "file", b"data")])})["text"]
    assert "skipped 1" in out and not os.path.lexists(root / "out" / "ln")
    mode = os.stat(root / "out" / "f").st_mode
    assert not mode & 0o4000


def test_unpack_through_preexisting_symlink_dir_blocked(root, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "out").mkdir()
    os.symlink(outside, root / "out" / "esc")
    c = core(root)
    with pytest.raises(FsError):
        c.call("unpack_path", {"path": "out", "kind": "dir", "overwrite": True,
                               "tar_b64": _make_tar([("esc/pwn", "file", b"x")])})
    assert not (outside / "pwn").exists()


def test_transfer_size_limit(root):
    (root / "big").write_bytes(b"x" * 2000)
    with pytest.raises(FsError, match="exceeds the limit"):
        core(root, max_transfer_bytes=1000).call("pack_path", {"path": "big"})


def test_unpack_corrupt_payload(root):
    with pytest.raises(FsError, match="corrupt"):
        core(root).call("unpack_path", {"path": "x", "kind": "file", "tar_b64": "!!!"})


# ------------------------------------------------------------ the guest agent

def run_agent(request, python=sys.executable):
    src = open(fscore.__file__, encoding="utf-8").read()
    payload = fscore.agent_payload(src, request)
    p = subprocess.run([python, "-c", fscore.BOOTSTRAP], input=payload, capture_output=True, timeout=30)
    return p, fscore.parse_agent_output(p.stdout)


def test_agent_roundtrip_via_bootstrap(root):
    (root / "hello.txt").write_text("hi there")
    cfg = {"roots": [str(root)], "read_only": True}
    p, res = run_agent({"tool": "read_file", "args": {"path": "hello.txt"}, "cfg": cfg})
    assert res == {"ok": True, "text": "hi there"}


def test_agent_reports_errors_without_traceback(root):
    cfg = {"roots": [str(root)]}
    _, res = run_agent({"tool": "read_file", "args": {"path": "/etc/passwd"}, "cfg": cfg})
    assert res["ok"] is False and res["kind"] == "fs" and "outside" in res["error"]
    _, res = run_agent({"tool": "read_file", "args": {"path": "missing"}, "cfg": cfg})
    assert res["ok"] is False and res["kind"] == "os" and "ENOENT" in res["error"]
    _, res = run_agent({"tool": "read_file", "args": {"path": "x"}, "cfg": {"roots": ["/nonexistent-zzz"]}})
    assert res["ok"] is False and "none of the configured roots" in res["error"]
    p, res = run_agent({"tool": "nope", "args": {}, "cfg": cfg})
    assert res["ok"] is False and "Traceback" not in json.dumps(res)


def test_agent_tolerates_noise_before_reply(root):
    out = b"banner from sitecustomize\n" + fscore.SENTINEL + b'{"ok": true, "text": "x"}\n'
    assert fscore.parse_agent_output(out)["text"] == "x"
    with pytest.raises(FsError, match="no reply"):
        fscore.parse_agent_output(b"garbage")
    with pytest.raises(FsError, match="malformed"):
        fscore.parse_agent_output(fscore.SENTINEL + b"{not json")
