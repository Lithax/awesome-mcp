"""End to end: a real server process over stdio, driven by a real MCP client, against the fake docker."""
import json
import os
import sys

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from conftest import fake_bin

ROOT = os.path.dirname(os.path.dirname(__file__))
pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


def write_config(tmp_path, extra=""):
    ws = tmp_path / "guest-ws"
    ws.mkdir(exist_ok=True)
    host = tmp_path / "hostfiles"
    host.mkdir(exist_ok=True)
    (host / "readme.txt").write_text("from the host")
    cfgfile = tmp_path / "config.toml"
    cfgfile.write_text(f'''
[server]
state_dir = "{tmp_path}/state"
[docker]
binary = "{fake_bin(tmp_path)}"
[sandbox]
workdir = "{ws}"
[fs]
read_only = false
allow_delete = true
guest_roots = ["{ws}"]
[host]
enabled = true
roots = ["{host}"]
[audit]
log_file = "{tmp_path}/audit.jsonl"
[shell.commands]
confirm = ["make deploy"]
{extra}
''')
    return str(cfgfile), ws, host


class Session:
    def __init__(self, cfgfile, *flags, elicit=None):
        self.elicit = elicit
        self.params = StdioServerParameters(command=sys.executable, args=[f"{ROOT}/sandbox_mcp.py", "--config", cfgfile, *flags])

    async def __aenter__(self):
        self._cm = stdio_client(self.params)
        r, w = await self._cm.__aenter__()
        self.s = ClientSession(r, w, elicitation_callback=self.elicit) if self.elicit else ClientSession(r, w)
        await self.s.__aenter__()
        await self.s.initialize()
        return self

    async def __aexit__(self, *a):
        await self.s.__aexit__(*a)
        await self._cm.__aexit__(*a)

    async def call(self, _tool, **args):
        r = await self.s.call_tool(_tool, args)
        text = "\n".join(c.text for c in r.content if c.type == "text")
        return r.isError, text


async def test_full_workflow(tmp_path, fake_docker):
    cfgfile, ws, host = write_config(tmp_path)
    async with Session(cfgfile) as c:
        names = {t.name for t in (await c.s.list_tools()).tools}
        assert {"sandbox_create", "run_command", "read_file", "write_file", "transfer_files", "image_list",
                "sandbox_destroy", "check_command", "delete_path", "view_image"} <= names

        err, out = await c.call("sandbox_create", name="dev", memory_mb=256)
        assert not err, out
        info = json.loads(out)
        assert info["name"] == "dev" and info["network"] == "none" and info["memory_mb"] == 256

        err, out = await c.call("run_command", command="echo hello && pwd", sandbox="dev")
        assert not err and "exit code: 0" in out and "hello" in out and str(ws) in out

        err, out = await c.call("write_file", path="app/main.py", content="print('hi')\n", sandbox="dev")
        assert not err, out
        assert (ws / "app" / "main.py").exists()          # the "guest" is the local dir under the fake docker
        err, out = await c.call("run_command", command="python3 app/main.py", sandbox="dev")
        assert "hi" in out
        err, out = await c.call("edit_file", path="app/main.py", sandbox="dev",
                                edits=[{"old_text": "hi", "new_text": "bye"}])
        assert not err and "+print('bye')" in out
        err, out = await c.call("grep", pattern="bye", sandbox="dev")
        assert "main.py:1" in out
        err, out = await c.call("read_file", path="/etc/passwd", sandbox="dev")
        assert err and "outside" in out

        # host -> sandbox transfer; sandbox -> host is refused (host is read-only by default)
        err, out = await c.call("transfer_files", source_sandbox="host", source_path=str(host / "readme.txt"),
                                destination_sandbox="dev", destination_path="copied.txt")
        assert not err, out
        assert (ws / "copied.txt").read_text() == "from the host"
        err, out = await c.call("transfer_files", source_sandbox="dev", source_path="copied.txt",
                                destination_sandbox="host", destination_path=str(host / "x.txt"))
        assert err and "read-only" in out and not (host / "x.txt").exists()

        # shell policy inside the sandbox
        err, out = await c.call("run_command", command="rm -rf /", sandbox="dev")
        assert err and "BLOCKED" in out
        err, out = await c.call("run_command", command="make deploy", sandbox="dev")
        assert err and "REFUSED" in out and "approval" in out                    # no elicitation in this client
        err, out = await c.call("run_command", command="git push origin main", sandbox="dev")
        assert err and "BLOCKED" in out and "network" in out                     # no network in this sandbox
        err, out = await c.call("check_command", command="rm -rf /", sandbox="dev")
        assert not err and '"would": "refuse"' in out

        # limits are enforced through the tool surface
        err, out = await c.call("sandbox_create", name="big", memory_mb=10**6)
        assert err and "memory_mb" in out
        err, out = await c.call("sandbox_create", name="net", network="outbound")
        assert err and "disabled" in out
        err, out = await c.call("run_command", command="echo x", sandbox="nosuch")
        assert err and "no such sandbox" in out
        err, out = await c.call("run_command", command="echo x")
        assert err and "no sandbox specified" in out and "dev" in out

        err, out = await c.call("sandbox_list")
        assert '"name": "dev"' in out and '"runtime_state": "running"' in out
        err, out = await c.call("delete_path", path="copied.txt", sandbox="dev")
        assert not err and "trash" in out
        err, out = await c.call("sandbox_stop", name="dev")
        err, out = await c.call("run_command", command="echo x", sandbox="dev")
        assert err and "stopped" in out
        assert not (await c.call("sandbox_start", name="dev"))[0]
        assert not (await c.call("sandbox_destroy", name="dev"))[0]
        err, out = await c.call("sandbox_info", name="dev")
        assert err and "no such sandbox" in out

    # the audit chain is intact and contains no file contents or secrets
    from sbx.shellcore import Audit
    ok, msg = Audit.verify(str(tmp_path / "audit.jsonl"))
    assert ok, msg
    log = (tmp_path / "audit.jsonl").read_text()
    assert "sandbox_create" in log and "print('bye')" not in log and "from the host" not in log


async def test_default_sandbox_and_readonly_tool_surface(tmp_path, fake_docker):
    cfgfile, ws, host = write_config(tmp_path, extra="")
    text = open(cfgfile).read().replace("read_only = false", "read_only = true").replace("allow_delete = true", "allow_delete = false")
    open(cfgfile, "w").write(text)
    async with Session(cfgfile, "--default-sandbox", "dev", "--tools", "fs,shell,sandbox") as c:
        names = {t.name for t in (await c.s.list_tools()).tools}
        assert "read_file" in names and "write_file" not in names and "delete_path" not in names \
            and "transfer_files" not in names and "edit_file" not in names
        assert not (await c.call("sandbox_create", name="dev"))[0]
        (ws / "note.txt").write_text("hello")
        err, out = await c.call("read_file", path="note.txt")           # default sandbox applies
        assert not err and out == "hello"
        err, out = await c.call("shell_info")
        assert '"target": "dev"' in out and '"network": false' in out


async def test_tool_groups_can_be_split(tmp_path, fake_docker):
    cfgfile, *_ = write_config(tmp_path)
    async with Session(cfgfile, "--tools", "fs") as c:
        names = {t.name for t in (await c.s.list_tools()).tools}
        assert "read_file" in names and "run_command" not in names and "sandbox_create" not in names


async def test_human_approval_for_network_and_ports(tmp_path, fake_docker):
    from mcp.types import ElicitResult
    cfgfile, ws, host = write_config(tmp_path, extra="")
    text = open(cfgfile).read().replace("[audit]", "[limits]\nallow_outbound = true\nallow_ports = true\n[audit]")
    open(cfgfile, "w").write(text)
    seen = []
    answers = iter([True, False])

    async def cb(context, params):
        seen.append(params.message)
        return ElicitResult(action="accept", content={"approve": next(answers)})

    async with Session(cfgfile, elicit=cb) as c:
        err, out = await c.call("sandbox_create", name="net1", network="outbound", ports=["8080"])
        assert not err, out
        assert "internet access" in seen[0] and "published port" in seen[0]
        err, out = await c.call("sandbox_create", name="net2", network="outbound")
        assert err and "DECLINED" in out
        err, out = await c.call("sandbox_list")
        assert "net1" in out and "net2" not in out
        # no-network sandboxes never prompt
        n = len(seen)
        assert not (await c.call("sandbox_create", name="quiet"))[0] and len(seen) == n
        # and with network the shell classifier now allows network tools (still judged, not blind)
        err, out = await c.call("check_command", command="curl -sS https://example.com -o page.html", sandbox="net1")
        assert not err and "network_disabled" not in out


async def test_host_target_shell_and_fs(tmp_path, fake_docker):
    cfgfile, ws, host = write_config(tmp_path, extra="")
    text = open(cfgfile).read().replace("[audit]", "[shell.access]\nmode = \"readonly\"\nallow_root = true\n[audit]")
    text = text.replace("roots = [\"", "shell = true\nroots = [\"", 1) if False else text
    text = text.replace("[host]\nenabled = true", "[host]\nenabled = true\nshell = true")
    open(cfgfile, "w").write(text)
    async with Session(cfgfile) as c:
        err, out = await c.call("read_file", path=str(host / "readme.txt"), sandbox="host")
        assert not err and out == "from the host"
        err, out = await c.call("write_file", path=str(host / "w.txt"), content="x", sandbox="host")
        assert err and "read-only" in out
        err, out = await c.call("read_file", path="/etc/passwd", sandbox="host")
        assert err and "outside" in out
        err, out = await c.call("run_command", command="ls", cwd=str(host), sandbox="host")
        assert not err and "readme.txt" in out
        err, out = await c.call("run_command", command="touch hacked", cwd=str(host), sandbox="host")
        assert err                                  # readonly mode on the host: strict allow-list refuses it
        assert not (host / "hacked").exists()
