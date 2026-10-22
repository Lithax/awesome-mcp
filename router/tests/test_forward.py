"""Tests for tool forwarding (servers.json `expose` + the forward() tool).

Run from the router directory:   python -m pytest tests -q
The upstream is demo_upstream.py over stdio; the router is driven in-memory.
"""
import asyncio
import json
import sys
from pathlib import Path

import pytest
from fastmcp import Client
from fastmcp.client.messages import MessageHandler

ROUTER_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROUTER_DIR))

import router  # noqa: E402


def demo_cfg(**extra):
    return {"command": sys.executable, "args": [str(ROUTER_DIR / "demo_upstream.py")], **extra}


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    path = tmp_path / "servers.json"
    monkeypatch.setattr(router, "CONFIG_PATH", path)

    def write(**servers):
        path.write_text(json.dumps({"mcpServers": servers}))

    yield write
    # reset module state and drop everything this test registered
    for name in list(router._forwarded):
        router._remove_registered(name)
    router._forwarded.clear()
    router._dynamic.clear()
    asyncio.run(router.pool.shutdown())


class Recorder(MessageHandler):
    def __init__(self):
        self.tool_list_changed = 0

    async def on_tool_list_changed(self, message):
        self.tool_list_changed += 1


def run(coro):
    return asyncio.run(coro)


async def tool_names(client):
    return {t.name for t in await client.list_tools()}


def test_static_expose_with_prefix(cfg):
    cfg(demo=demo_cfg(expose=["add", "shout"], prefix="d_"))

    async def go():
        await router._sync_forwarded()
        async with Client(router.mcp) as c:
            names = await tool_names(c)
            assert {"d_add", "d_shout"} <= names
            assert "d_delete_everything" not in names and "delete_everything" not in names
            # the router's own tools are still there
            assert {"call_tool", "list_tools", "forward"} <= names
            res = await c.call_tool("d_add", {"a": 2, "b": 3})
            assert res.content[0].text.strip() == "5"
            # real schema is exposed, not a generic wrapper
            tool = next(t for t in await c.list_tools() if t.name == "d_add")
            assert set(tool.input_schema["properties"]) == {"a", "b"}

    run(go())


def test_deny_tools_beats_expose(cfg):
    cfg(demo=demo_cfg(expose=["*"], deny_tools=["delete_*"]))

    async def go():
        await router._sync_forwarded()
        async with Client(router.mcp) as c:
            names = await tool_names(c)
            assert {"add", "shout", "fail"} <= names
            assert "delete_everything" not in names

    run(go())


def test_upstream_errors_pass_through(cfg):
    cfg(demo=demo_cfg(expose=["fail"]))

    async def go():
        await router._sync_forwarded()
        async with Client(router.mcp) as c:
            res = await c.call_tool("fail", {}, raise_on_error=False)
            assert res.is_error
            assert "intentional failure" in res.content[0].text

    run(go())


def test_dynamic_forward_and_unforward_notify_client(cfg):
    cfg(demo=demo_cfg())
    rec = Recorder()

    async def go():
        async with Client(router.mcp, message_handler=rec) as c:
            assert "shout" not in await tool_names(c)
            out = json.loads((await c.call_tool("forward", {"server": "demo", "tools": ["shout"]})).content[0].text)
            assert out["changed"] == ["shout"]
            assert out["forwarded"] == [{"name": "shout", "server": "demo", "tool": "shout"}]
            await asyncio.sleep(0.2)
            assert rec.tool_list_changed >= 1
            assert "shout" in await tool_names(c)
            assert (await c.call_tool("shout", {"text": "hi"})).content[0].text == "HI"

            before = rec.tool_list_changed
            out = json.loads(
                (await c.call_tool("forward", {"server": "demo", "tools": ["shout"], "enable": False})).content[0].text
            )
            assert out["changed"] == ["shout"] and out["forwarded"] == []
            await asyncio.sleep(0.2)
            assert rec.tool_list_changed > before
            assert "shout" not in await tool_names(c)

    run(go())


def test_forward_reports_unmatched_glob_and_static_note(cfg):
    cfg(demo=demo_cfg(expose=["add"]))

    async def go():
        await router._sync_forwarded()
        async with Client(router.mcp) as c:
            out = json.loads((await c.call_tool("forward", {"server": "demo", "tools": ["nope_*"]})).content[0].text)
            assert any("matched no allowed tool" in n for n in out["notes"])
            out = json.loads(
                (await c.call_tool("forward", {"server": "demo", "tools": ["add"], "enable": False})).content[0].text
            )
            assert any("still forwarded by servers.json" in n for n in out["notes"])
            assert "add" in await tool_names(c)

    run(go())


def test_forward_requires_tools_and_known_server(cfg):
    cfg(demo=demo_cfg())

    async def go():
        async with Client(router.mcp) as c:
            r = await c.call_tool("forward", {"server": "demo"}, raise_on_error=False)
            assert r.is_error and "tools=" in r.content[0].text
            r = await c.call_tool("forward", {"server": "ghost", "tools": ["x"]}, raise_on_error=False)
            assert r.is_error and "unknown server" in r.content[0].text

    run(go())


def test_resync_picks_up_config_edit_and_removal(cfg):
    cfg(demo=demo_cfg(expose=["add"]))

    async def go():
        await router._sync_forwarded()
        assert set(router._forwarded) == {"add"}
        cfg(demo=demo_cfg(expose=["shout"]))
        changed = await router._sync_forwarded()
        assert set(changed) == {"add", "shout"} and set(router._forwarded) == {"shout"}
        cfg(demo=demo_cfg(expose=["shout"], disabled=True))
        await router._sync_forwarded()
        assert router._forwarded == {}

    run(go())


def test_name_clash_falls_back_to_server_prefix(cfg):
    assert router._exposed_name("demo", {}, "call_tool", {}) == "demo_call_tool"
    assert router._exposed_name("b", {}, "add", {"add": "a"}) == "b_add"
    assert router._exposed_name("a", {"prefix": "x_"}, "add", {}) == "x_add"


def test_unreachable_server_keeps_previous_tools(cfg):
    cfg(demo=demo_cfg(expose=["add"]))

    async def go():
        await router._sync_forwarded()
        assert "add" in router._forwarded
        asyncio.get_running_loop()
        cfg(demo={"command": "/nonexistent/binary", "expose": ["add"]})
        changed = await router._sync_forwarded()
        assert changed == [] and "add" in router._forwarded

    run(go())
