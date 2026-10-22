"""End-to-end smoke test: start the real router over HTTP with an `expose` config and
check the forwarded tools are there right after startup (autostart -> sync path).

    python tests/smoke_http.py
"""
import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from fastmcp import Client

ROUTER_DIR = Path(__file__).resolve().parent.parent
PORT = 18765


async def main() -> None:
    with tempfile.TemporaryDirectory() as d:
        cfg = Path(d) / "servers.json"
        cfg.write_text(json.dumps({"mcpServers": {"demo": {
            "command": sys.executable,
            "args": [str(ROUTER_DIR / "demo_upstream.py")],
            "autostart": True,
            "expose": ["add", "shout"],
            "deny_tools": ["delete_*"],
        }}}))
        env = {**os.environ, "ROUTER_CONFIG": str(cfg), "ROUTER_HOST": "127.0.0.1", "ROUTER_PORT": str(PORT)}
        proc = subprocess.Popen([sys.executable, "router.py"], cwd=ROUTER_DIR, env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        try:
            names: set[str] = set()
            for _ in range(60):
                await asyncio.sleep(0.5)
                try:
                    async with Client(f"http://127.0.0.1:{PORT}/mcp") as c:
                        names = {t.name for t in await c.list_tools()}
                        if {"add", "shout"} <= names:
                            res = await c.call_tool("add", {"a": 20, "b": 22})
                            print("tools:", sorted(names))
                            print("add(20,22) ->", res.content[0].text)
                            assert res.content[0].text.strip() == "42"
                            assert "delete_everything" not in names
                            print("SMOKE OK")
                            return
                except Exception:  # server not up yet
                    continue
            raise SystemExit(f"forwarded tools never appeared; saw {sorted(names)}")
        finally:
            proc.terminate()
            try:
                err = proc.communicate(timeout=15)[1]
            except subprocess.TimeoutExpired:
                proc.kill()
                err = proc.communicate()[1]
            print("--- router stderr ---\n" + (err or "")[-1500:])


asyncio.run(main())
