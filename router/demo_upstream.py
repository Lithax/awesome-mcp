"""Tiny upstream MCP server used to try the router and its CLI.

    python examples/demo_upstream.py             # stdio
    python examples/demo_upstream.py http 9000   # streamable HTTP at :9000/mcp
    python examples/demo_upstream.py sse 9001    # legacy SSE at :9001/sse

Then, in another terminal:  python router.py add 127.0.0.1:9000
"""
import sys

from fastmcp import FastMCP

demo = FastMCP("demo", instructions="Tiny demo server for testing the router.")

@demo.tool(annotations={"readOnlyHint": True})
def add(a: int, b: int) -> int:
    """Add two integers.

    Longer explanation that should only show up in describe_tool."""
    return a + b

@demo.tool
def shout(text: str) -> str:
    """Uppercase some text."""
    return text.upper()

@demo.tool
def delete_everything() -> str:
    """Pretend-dangerous tool, used to test deny_tools."""
    return "boom"

@demo.tool
def fail() -> str:
    """Always raises, to test error passthrough."""
    raise RuntimeError("intentional failure")

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "stdio"
    if mode == "stdio":
        demo.run(transport="stdio")
    else:
        demo.run(transport=mode, host="127.0.0.1", port=int(sys.argv[2]))
