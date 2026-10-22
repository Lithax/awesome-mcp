from mcp.server.fastmcp import FastMCP

mcp = FastMCP("hello-world", host="0.0.0.0", port=11443)

@mcp.tool()
def hello(name: str = "world") -> str:
    """Say hello to someone."""
    return f"Hello, {name}!"

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
