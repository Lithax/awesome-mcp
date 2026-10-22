# mcp-router

One MCP server that fronts many. Add it as your single custom connector; it reaches every
server listed in `servers.json`.

## Run
    python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
    python router.py                      # http://127.0.0.1:8000/mcp
    ROUTER_TRANSPORT=stdio python router.py   # for local stdio clients

Env vars: `ROUTER_CONFIG`, `ROUTER_HOST`, `ROUTER_PORT`, `ROUTER_TIMEOUT` (60s), `ROUTER_MAX_CHARS` (20000).

## Add servers from the command line
Point the CLI at something that's already running; it works out the rest.

    python router.py add 127.0.0.1:9000                  # finds /mcp or /sse, detects http vs sse
    python router.py add https://host/some/path -y       # -y: never prompt, take defaults
    python router.py add --stdio -- npx -y some-pkg /dir # launches it to scan it
    python router.py list
    python router.py remove NAME

What `add` does: probes the endpoint, detects streamable HTTP vs legacy SSE, detects whether
auth is needed, connects, lists the tools, flags destructive-looking ones (using the server's
own `readOnlyHint`/`destructiveHint` annotations plus name heuristics like `delete_*`, `exec`,
`write_*`) and offers to put them in `deny_tools`. It asks only for what it can't infer: a
credential if the server returns 401, a name, a description. Then it shows the entry and asks
before saving (atomic write, previous file kept as `servers.json.bak`).

Useful flags: `--name`, `--description`, `--header 'Name: value'`, `--env KEY=VALUE` (stdio),
`--allow GLOB` / `--deny GLOB`, `--allow-all`, `--disabled`, `--force`, `--dry-run`, `--config PATH`.

**Secrets:** tokens are stored as `${ENV_VAR}` references, never plaintext (unless
`--inline-secret`), and the CLI tells you what to `export` where the router runs. Prefer the
interactive hidden prompt or an already-exported variable
(`--header 'Authorization: Bearer ${MY_TOKEN}'`) over typing a token in a command line, since
that lands in your shell history. Servers that only support OAuth (no static token) aren't
supported yet.

To try it: `python examples/demo_upstream.py http 9000` in one terminal, then
`python router.py add 127.0.0.1:9000` in another.

## Tools
| tool | purpose |
|---|---|
| `list_servers` | configured upstreams |
| `list_tools(server)` | names + one-line descriptions |
| `describe_tool(server, tool)` | full JSON schema |
| `call_tool(server, tool, arguments)` | run it |
| `restart_server(server)` | drop cached connection / kill stdio process |

## Notes
- Entries can set `"transport": "sse"` for legacy SSE servers (the CLI does this for you).
- `list_tools` follows pagination, so servers with many tools aren't truncated.
- `servers.json` is re-read on every call: add, edit or disable servers live. Changed entries reconnect automatically.
- `allow_tools` / `deny_tools` (globs) restrict what each upstream exposes. Deny wins.
- `${VAR}` in `env`, `headers`, `args`, `url` expands from the router's environment.
- **Auth:** this router has none. Bind to 127.0.0.1 and put your tunnel's access control in front of it.
  Anyone who can reach it can use every upstream server you configure.
- Upstream output is untrusted data; the router's instructions tell the model to treat it that way.
