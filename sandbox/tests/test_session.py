"""Persistent shell sessions: unit tests for capture/validation, end to end over MCP against the fake docker."""
import json

import pytest

from sbx import session as S
from test_e2e import Session, write_config, anyio_backend  # noqa: F401  (fixture re-export)

pytestmark = pytest.mark.anyio


# ----------------------------------------------------------------------------------------- unit
def frame(token, before, after, cwd="/w", body=b"out\n"):
    env = lambda d: b"".join(f"{k}={v}".encode() + b"\0" for k, v in d.items())  # noqa: E731
    t = token.encode()
    return (t + b"B\0" + env(before) + t + b"M\0" + body + t + b"F\0" + cwd.encode() + b"\0" + env(after) + t + b"Z\0")


def test_split_output_strips_framing():
    vis, cap = S.split_output(frame("tok", {"A": "1"}, {"A": "2", "B": "x"}), "tok")
    assert vis == b"out\n" and cap.cwd == "/w" and cap.before == {"A": "1"} and cap.after == {"A": "2", "B": "x"}


def test_truncated_or_missing_trailer_keeps_state():
    raw = frame("tok", {}, {})
    vis, cap = S.split_output(raw[:-3], "tok")          # lost the end marker (truncation / kill)
    assert cap is None and vis == b"out\n"
    vis, cap = S.split_output(b"just output", "tok")    # shell was replaced by `exec`
    assert cap is None and vis == b"just output"


def test_absorb_diffs_and_validates():
    s = S.Session("default")
    cap = S.Captured("/w/sub", {"KEEP": "1", "GONE": "1", "TERM": "dumb"},
                     {"KEEP": "1", "NEW": "v", "PATH": "/opt/bin:/usr/bin", "LD_PRELOAD": "/x.so", "EDITOR": "sh",
                      "TERM": "dumb", "_": "/usr/bin/env", "SHLVL": "2", "FIXED": "no", "__sbx_c": "x"})
    notes = S.absorb(s, cap, {"FIXED": "yes"}, 4096)
    assert s.cwd == "/w/sub"
    assert s.env_set == {"NEW": "v", "PATH": "/opt/bin:/usr/bin"}
    assert s.env_unset == {"GONE"}
    text = " ".join(notes)
    assert "LD_PRELOAD" in text and "EDITOR" in text and "FIXED" in text and "__sbx" not in text


def test_absorb_rejects_relative_path_entries_and_oversize():
    s = S.Session("default")
    S.absorb(s, S.Captured("/w", {}, {"PATH": "/usr/bin::bin", "PYTHONPATH": ".:/x"}), {}, 4096)
    assert s.env_set == {}
    notes = S.absorb(s, S.Captured("/w", {}, {"BIG": "x" * 5000}), {}, 4096)
    assert s.env_set == {} and any("not kept" in n for n in notes)


def test_store_limits_and_reset():
    st = S.SessionStore()
    st.get("a", "1", "one", 2); st.get("a", "1", "two", 2)
    with pytest.raises(Exception, match="too many"):
        st.get("a", "1", "three", 2)
    with pytest.raises(Exception, match="invalid session name"):
        st.get("a", "1", "bad name", 2)
    assert st.reset("a", "one") == 1 and st.reset("a") == 1 and st.peek("a", "1") == []


# ------------------------------------------------------------------------------------------ e2e
async def approve(context, params):
    from mcp.types import ElicitResult
    return ElicitResult(action="accept", content={"approve": True})


async def test_cwd_and_env_persist(tmp_path, fake_docker):
    cfgfile, ws, _ = write_config(tmp_path)
    (ws / "proj").mkdir()
    # like `source venv/bin/activate` (a human approves sourcing; a literal `export PATH=` is blocked outright)
    (ws / "act.sh").write_text('export PATH="/opt/tools:$PATH"\n')
    async with Session(cfgfile, elicit=approve) as c:
        assert not (await c.call("sandbox_create", name="dev"))[0]
        run = lambda cmd, **kw: c.call("run_command", command=cmd, sandbox="dev", **kw)  # noqa: E731

        err, out = await run(". ./act.sh && cd proj && export FOO=bar")
        assert not err and "exit code: 0" in out, out
        err, out = await run('pwd; echo "FOO=$FOO"; echo "$PATH" | cut -d: -f1')
        assert str(ws / "proj") in out and "FOO=bar" in out and "/opt/tools" in out

        err, out = await run("unset FOO")
        err, out = await run('echo "FOO=[${FOO-unset}]"')
        assert "FOO=[unset]" in out

        # explicit cwd overrides; separate sessions are isolated; reset forgets everything
        err, out = await run("pwd", cwd=str(ws))
        assert str(ws) in out and "proj" not in out.split("--- stdout ---")[1]
        err, out = await run("export ONLY_A=1; cd proj", session="a")
        err, out = await run('echo "[${ONLY_A-}]"; pwd', session="b")
        assert "[]" in out and "proj" not in out
        err, out = await c.call("reset_shell_session", sandbox="dev")
        assert not err and "reset" in out
        err, out = await run('echo "[${ONLY_A-}]"; pwd', session="a")
        assert "[]" in out and str(ws) in out


async def test_exit_code_output_and_failure_are_unchanged(tmp_path, fake_docker):
    cfgfile, ws, _ = write_config(tmp_path)
    async with Session(cfgfile) as c:
        await c.call("sandbox_create", name="dev")
        err, out = await c.call("run_command", command="echo hi; echo oops >&2; exit 3", sandbox="dev")
        assert "exit code: 3" in out and "hi" in out and "oops" in out and "sbx" not in out.lower().replace("sandbox", "")
        # a command that redirects stdout away must not break state capture or leak framing
        err, out = await c.call("run_command", command="exec >/dev/null; export Q=1", sandbox="dev")
        err, out = await c.call("run_command", command="echo $Q", sandbox="dev")
        assert "exit code: 0" in out and "--- stdout ---" in out


async def test_cwd_outside_roots_is_dropped(tmp_path, fake_docker):
    cfgfile, ws, _ = write_config(tmp_path)
    async with Session(cfgfile, elicit=approve) as c:
        await c.call("sandbox_create", name="dev")
        # `cd /` is allowed to run (cd is harmless to the classifier) but the session must not stay there
        err, out = await c.call("run_command", command="cd /", sandbox="dev")
        err, out = await c.call("run_command", command="pwd", sandbox="dev")
        assert not err, out
        assert str(ws) in out and "no longer allowed" in out


async def test_session_state_hidden_values_and_disable(tmp_path, fake_docker):
    cfgfile, ws, _ = write_config(tmp_path)
    async with Session(cfgfile) as c:
        await c.call("sandbox_create", name="dev")
        await c.call("run_command", command="export API_THING=supersecretvalue", sandbox="dev")
        err, out = await c.call("shell_info", sandbox="dev")
        info = json.loads(out)
        assert info["sessions"]["open"][0]["env_changed"] == ["API_THING"] and "supersecretvalue" not in out
        await c.call("sandbox_stop", name="dev")
        await c.call("sandbox_start", name="dev")
        err, out = await c.call("shell_info", sandbox="dev")
        assert json.loads(out)["sessions"]["open"] == []

    (tmp_path / "off").mkdir()
    cfgfile, ws, _ = write_config(tmp_path / "off", extra="[shell.session]\nenabled = false")
    async with Session(cfgfile) as c:
        await c.call("sandbox_create", name="dev")
        await c.call("run_command", command="export FOO=1", sandbox="dev")
        err, out = await c.call("run_command", command='echo "[${FOO-}]"', sandbox="dev")
        assert "[]" in out


async def test_large_output_and_timeout_keep_session_sane(tmp_path, fake_docker):
    cfgfile, ws, _ = write_config(tmp_path)
    async with Session(cfgfile) as c:
        await c.call("sandbox_create", name="dev")
        await c.call("run_command", command="export KEEP=1", sandbox="dev")
        # output bigger than max_output_bytes: truncated for the model, framing never leaks, state still captured
        err, out = await c.call("run_command", command="head -c 400000 /dev/zero | tr '\\0' x; export BIG=1", sandbox="dev")
        assert not err and "truncated" in out and out.count("x") <= 200_010 and "F\x00" not in out and "__sbx" not in out
        err, out = await c.call("run_command", command='echo "$KEEP$BIG"', sandbox="dev")
        assert "11" in out
        # a killed command leaves the session exactly as it was
        err, out = await c.call("run_command", command="export LOST=1; sleep 30", timeout_seconds=1, sandbox="dev")
        assert "TIMED OUT" in out
        err, out = await c.call("run_command", command='echo "[$KEEP][${LOST-}]"', sandbox="dev")
        assert "[1][]" in out
