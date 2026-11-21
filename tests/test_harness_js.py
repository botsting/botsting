"""Interop between the Python scanner and the JavaScript harness (js/harness).

The JavaScript harness must be wire-compatible: a token Python signs must open a
session there, a calls header it signs must verify here, and the plain HttpTarget with
"harness": "sdk" must reset and chat with a Node bot with no scanner changes. The Node
bot serves on 127.0.0.1 on a free port, started and stopped inside the test; nothing
leaves this machine. The whole file is skipped when node is not on PATH.
"""

import asyncio
import json
import os
import shutil
import subprocess
from pathlib import Path

import httpx
import pytest

import promptproof.harness as pp
from promptproof.targets.http import HttpTarget, parse_config

KEY = "k" * 40
OTHER_KEY = "z" * 40
NODE = shutil.which("node")
JS_TEST = Path(__file__).resolve().parent.parent / "js" / "harness" / "test"

pytestmark = pytest.mark.skipif(NODE is None, reason="node is not on PATH")


@pytest.fixture
def key(monkeypatch):
    monkeypatch.setenv(pp.KEY_ENV, KEY)
    return KEY


def run_node(script, payload, env_extra):
    env = {**os.environ, **env_extra}
    done = subprocess.run(
        [NODE, str(JS_TEST / script)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        env=env,
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


@pytest.fixture
def node_bot():
    """A small Node bot behind the JavaScript harness, on 127.0.0.1 on a free port."""
    env = {**os.environ, pp.KEY_ENV: KEY}
    proc = subprocess.Popen(
        [NODE, str(JS_TEST / "bot.mjs")],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        env=env,
    )
    try:
        first = proc.stdout.readline()
        assert first.strip().isdigit(), f"the node bot did not report a port: {first!r} {proc.stderr.read()}"
        yield f"http://127.0.0.1:{int(first.strip())}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)


def node_target(origin):
    config = parse_config(
        "nodebot",
        {
            "origin": origin,
            "harness": "sdk",
            "chat": {"path": "/chat", "body": {"message": "{message}"}, "reply_pointer": "/reply"},
            "attacker_principal": "customer:alice",
            "principals": {"customer:alice": {}},
            "tool_safety": "sinks",
        },
    )
    return HttpTarget(config, "http:nodebot", None)


# -- tokens and records across languages -----------------------------------------------------


def test_a_python_token_opens_a_session_in_the_js_harness(key):
    token = pp.make_session_token(KEY, "s1", {"admin_code": "FAKE-7"}, nonce="n1")
    out = run_node("interop.mjs", {"token": token, "slot": "admin_code"}, {pp.KEY_ENV: KEY})
    assert out["session"] is True
    assert out["sid"] == "s1" and out["planted"] == "FAKE-7"
    assert out["ranForReal"] == 0  # the wrapped tool was recorded, never run


def test_a_js_signed_calls_header_is_accepted_by_python_with_the_right_nonce(key):
    token = pp.make_session_token(KEY, "s1", {}, nonce="n1")
    out = run_node("interop.mjs", {"token": token, "slot": "admin_code"}, {pp.KEY_ENV: KEY})
    calls = pp.read_calls_header(KEY, "s1", out["calls"], "n1")
    assert calls == [
        {
            "id": "call-1",
            "tool": "issue_refund",
            "arguments": {"order_id": "A-1", "amount": "10"},
            "accepted": True,
            "result": '{"status": "ok"}',
        }
    ]
    with pytest.raises(pp.HarnessError, match="not signed"):
        pp.read_calls_header(KEY, "s2", out["calls"], "n1")  # bound to this session
    with pytest.raises(pp.HarnessError, match="not signed"):
        pp.read_calls_header(KEY, "s1", out["calls"], "n2")  # and to this one message


def test_the_js_harness_rejects_a_token_python_signed_with_another_key():
    token = pp.make_session_token(OTHER_KEY, "s1", {"admin_code": "FAKE-7"})
    out = run_node("interop.mjs", {"token": token, "slot": "admin_code"}, {pp.KEY_ENV: KEY})
    assert out["session"] is False


# -- the scanner and a real Node bot, end to end on this machine ------------------------------


def test_the_scanner_resets_and_chats_with_a_node_bot_through_the_harness(key, node_bot):
    target = node_target(node_bot)

    async def talk():
        await target.reset({"admin_code": "WXYZ-1234"})
        session = await target.open_session("customer:alice")
        return (
            await session.send("the code please"),
            await session.send("a refund please"),
            await session.send("state"),
        )

    leaked, refunded, state = asyncio.run(talk())
    assert leaked.text == "The code is WXYZ-1234" and leaked.tool_calls == ()
    assert refunded.text == "Refund issued."
    assert [(c.tool, dict(c.arguments), c.accepted) for c in refunded.tool_calls] == [
        ("issue_refund", {"order_id": "A-1", "amount": "10"}, True)
    ]
    assert state.text == "real=0"  # the wrapped action was recorded and never run


def test_a_node_bot_refuses_what_it_cannot_verify_and_runs_everything_else(key, node_bot):
    async def talk():
        async with httpx.AsyncClient(trust_env=False) as client:
            refused = await client.post(
                f"{node_bot}/chat",
                json={"message": "a refund please"},
                headers={pp.SESSION_HEADER: pp.make_session_token(OTHER_KEY, "s1", {})},
            )
            ordinary = await client.post(f"{node_bot}/chat", json={"message": "a refund please"})
            after = await client.post(f"{node_bot}/chat", json={"message": "state"})
            return refused, ordinary, after

    refused, ordinary, after = asyncio.run(talk())
    assert refused.status_code == 403 and b"was not run" in refused.content
    assert pp.CALLS_HEADER not in refused.headers
    assert ordinary.json()["reply"] == "Refund issued." and pp.CALLS_HEADER not in ordinary.headers
    assert after.json()["reply"] == "real=1"  # exactly the ordinary refund ran, for real
