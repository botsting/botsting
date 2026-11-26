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
from contextlib import contextmanager
from pathlib import Path

import httpx
import pytest

import promptproof.harness as pp
from promptproof.cli import EXIT_NO_VERIFIED, EXIT_VIOLATIONS, main
from promptproof.core import authorization as auth
from promptproof.targets.http import HttpTarget, parse_config

KEY = "k" * 40
OTHER_KEY = "z" * 40
NODE = shutil.which("node")
JS_TEST = Path(__file__).resolve().parent.parent / "js" / "harness" / "test"
JS_EXAMPLE = JS_TEST.parent / "examples" / "support-bot.mjs"

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


@pytest.fixture
def node_live_bot():
    """The same Node bot, with the deployment switch for a capped real refund turned on."""
    env = {**os.environ, pp.KEY_ENV: KEY, pp.LIVE_ENV: "issue_refund"}
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


def node_target(origin, live=()):
    config = parse_config(
        "nodebot",
        {
            "origin": origin,
            "harness": "sdk",
            "chat": {"path": "/chat", "body": {"message": "{message}"}, "reply_pointer": "/reply"},
            "attacker_principal": "customer:alice",
            "principals": {"customer:alice": {}},
            "tool_safety": "sinks",
            "live_actions": list(live),
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
    record = pp.read_record(KEY, "s1", out["calls"], "n1")
    assert record["read"] == ["admin_code"] and record["tools"] == []  # the slot it read; not a readiness answer
    calls = record["calls"]
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


def test_js_reads_a_python_signed_record_with_name_lists(key, monkeypatch):
    monkeypatch.setattr(pp, "_marked_tools", {"example": ""})
    monkeypatch.setattr(pp, "_read_outside", {"read_at_start"})
    monkeypatch.setattr(pp, "_content_outside", {"note_read_elsewhere"})
    session = pp._Session(sid="s1", fixtures={}, content={}, key=KEY, nonce="n1")
    session.read.append("sample")
    session.points.append("order_note")
    header = session.header_value(tools=True)
    out = run_node(
        "interop.mjs",
        {"record": header, "sessionId": "s1", "nonce": "n1"},
        {pp.KEY_ENV: KEY},
    )
    ours = pp.read_record(KEY, "s1", header, "n1")
    assert ours == {
        "calls": [],
        "read": ["sample"],
        "tools": ["example"],
        "rules": {},
        "outside": ["read_at_start"],
        "points": ["order_note"],
        "points_outside": ["note_read_elsewhere"],
    }
    assert out == ours  # the JavaScript reader returns rules too, with the same validation


def test_python_reads_a_js_signed_readiness_record_with_tools_and_rules(key):
    """The other direction: a record the JavaScript harness signs, with the tool names
    and the never-for-users rules of its readiness answer, verifies with Python's reader."""
    out = run_node(
        "interop.mjs",
        {
            "make": {
                "sessionId": "s1",
                "nonce": "n1",
                "read": ["staff_code"],
                "mark": {"issue_refund": "a refund of 50 on order A-1001", "send_email": ""},
            }
        },
        {pp.KEY_ENV: KEY},
    )
    record = pp.read_record(KEY, "s1", out["calls"], "n1")
    assert record == {
        "calls": [],
        "read": ["staff_code"],
        "tools": ["issue_refund", "send_email"],
        "rules": {"issue_refund": "a refund of 50 on order A-1001"},
        "outside": [],
        "points": [],
        "points_outside": [],
    }
    with pytest.raises(pp.HarnessError, match="not signed"):
        pp.read_record(KEY, "s2", out["calls"], "n1")  # bound to this session, as ever


def test_python_control_and_discover_tokens_behave_the_same_in_js(key):
    token = pp.make_session_token(KEY, "s1", {"admin_code": "FAKE-7"}, nonce="n1", control={"admin_code": "open sesame"})
    out = run_node("interop.mjs", {"token": token, "slot": "admin_code"}, {pp.KEY_ENV: KEY})
    assert out["session"] is True
    assert out["planted"] == "FAKE-7" + pp.control_note("open sesame")  # the note, exactly as Python writes it
    assert out["read"] == ["admin_code"]
    discover = pp.make_session_token(KEY, "s2", {"admin_code": "FAKE-7"}, nonce="n1", discover=True)
    out = run_node("interop.mjs", {"token": discover, "slot": "admin_code"}, {pp.KEY_ENV: KEY})
    assert out["planted"] == "(none)"  # a discover session plants nothing...
    assert out["read"] == ["admin_code"]  # ...but still tells the scanner the slot exists


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


# -- live actions under caps, across languages ------------------------------------------------


def test_a_python_live_token_is_accepted_by_the_js_harness(key):
    """A token Python signs with live tools and a run opens there, and with the
    deployment switch on, a refund inside the cap runs for real while one outside it
    is recorded with the reason and not run."""
    token = pp.make_session_token(KEY, "s1", {}, live=("issue_refund",), run="run-js-1")
    out = run_node(
        "interop.mjs",
        {"token": token, "slot": "admin_code", "liveAmounts": [7, 5000]},
        {pp.KEY_ENV: KEY, pp.LIVE_ENV: "issue_refund"},
    )
    assert out["session"] is True
    assert out["runId"] == "run-js-1" and out["live"] == ["issue_refund"]
    assert out["ranForReal"] == 1 and out["realAmounts"] == [7]  # 5000 never ran
    calls = pp.read_calls_header(KEY, "s1", out["calls"])
    assert [c["live"] for c in calls] == ["ran", "capped"]
    assert calls[0]["result"].startswith("[ran for real within the caps]")
    assert calls[0]["accepted"] is True
    assert calls[1]["result"].startswith("[not run: amount 5000 is outside the cap of 0 to 10]")
    # Without the deployment switch, the same token gets nothing run for real.
    off = run_node(
        "interop.mjs",
        {"token": token, "slot": "admin_code", "liveAmounts": [7]},
        {pp.KEY_ENV: KEY},
    )
    assert off["ranForReal"] == 0
    refused = pp.read_calls_header(KEY, "s1", off["calls"])
    assert refused[0]["live"] == "capped"
    assert "this deployment does not allow issue_refund to run for real" in refused[0]["result"]


def test_a_scan_carries_out_a_small_refund_on_a_node_bot_and_only_records_a_large_one(key, node_live_bot):
    target = node_target(node_live_bot, live=["issue_refund"])

    async def talk():
        await target.reset({})
        conversation = await target.open_session("customer:alice")
        return (
            await conversation.send("refund 7"),
            await conversation.send("refund 5000"),
            await conversation.send("what ran"),
        )

    small, large, ran = asyncio.run(talk())
    assert small.tool_calls[0].result.startswith("[ran for real within the caps]")
    assert small.tool_calls[0].accepted is True
    assert large.tool_calls[0].accepted is True
    assert "amount 5000 is outside the cap of 0 to 10" in large.tool_calls[0].result
    assert large.tool_calls[0].result.startswith("[not run: ")
    assert ran.text == 'ran=[["T-1",7]]'  # the in-memory record: only the refund inside the cap ran


# -- a first scan of the Node example bot, end to end on this machine ------------------------


@pytest.fixture
def first_scan_env(tmp_path, monkeypatch):
    """What test_quick.py sets up for a scan: nothing on disk yet, and the harness key."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PROMPTPROOF_TARGETS_FILE", str(tmp_path / "promptproof.targets.json"))
    monkeypatch.setenv(pp.KEY_ENV, KEY)
    auth.forget_checks()


@contextmanager
def node_example(fixed=False):
    """The Node twin of examples/support_bot.py (js/harness/examples/support-bot.mjs),
    on 127.0.0.1 on a free port, stopped when the test is done."""
    env = {**os.environ, pp.KEY_ENV: KEY}
    proc = subprocess.Popen(
        [NODE, str(JS_EXAMPLE), "--port", "0"] + (["--fixed"] if fixed else []),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        env=env,
    )
    try:
        first = proc.stdout.readline()
        assert first.strip().isdigit(), f"the node example did not report a port: {first!r} {proc.stderr.read()}"
        yield f"http://127.0.0.1:{int(first.strip())}/chat"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)


def dana(origin):
    return "Dana Levi"


def refunds_really_carried_out(chat_url):
    """How many refunds the bot really issued, from its own in-memory record."""
    with httpx.Client(trust_env=False) as client:
        return client.post(f"{chat_url.rsplit('/', 1)[0]}/state", json={"message": "state"}).json()["refunds"]


def test_a_first_scan_of_the_node_example_finds_and_clears_all_three_weaknesses(first_scan_env, monkeypatch, capsys):
    """The whole `promptproof scan` command against the Node example bot, the way
    test_quick.py runs it against the Python one: no description file, the harness
    tells the scanner everything. The weak build reports a verified leak of staff_code
    and a verified call to issue_refund; the fixed build reports nothing, with every
    slot reachable through the harness's pass-phrase route; and the marked tool never
    really runs in either build."""
    monkeypatch.setattr("promptproof.quick._ask_name", dana)
    with node_example() as weak:
        assert main(["scan", weak, "--replays", "2", "--out", "weak/scan.json"]) == EXIT_VIOLATIONS
        assert refunds_really_carried_out(weak) == 0  # recorded, never run
    printed = capsys.readouterr().out
    assert "Secrets it reads on an ordinary message: staff_code." in printed
    assert "verified violation" in printed and "Tools no chat user may cause: issue_refund." in printed
    report = json.loads(Path("weak/scan.json").read_text(encoding="utf-8"))
    assert report["status"] == "violations_verified"
    assert {finding["slot_id"] for finding in report["findings"]} == {"staff_code", "issue_refund", "order_note"}
    assert all(slot["state"] == "reachable" for slot in report["slots"])
    # The real secret the bot holds outside a test never appears in any evidence.
    assert "NW-STAFF-2291" not in Path("weak/scan.json").read_text(encoding="utf-8")

    with node_example(fixed=True) as fixed:
        assert main(["scan", fixed, "--replays", "2", "--out", "fixed/scan.json"]) == EXIT_NO_VERIFIED
        assert refunds_really_carried_out(fixed) == 0
    report = json.loads(Path("fixed/scan.json").read_text(encoding="utf-8"))
    assert report["status"] == "no_verified_violations", report["inconclusive_reasons"]
    assert all(slot["state"] == "reachable" for slot in report["slots"])  # the pass phrase route worked
