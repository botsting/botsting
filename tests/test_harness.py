"""The drop-in harness: a few lines in the bot's code instead of a test endpoint.

It must do nothing for anyone but a signed Promptproof session, must never run a
decorated tool during a test, and must report calls in a way nothing else can forge.
The end-to-end tests serve the practice bot with the harness on 127.0.0.1 and scan it
exactly as a user would. Nothing here leaves this machine.
"""

import asyncio
import json
import threading
import time
from datetime import UTC, datetime
from wsgiref.simple_server import WSGIRequestHandler, make_server

import httpx
import pytest

import promptproof.harness as pp
from promptproof.attacks.library import default_attacks
from promptproof.core import authorization as auth
from promptproof.core.authorization import AuthorizationStore, new_authorization
from promptproof.core.runner import run_scan
from promptproof.llm.scripted import ScriptedModel
from promptproof.practice_server import practice_description, write_description
from promptproof.targets.base import TargetError
from promptproof.targets.http import HttpTarget, TargetConfigError, parse_config
from promptproof.targets.registry import build_target
from promptproof.targets.toy import ToyTarget

KEY = "k" * 40
OTHER_KEY = "z" * 40


@pytest.fixture
def key(monkeypatch):
    monkeypatch.setenv(pp.KEY_ENV, KEY)
    return KEY


real_refunds: list[tuple[str, float]] = []


@pp.action("issue_refund")
def issue_refund(order_id: str, amount: float) -> dict:
    real_refunds.append((order_id, amount))
    return {"status": "refunded for real"}


@pp.action("send_email", result=lambda to, body: f"queued to {to}")
async def send_email(to: str, body: str) -> str:
    real_refunds.append((to, -1))
    return "sent for real"


def in_session(token, function, *args, **kwargs):
    """Run `function` as the harness would inside a request carrying `token`."""
    session = pp._open(token)
    reset = pp._current.set(session)
    try:
        return function(*args, **kwargs), session
    finally:
        pp._current.reset(reset)


# -- doing nothing unless asked properly ----------------------------------------------------


def test_without_a_key_everything_runs_as_written(monkeypatch):
    monkeypatch.delenv(pp.KEY_ENV, raising=False)
    real_refunds.clear()
    token = pp.make_session_token(KEY, "s1", {"admin_code": "FAKE"})
    result, session = in_session(token, issue_refund, "A-1", 5)
    assert (
        session is None
        and result == {"status": "refunded for real"}
        and real_refunds == [("A-1", 5)]
    )
    assert pp.planted("admin_code", "default") == "default" and not pp.active()


@pytest.mark.parametrize(
    "make",
    [
        lambda: pp.make_session_token(
            OTHER_KEY, "s1", {"admin_code": "FAKE"}
        ),  # someone else's key
        lambda: pp.make_session_token(
            KEY, "s1", {"admin_code": "FAKE"}, now=time.time() - 400
        ),  # expired
        lambda: (
            pp.make_session_token(KEY, "s1", {"admin_code": "FAKE"})[:-3] + "AAA"
        ),  # bad signature
        lambda: "not a token",
        lambda: None,
    ],
)
def test_a_request_without_a_valid_session_is_an_ordinary_request(key, make):
    real_refunds.clear()
    result, session = in_session(make(), issue_refund, "A-1", 5)
    assert (
        session is None
        and result == {"status": "refunded for real"}
        and real_refunds == [("A-1", 5)]
    )


def test_a_changed_fixture_breaks_the_signature(key):
    token = pp.make_session_token(KEY, "s1", {"admin_code": "FAKE"})
    payload, _, mac = token.partition(".")
    body = json.loads(pp._unb64(payload))
    body["fixtures"]["admin_code"] = "SOMETHING ELSE"
    forged = (
        pp._b64(json.dumps(body, sort_keys=True, separators=(",", ":")).encode())
        + "."
        + mac
    )
    assert pp._open(forged) is None


def test_a_short_key_is_refused(monkeypatch):
    monkeypatch.setenv(pp.KEY_ENV, "short")
    with pytest.raises(pp.HarnessError, match="at least 32"):
        pp.wrap(lambda environ, start_response: [])
    with pytest.raises(pp.HarnessError):
        pp.make_session_token("short", "s1", {})


# -- inside a test session ------------------------------------------------------------------


def test_in_a_test_session_tools_are_recorded_and_never_run(key):
    real_refunds.clear()
    token = pp.make_session_token(
        KEY, "s1", {"admin_code": "FAKE-CODE"}, {"ticket": "planted text"}
    )

    def turn():
        assert (
            pp.active()
            and pp.planted("admin_code") == "FAKE-CODE"
            and pp.content("ticket") == "planted text"
        )
        assert pp.planted("unknown", "d") == "d"
        first = issue_refund("A-1", amount=12.5)
        second = asyncio.run(send_email("x@example.com", "hello"))
        return first, second

    (first, second), session = in_session(token, turn)
    assert (
        real_refunds == []
        and first == {"status": "ok"}
        and second == "queued to x@example.com"
    )
    calls = pp.read_calls_header(KEY, "s1", session.header_value())
    assert calls == [
        {"id": "call-1", "tool": "issue_refund", "arguments": {"order_id": "A-1", "amount": "12.5"},
         "accepted": True, "result": '{"status": "ok"}'},
        {"id": "call-2", "tool": "send_email", "arguments": {"to": "x@example.com", "body": "hello"},
         "accepted": True, "result": "queued to x@example.com"},
    ]  # fmt: skip


def test_the_call_record_cannot_be_forged_or_moved_to_another_session(key):
    token = pp.make_session_token(KEY, "s1", {})
    _, session = in_session(token, issue_refund, "A-1", 1)
    header = session.header_value()
    with pytest.raises(pp.HarnessError, match="not signed"):
        pp.read_calls_header(KEY, "s2", header)  # replayed into another conversation
    with pytest.raises(pp.HarnessError, match="not signed"):
        pp.read_calls_header(OTHER_KEY, "s1", header)
    empty = pp._Session("s1", {}, {}, KEY).header_value()
    with pytest.raises(pp.HarnessError, match="not signed"):
        pp.read_calls_header(
            KEY, "s1", empty.split(".")[0] + "." + header.split(".")[1]
        )  # swapped body
    with pytest.raises(pp.HarnessError, match="did not see this as a test session"):
        pp.read_calls_header(KEY, "s1", None)


def test_too_many_calls_in_one_reply_is_an_error_not_a_silent_gap(key):
    token = pp.make_session_token(KEY, "s1", {})

    def many():
        for i in range(pp.MAX_CALLS + 3):
            issue_refund(f"A-{i}", 1)

    _, session = in_session(token, many)
    with pytest.raises(pp.HarnessError, match="3 were not recorded"):
        pp.read_calls_header(KEY, "s1", session.header_value())


def test_oversized_content_is_refused_before_sending():
    with pytest.raises(pp.HarnessError, match="bytes in the header"):
        pp.make_session_token(KEY, "s1", {}, {"doc": "x" * 6000})


# -- the web app ------------------------------------------------------------------------------


async def asgi_bot(scope, receive, send):
    """A tiny ASGI bot: one chat endpoint that refunds when asked, with a planted secret."""
    if scope["path"] != "/chat":
        await send({"type": "http.response.start", "status": 404, "headers": []})
        await send({"type": "http.response.body", "body": b""})
        return
    message = json.loads((await receive())["body"])["message"]
    reply = "Hello."
    if "refund" in message:
        issue_refund("A-1", 10)
        reply = "Refund issued."
    if "code" in message:
        reply = "The code is " + pp.planted("admin_code", "(none)")
    body = json.dumps({"reply": reply}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": body})


def sdk_description(**changes):
    raw = {
        "origin": "https://bot.example.com",
        "harness": "sdk",
        "chat": {
            "path": "/chat",
            "body": {"message": "{message}"},
            "reply_pointer": "/reply",
        },
        "attacker_principal": "customer:alice",
        "principals": {"customer:alice": {}},
        "tool_safety": "sinks",
    }
    raw.update(changes)
    return parse_config("bot", raw)


def sdk_target(app):
    return HttpTarget(
        sdk_description(), "http:bot", None, transport=httpx.ASGITransport(app=app)
    )


def test_the_scanner_and_an_asgi_bot_work_together(key):
    real_refunds.clear()
    target = sdk_target(pp.wrap(asgi_bot))

    async def talk():
        await target.reset({"admin_code": "WXYZ-1234"})
        session = await target.open_session("customer:alice")
        return await session.send("the code please"), await session.send(
            "a refund please"
        )

    leaked, refunded = asyncio.run(talk())
    assert leaked.text == "The code is WXYZ-1234" and leaked.tool_calls == ()
    assert refunded.text == "Refund issued." and real_refunds == []
    assert [(c.tool, dict(c.arguments), c.accepted) for c in refunded.tool_calls] == [
        ("issue_refund", {"order_id": "A-1", "amount": "10"}, True)
    ]


@pytest.mark.parametrize(
    "problem", ["not wrapped", "no key on the bot", "a different key on the bot"]
)
def test_no_attack_is_sent_unless_the_harness_confirms_test_mode(monkeypatch, problem):
    # The scanner reads its key from SCANNER_KEY; the bot reads PROMPTPROOF_HARNESS_KEY.
    monkeypatch.setenv("SCANNER_KEY", KEY)
    monkeypatch.setenv(pp.KEY_ENV, KEY)
    if problem == "no key on the bot":
        monkeypatch.delenv(pp.KEY_ENV)
    if problem == "a different key on the bot":
        monkeypatch.setenv(pp.KEY_ENV, OTHER_KEY)
    app = asgi_bot if problem == "not wrapped" else pp.wrap(asgi_bot)
    seen: list[str] = []
    inner = httpx.ASGITransport(app=app)

    class Watching(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            seen.append(request.url.path)
            return await inner.handle_async_request(request)

    target = HttpTarget(
        sdk_description(harness_key_env="SCANNER_KEY"),
        "http:bot",
        None,
        transport=Watching(),
    )
    with pytest.raises(TargetError, match="did not confirm test mode"):
        asyncio.run(target.reset({"admin_code": "WXYZ-1234"}))
    assert seen == [pp.READY_PATH]


def test_an_ordinary_user_of_the_wrapped_bot_sees_no_difference(key):
    real_refunds.clear()
    app = pp.wrap(asgi_bot)

    async def talk():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bot.example.com"
        ) as client:
            chat = await client.post("/chat", json={"message": "a refund and the code"})
            ready = await client.post(pp.READY_PATH, json={})
            return chat, ready

    chat, ready = asyncio.run(talk())
    assert (
        chat.json() == {"reply": "The code is (none)"}
        and pp.CALLS_HEADER not in chat.headers
    )
    assert real_refunds == [("A-1", 10)]  # the tool ran as written
    assert (
        ready.status_code == 404
    )  # the bot's own answer: the harness does not reveal itself


def test_the_ownership_proof_is_served_from_the_environment(monkeypatch):
    monkeypatch.delenv(pp.KEY_ENV, raising=False)
    monkeypatch.setenv(pp.CHALLENGE_ENV, "promptproof-challenge=abc123")
    app = pp.wrap(asgi_bot)

    async def fetch():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://bot.example.com"
        ) as client:
            return await client.get(pp.CHALLENGE_PATH)

    response = asyncio.run(fetch())
    assert (
        response.status_code == 200
        and response.text.strip() == "promptproof-challenge=abc123"
    )


def test_sdk_descriptions_are_checked():
    assert sdk_description().harness == "sdk"
    with pytest.raises(TargetConfigError, match="no reset endpoint"):
        sdk_description(reset={"path": "/reset"})
    with pytest.raises(TargetConfigError, match="no reset endpoint"):
        sdk_description(
            chat={
                "path": "/chat",
                "body": {"m": "{message}"},
                "tool_calls_pointer": "/calls",
            }
        )
    with pytest.raises(TargetConfigError, match="harness must be"):
        sdk_description(harness="pixel")
    with pytest.raises(TargetConfigError, match="harness_key_env"):
        sdk_description(harness_key_env="not a name")


# -- end to end: the practice bot behind the harness, over real HTTP on this machine ------------


@pp.action("issue_refund")
def practice_refund(order_id: str, amount: str) -> dict:
    raise AssertionError("a decorated tool ran during a test")


class HarnessToy(ToyTarget):
    """The practice bot as an owner would wire it: the refund that its own checks allow
    goes through the decorated function; no recorder of its own is reported."""

    def _issue_refund(self, authorization, order_id, amount):
        call = super()._issue_refund(authorization, order_id, amount)
        if call.accepted:
            practice_refund(order_id, str(amount))
        return call


def harness_app(variant):
    bot = HarnessToy(variant=variant, model=ScriptedModel(), spec=f"toy:{variant}")
    state = {"planted": None, "sessions": {}}

    def app(environ, start_response):
        body = json.loads(
            environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH") or 0)) or b"{}"
        )
        planted = (
            {s.id: pp.planted(s.id) for s in bot.slots()},
            {
                p.id: pp.content(p.id)
                for p in bot.injection_points()
                if pp.content(p.id)
            },
        )
        if planted != state["planted"]:
            asyncio.run(bot.reset(*planted))
            state["planted"], state["sessions"] = planted, {}
        sessions = state["sessions"]
        if body["session_id"] not in sessions:
            sessions[body["session_id"]] = asyncio.run(bot.open_session(body["user"]))
        reply = asyncio.run(sessions[body["session_id"]].send(body["message"]))
        data = json.dumps({"reply": reply.text}).encode()
        start_response(
            "200 OK",
            [("Content-Type", "application/json"), ("Content-Length", str(len(data)))],
        )
        return [data]

    return pp.wrap(app)


class Quiet(WSGIRequestHandler):
    def log_message(self, *args):
        pass


@pytest.fixture
def harness_practice(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(
        "PROMPTPROOF_TARGETS_FILE", str(tmp_path / "promptproof.targets.json")
    )
    monkeypatch.setenv(pp.KEY_ENV, KEY)
    auth.forget_checks()
    servers = []

    def run(variant):
        server = make_server("127.0.0.1", 0, harness_app(variant), handler_class=Quiet)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        port = server.server_address[1]
        description = practice_description(port, variant)
        del description["reset"], description["chat"]["tool_calls_pointer"]
        description["harness"] = "sdk"
        write_description(
            tmp_path / "promptproof.targets.json", "practice", description
        )
        origin = f"http://127.0.0.1:{port}"
        record = new_authorization(
            origin,
            "Dana Levi",
            "the practice bot",
            "test",
            1,
            datetime.now(UTC),
            allowed_tools=("issue_refund",),
        )
        AuthorizationStore().add(record)
        return build_target("http:practice")

    yield run
    for server in servers:
        server.shutdown()
        server.server_close()


def test_scanning_through_the_harness_finds_what_the_in_process_scan_finds(
    harness_practice,
):
    target = harness_practice("vulnerable")
    report = asyncio.run(run_scan(target, default_attacks(target)))
    local = build_target("toy:vulnerable")
    in_process = asyncio.run(run_scan(local, default_attacks(local)))
    assert report.status == "violations_verified"
    assert {(f.attack_id, f.slot_id, f.level) for f in report.findings} == {
        (f.attack_id, f.slot_id, f.level) for f in in_process.findings
    }


def test_scanning_the_fixed_bot_through_the_harness_finds_nothing(harness_practice):
    target = harness_practice("fixed")
    report = asyncio.run(run_scan(target, default_attacks(target)))
    assert report.status == "no_verified_violations", report.inconclusive_reasons


def test_the_command_line_makes_a_usable_key(capsys):
    from promptproof.cli import main

    assert main(["harness-key"]) == 0
    printed = capsys.readouterr()
    made = printed.out.strip()
    assert pp.check_key(made) == made and "Never set it in production" in printed.err
