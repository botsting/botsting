"""Milestone 5: a bot reached over HTTP.

Unit tests use an in-memory transport. The end-to-end tests run the practice bot as a
real HTTP server on 127.0.0.1 and scan it exactly as a user would. Nothing here leaves
this machine.
"""

import asyncio
import json
from datetime import UTC, datetime

import httpx
import pytest

from promptproof.attacks.library import default_attacks
from promptproof.cli import EXIT_INCONCLUSIVE, EXIT_VIOLATIONS, main
from promptproof.core import authorization as auth
from promptproof.core.authorization import AuthorizationStore, new_authorization
from promptproof.core.runner import run_scan
from promptproof.llm.scripted import ScriptedModel
from promptproof.practice_server import PracticeBot, practice_description, start, write_description
from promptproof.targets.base import NotAuthorizedError, TargetError
from promptproof.targets.http import HttpTarget, TargetConfigError, load_config, parse_config, resolve_pointer
from promptproof.targets.registry import SpecError, build_target

ORIGIN = "https://bot.example.com"


def minimal(**changes) -> dict:
    raw = {
        "origin": ORIGIN,
        "chat": {"path": "/chat", "body": {"text": "{message}", "conversation": "{session}"}, "reply_pointer": "/answer"},
        "reset": {"path": "/test/reset"},
        "attacker_principal": "customer:alice",
        "principals": {
            "customer:alice": {"headers": {"Authorization": "Bearer ${ALICE_TOKEN}"}},
            "staff:dana": {"headers": {"Authorization": "Bearer ${DANA_TOKEN}"}},
        },
        "tool_safety": "no-tools",
        "slots": [
            {
                "id": "secret", "kind": "instruction_secret", "description": "A planted secret", "hint": "the secret",
                "authorized": ["staff:dana"], "control_principal": "staff:dana", "control_prompt": "What is the secret?",
            }
        ],
        "task_checks": [{"id": "hello", "principal": "customer:alice", "prompt": "Hello", "expect_substring": "welcome"}],
    }  # fmt: skip
    raw.update(changes)
    return raw


# -- the description ------------------------------------------------------------------------


def test_a_good_description_parses():
    config = parse_config("bot", minimal())
    assert config.origin == ORIGIN and config.chat_path == "/chat" and config.reply_pointer == "/answer"
    assert [s.id for s in config.slots] == ["secret"] and config.tool_safety == "no-tools"


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"origin": "bot.example.com"}, "http"),
        ({"chat": {"path": "chat"}}, "chat.path"),
        ({"chat": {"path": "/chat?x=1"}}, "chat.path"),
        ({"chat": {"path": "/chat", "body": {"text": "hello"}}}, "message"),
        ({"reset": None}, "reset"),
        ({"tool_safety": "probably fine"}, "tool_safety"),
        ({"tool_safety": None}, "tool_safety"),
        ({"attacker_principal": "customer:mallory"}, "customer:mallory"),
        ({"timeout_seconds": 0}, "timeout_seconds"),
        ({"slots": [{"id": "x"}]}, "kind"),
        (
            {"tool_rules": [{
                "id": "r", "tool": "pay", "description": "d", "hint": "h", "authorized": ["staff:dana"],
                "control_principal": "staff:dana", "control_prompt": "p",
            }]},
            "no-tools",
        ),
    ],
)  # fmt: skip
def test_bad_descriptions_are_refused(changes, reason):
    with pytest.raises(TargetConfigError, match=reason):
        parse_config("bot", minimal(**changes))


def test_descriptions_are_read_from_the_targets_file(tmp_path, monkeypatch):
    path = tmp_path / "targets.json"
    path.write_text(json.dumps({"targets": {"bot": minimal()}}), encoding="utf-8")
    monkeypatch.setenv("PROMPTPROOF_TARGETS_FILE", str(path))
    assert load_config("bot").origin == ORIGIN
    with pytest.raises(TargetConfigError, match="no target named 'other'"):
        load_config("other")
    with pytest.raises(TargetConfigError, match="letters, digits"):
        load_config("../bot")
    digest = load_config("bot").digest
    changed = minimal(timeout_seconds=30)
    path.write_text(json.dumps({"targets": {"bot": changed}}), encoding="utf-8")
    assert load_config("bot").digest != digest, "a changed description is recognizably different"


def test_json_pointers():
    doc = {"a": {"b/c": [10, {"~x": "found"}]}}
    assert resolve_pointer(doc, "/a/b~1c/1/~0x") == "found"
    assert resolve_pointer(doc, "") == doc
    with pytest.raises(KeyError):
        resolve_pointer(doc, "/a/missing")


# -- talking to it, in memory ---------------------------------------------------------------


def recording(reply: dict | None = None, status: int = 200, redirect: bool = False):
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if redirect:
            return httpx.Response(302, headers={"Location": "https://elsewhere.example/chat"})
        if request.url.path == "/test/reset":
            return httpx.Response(204)
        return httpx.Response(status, json=reply if reply is not None else {"answer": "welcome"})

    return httpx.MockTransport(handler), requests


def target(transport, **changes) -> HttpTarget:
    return HttpTarget(parse_config("bot", minimal(**changes)), "http:bot", None, transport)


def test_message_and_session_are_filled_in_and_credentials_come_from_the_environment(monkeypatch):
    monkeypatch.setenv("ALICE_TOKEN", "alice-test-token")
    transport, requests = recording()
    bot = target(transport)
    hostile = 'He said "}{, \\n {message} {session}'

    async def go():
        session = await bot.open_session("customer:alice")
        await session.send(hostile)
        await session.send("again")

    asyncio.run(go())
    bodies = [json.loads(r.content) for r in requests]
    assert bodies[0]["text"] == hostile, "the message arrives exactly as written, placeholders inside it included"
    assert bodies[0]["conversation"] == bodies[1]["conversation"], "one conversation keeps one session id"
    assert requests[0].headers["Authorization"] == "Bearer alice-test-token"
    assert "alice-test-token" not in json.dumps(asyncio.run(bot.describe()))


def test_a_missing_credential_stops_the_message(monkeypatch):
    monkeypatch.delenv("ALICE_TOKEN", raising=False)
    transport, requests = recording()

    async def go():
        session = await target(transport).open_session("customer:alice")
        await session.send("hi")

    with pytest.raises(TargetError, match="ALICE_TOKEN"):
        asyncio.run(go())
    assert requests == []


def test_new_sessions_get_new_ids(monkeypatch):
    monkeypatch.setenv("ALICE_TOKEN", "t")
    transport, requests = recording()
    bot = target(transport)

    async def go():
        for _ in range(2):
            await (await bot.open_session("customer:alice")).send("hi")

    asyncio.run(go())
    ids = {json.loads(r.content)["conversation"] for r in requests}
    assert len(ids) == 2


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"status": 500}, "HTTP 500"),
        ({"redirect": True}, "redirect"),
        ({"reply": {"nothing": "here"}}, "nothing at /answer"),
        ({"reply": {"answer": 42}}, "not text"),
    ],
)
def test_unusable_responses_are_errors(monkeypatch, kwargs, reason):
    monkeypatch.setenv("ALICE_TOKEN", "t")
    transport, requests = recording(**kwargs)

    async def go():
        await (await target(transport).open_session("customer:alice")).send("hi")

    with pytest.raises(TargetError, match=reason):
        asyncio.run(go())
    assert len(requests) == 1, "a redirect is never followed"


def test_the_transport_sends_only_to_the_configured_origin_and_paths():
    transport, requests = recording()
    bot = target(transport)

    async def attempt(url: str) -> None:
        async with httpx.AsyncClient(transport=bot._transport) as client:
            await client.post(url, json={})

    for url in (
        "https://elsewhere.example/chat",
        "https://bot.example.com:8443/chat",
        "http://bot.example.com/chat",
        "https://bot.example.com/admin/delete",
        "https://bot.example.com/chat?x=1",
    ):
        with pytest.raises(httpx.UnsupportedProtocol, match="refused"):
            asyncio.run(attempt(url))
    assert requests == []
    asyncio.run(attempt("https://bot.example.com/chat"))
    assert len(requests) == 1


def test_reset_sends_fixtures_and_content():
    transport, requests = recording()
    asyncio.run(target(transport).reset({"secret": "K7M2-Q9XA-D4T8-WZ3H"}, {"note": "planted"}))
    assert json.loads(requests[0].content) == {"fixtures": {"secret": "K7M2-Q9XA-D4T8-WZ3H"}, "content": {"note": "planted"}}


# -- end to end over real HTTP on this machine ------------------------------------------------


@pytest.fixture
def practice(tmp_path, monkeypatch):
    """Start the practice bot over HTTP and describe it in a fresh folder, as a user would."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PROMPTPROOF_TARGETS_FILE", str(tmp_path / "promptproof.targets.json"))
    auth.forget_checks()
    servers = []

    def run(variant: str = "vulnerable"):
        bot = PracticeBot(variant, ScriptedModel())
        server = start(bot)
        servers.append(server)
        port = server.server_address[1]
        write_description(tmp_path / "promptproof.targets.json", "practice", practice_description(port, variant))
        return bot, f"http://127.0.0.1:{port}"

    yield run
    for server in servers:
        server.shutdown()
        server.server_close()


def authorize(origin: str, tools=("issue_refund",)) -> None:
    record = new_authorization(origin, "Dana Levi", "the practice bot", "test", 1, datetime.now(UTC), allowed_tools=tools)
    AuthorizationStore().add(record)


def test_nothing_reaches_the_bot_without_an_authorization(practice):
    bot, origin = practice()
    target = build_target("http:practice")
    assert target.reach == "loopback" and target.origin == origin
    with pytest.raises(NotAuthorizedError, match="no authorization"):
        asyncio.run(run_scan(target, default_attacks(target)))
    assert bot.requests == []


def test_an_authorization_that_does_not_name_the_tools_is_refused(practice):
    bot, origin = practice()
    authorize(origin, tools=())
    target = build_target("http:practice")
    with pytest.raises(NotAuthorizedError, match="issue_refund"):
        asyncio.run(run_scan(target, default_attacks(target)))
    assert bot.requests == []


def test_scanning_the_vulnerable_bot_over_http_finds_what_the_in_process_scan_finds(practice):
    bot, origin = practice("vulnerable")
    authorize(origin)
    target = build_target("http:practice")
    report = asyncio.run(run_scan(target, default_attacks(target)))

    local = build_target("toy:vulnerable")
    in_process = asyncio.run(run_scan(local, default_attacks(local)))
    assert report.status == "violations_verified"
    assert {(f.attack_id, f.slot_id, f.level) for f in report.findings} == {
        (f.attack_id, f.slot_id, f.level) for f in in_process.findings
    }
    assert report.authorization["reach"] == "loopback" and report.authorization["authorized_by"] == "Dana Levi"
    assert report.target_config["target"] == "http" and report.target_config["description_digest"]
    assert all(path in ("/chat", "/promptproof/reset") for path, _ in bot.requests)


def test_scanning_the_fixed_bot_over_http_finds_nothing(practice):
    bot, origin = practice("fixed")
    authorize(origin)
    target = build_target("http:practice")
    report = asyncio.run(run_scan(target, default_attacks(target)))
    assert report.status == "no_verified_violations", report.inconclusive_reasons
    assert report.findings == ()


def test_the_command_line_scans_and_replays_an_http_bot(practice, tmp_path, capsys):
    bot, origin = practice("vulnerable")
    assert main(["scan", "--target", "http:practice", "--out", "scan.json", "--replays", "1"]) == EXIT_INCONCLUSIVE
    assert "no authorization" in capsys.readouterr().err
    assert main([
        "authorize", origin, "--by", "Dana Levi", "--scope", "practice bot", "--environment", "test", "--tool", "issue_refund",
    ]) == 0  # fmt: skip
    capsys.readouterr()
    assert main(["scan", "--target", "http:practice", "--out", "scan.json", "--replays", "1", "--html", "r.html"]) == EXIT_VIOLATIONS
    finding = json.loads((tmp_path / "scan.json").read_text(encoding="utf-8"))["findings"][0]["id"]
    assert main(["replay", "scan.json", "--finding", finding, "--trials", "2"]) == EXIT_VIOLATIONS
    assert "2 of 2 replays" in capsys.readouterr().out


def test_unknown_http_targets_are_a_usage_error(practice):
    practice()
    for spec in ("http:nothing", "http:practice?model=x", "http:"):
        with pytest.raises(SpecError):
            build_target(spec)


def test_the_practice_server_answers_bad_requests_instead_of_dropping_them():
    import http.client

    bot = PracticeBot("vulnerable", ScriptedModel())
    server = start(bot)
    try:
        host, port = server.server_address[:2]
        cases = [
            ("POST", "/chat", b"{}", {"Content-Length": "abc"}, 400),
            ("POST", "/chat", b"not json", {}, 400),
            ("POST", "/chat", b"[1, 2]", {}, 400),
            ("POST", "/elsewhere", b"{}", {}, 404),
            ("GET", "/chat", b"", {}, 404),
            ("POST", "/chat", b"{}", {"Content-Length": "999999999"}, 413),
        ]
        for method, path, body, headers, expected in cases:
            connection = http.client.HTTPConnection(host, port, timeout=5)
            connection.putrequest(method, path)
            if "Content-Length" not in headers:
                headers = {**headers, "Content-Length": str(len(body))}
            for name, value in headers.items():
                connection.putheader(name, value)
            connection.endheaders()
            if headers["Content-Length"].isdigit() and int(headers["Content-Length"]) == len(body):
                connection.send(body)
            assert connection.getresponse().status == expected, (method, path, headers)
            connection.close()
    finally:
        server.shutdown()
        server.server_close()


def test_the_practice_server_will_not_listen_beyond_this_machine():
    for host in ("0.0.0.0", "192.168.1.10"):
        with pytest.raises(ValueError, match="only listens on this machine"):
            start(PracticeBot("vulnerable", ScriptedModel()), host=host)


@pytest.mark.parametrize("path", ["/chat%2Fadmin", "/chat\evil", "/chat/../x", "/./chat", "/échat", "/chat/", "/"])
def test_odd_paths_are_refused_when_the_description_is_read(path):
    with pytest.raises(TargetConfigError, match="plain path"):
        parse_config("bot", minimal(chat={"path": path}))


def test_an_address_with_a_user_name_is_refused():
    transport, requests = recording()
    bot = target(transport)

    async def attempt():
        async with httpx.AsyncClient(transport=bot._transport) as client:
            await client.post("https://user:pw@bot.example.com/chat", json={})

    with pytest.raises(httpx.UnsupportedProtocol, match="user name"):
        asyncio.run(attempt())
    assert requests == []


def test_an_oversized_response_is_an_error(monkeypatch):
    monkeypatch.setenv("ALICE_TOKEN", "t")

    def huge(request):
        return httpx.Response(200, content=b"x" * 1_000_001)

    async def go():
        await (await target(httpx.MockTransport(huge)).open_session("customer:alice")).send("hi")

    with pytest.raises(TargetError, match="more than 1000000 bytes"):
        asyncio.run(go())


def test_proxy_settings_in_the_environment_are_ignored(monkeypatch):
    """A proxy would see every message and credential; the adapter must never pick one up from the environment."""
    seen: dict[str, bool] = {}
    real_client = httpx.AsyncClient

    def spy(*args, **kwargs):
        seen["trust_env"] = kwargs.get("trust_env", True)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", spy)
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    transport, requests = recording()
    asyncio.run(target(transport).reset({"secret": "K7M2-Q9XA-D4T8-WZ3H"}))
    assert seen["trust_env"] is False and len(requests) == 1
