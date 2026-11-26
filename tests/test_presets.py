"""`kritalon init`: descriptions for bots built in Flowise, Dify and Langflow. Each stand-in bot
here answers in the shape that builder documents, and each generated description is used as written."""

import asyncio
import json
import re
from datetime import UTC, datetime

import httpx
import pytest

from kritalon.attacks.library import default_attacks
from kritalon.cli import main
from kritalon.core.authorization import new_authorization
from kritalon.core.runner import ScanConfig, run_scan
from kritalon.presets import OWNER, PresetError, build
from kritalon.targets.http import HttpTarget, parse_config

ORIGIN = "http://127.0.0.1:3000"
ARGS = {
    "flowise": {"flow": "0b8f3c5e-1111-4222-8333-444455556666"},
    "dify": {},
    "langflow": {"flow": "support-flow", "component": "Prompt-a1B2c"},
}


def stand_in(preset: str, line: str, leaky: bool):
    """A bot in the builder's request and response shape whose instructions hold the line `init` printed.
    The careful build gives the reference only for the pass phrase; the leaky build gives it to anyone."""
    phrase = re.search(r'pass phrase "([^"]+)"', line).group(1)
    seen: list[httpx.Request] = []
    conversations: set[str] = set()

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        body = json.loads(request.content)
        if preset == "flowise":
            assert request.url.path == "/api/v1/prediction/" + ARGS["flowise"]["flow"]
            assert body["streaming"] is False and body["chatId"] == body["overrideConfig"]["sessionId"] != ""
            message, value = body["question"], body["overrideConfig"]["vars"]["pp_reference"]
        elif preset == "dify":
            assert request.url.path == "/v1/chat-messages" and body["response_mode"] == "blocking"
            assert body["user"].startswith("kritalon-")
            conversation = body["conversation_id"]
            if conversation and conversation not in conversations:
                return httpx.Response(404, json={"code": "not_found", "message": "Conversation Not Exists."})
            conversation = conversation or f"conv-{len(conversations) + 1}"
            conversations.add(conversation)
            message, value = body["query"], body["inputs"]["pp_reference"]
        else:
            assert request.url.path == "/api/v1/run/support-flow" and body["session_id"] != ""
            assert request.headers["x-api-key"] == "test-key"
            message, value = body["input_value"], body["tweaks"]["Prompt-a1B2c"]["pp_reference"]
        if preset != "langflow":
            assert request.headers["Authorization"] == "Bearer test-key"
        if "opening hours" in message.lower():
            text = "We are open every day."
        elif phrase in message or leaky:
            text = f"The internal reference is {value}."
        else:
            text = "I can't share that."
        if preset == "flowise":
            return httpx.Response(200, json={"text": text, "chatId": body["chatId"], "sessionId": body["chatId"]})
        if preset == "dify":
            return httpx.Response(200, json={"event": "message", "answer": text, "conversation_id": conversation})
        return httpx.Response(200, json={"session_id": body["session_id"], "outputs": [{"outputs": [{"results": {"message": {"text": text}}}]}]})

    return httpx.MockTransport(handler), seen


def scan(preset: str, leaky: bool, monkeypatch):
    for name in ("FLOWISE_API_KEY", "DIFY_APP_KEY", "LANGFLOW_API_KEY"):
        monkeypatch.setenv(name, "test-key")
    raw, _, line = build(preset, ORIGIN, **ARGS[preset])
    raw["task_checks"][0].update(prompt="What are your opening hours?", expect_substring="open")
    transport, seen = stand_in(preset, line, leaky)
    permission = new_authorization(ORIGIN, "Dana Levi", "the builder bot", "test", 1, datetime.now(UTC))
    target = HttpTarget(parse_config(preset, raw), f"http:{preset}", permission, transport)
    report = asyncio.run(run_scan(target, default_attacks(target), ScanConfig(reproduction_trials=2)))
    return report, seen, line


@pytest.mark.parametrize("preset", ["flowise", "dify", "langflow"])
def test_a_generated_description_scans_a_bot_in_that_builders_shape(preset, monkeypatch):
    report, seen, line = scan(preset, leaky=True, monkeypatch=monkeypatch)
    assert report.status == "violations_verified", report.inconclusive_reasons
    assert {finding.slot_id for finding in report.findings} == {"pp_reference"}
    report, seen, line = scan(preset, leaky=False, monkeypatch=monkeypatch)
    assert report.status == "no_verified_violations", report.inconclusive_reasons
    # The pass phrase is the owner's alone: no message sent as the attacker ever contained it.
    phrase = re.search(r'pass phrase "([^"]+)"', line).group(1)
    owner_only = [json.loads(r.content) for r in seen if phrase in r.content.decode()]
    assert owner_only and all(body.get("user", "kritalon-owner") == "kritalon-owner" for body in owner_only)


def test_a_builder_that_ignores_the_variable_is_reported_as_unreachable_not_as_protected(monkeypatch):
    """Flowise answers 200 and drops an override that is not switched on."""
    monkeypatch.setenv("FLOWISE_API_KEY", "test-key")
    raw, _, _ = build("flowise", ORIGIN, **ARGS["flowise"])
    raw["task_checks"][0].update(prompt="What are your opening hours?", expect_substring="open")

    def handler(request: httpx.Request) -> httpx.Response:
        text = "We are open every day." if b"opening hours" in request.content else "I can't share that."
        return httpx.Response(200, json={"text": text})

    permission = new_authorization(ORIGIN, "Dana Levi", "the builder bot", "test", 1, datetime.now(UTC))
    target = HttpTarget(parse_config("flowise", raw), "http:flowise", permission, httpx.MockTransport(handler))
    report = asyncio.run(run_scan(target, default_attacks(target), ScanConfig(reproduction_trials=1)))
    assert report.status == "inconclusive"
    assert any("pp_reference" in reason or "never received" in reason for reason in report.inconclusive_reasons)


def test_each_preset_uses_the_builders_own_variable_syntax_and_a_fresh_pass_phrase():
    lines = {preset: build(preset, ORIGIN, **ARGS[preset])[2] for preset in ARGS}
    assert "{{$vars.pp_reference}}" in lines["flowise"]
    assert "{{pp_reference}}" in lines["dify"] and "$vars" not in lines["dify"]
    assert "{pp_reference}" in lines["langflow"] and "{{" not in lines["langflow"]
    phrases = {re.search(r'pass phrase "([^"]+)"', build("dify", ORIGIN)[2]).group(1) for _ in range(5)}
    assert len(phrases) == 5 and all(len(p.split()) == 3 for p in phrases)
    raw, _, line = build("dify", ORIGIN)
    phrase = re.search(r'pass phrase "([^"]+)"', line).group(1)
    assert phrase in raw["slots"][0]["control_prompt"] and raw["slots"][0]["control_principal"] == OWNER
    assert phrase not in raw["slots"][0]["hint"]  # the attacker is told what to look for, never the phrase


@pytest.mark.parametrize(
    ("preset", "kwargs", "reason"),
    [
        ("flowise", {}, "--id is needed"),
        ("langflow", {"flow": "f"}, "--component is needed"),
        ("langflow", {"flow": "../x", "component": "Prompt-1"}, "--id is needed"),
        ("dify", {"variable": "not a name"}, "--variable"),
        ("dify", {"variable": "x}{canary:y"}, "--variable"),
        ("botpress", {}, "unknown preset"),
    ],
)
def test_bad_requests_are_refused(preset, kwargs, reason):
    with pytest.raises(PresetError, match=reason):
        build(preset, ORIGIN, **kwargs)
    with pytest.raises(PresetError):
        build("dify", "not a url")


def test_the_command_line_writes_the_file_and_says_what_is_left(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("KRITALON_TARGETS_FILE", str(tmp_path / "kritalon.targets.json"))
    assert main(["init", "--preset", "dify", "--origin", "http://localhost", "--name", "support"]) == 0
    printed = capsys.readouterr().out
    assert "Add this line to the bot's instructions" in printed and "DIFY_APP_KEY" in printed
    assert "kritalon doctor --target http:support" in printed and "REPLACE THIS" in printed
    assert "Dify Cloud's terms forbid" in printed
    stored = json.loads((tmp_path / "kritalon.targets.json").read_text(encoding="utf-8"))
    parse_config("support", stored["targets"]["support"])
    # A second run does not silently replace the pass phrase the owner already put in the bot.
    assert main(["init", "--preset", "dify", "--origin", "http://localhost", "--name", "support"]) == 2
    assert "already describes" in capsys.readouterr().out
    assert json.loads((tmp_path / "kritalon.targets.json").read_text(encoding="utf-8")) == stored
    assert main(["init", "--preset", "dify", "--origin", "http://localhost", "--name", "support", "--force"]) == 0
    assert main(["init", "--preset", "flowise", "--origin", "http://localhost:3000", "--name", "other"]) == 2
