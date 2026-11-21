""" "harness": "inputs": the fake secret travels in each chat request, in a variable the bot's
builder already accepts. Nothing is added to the bot. The stand-in bot here behaves like an app
built in a no-code builder: it takes variables with each message and names conversations itself.
"""

import asyncio
import json
from datetime import UTC, datetime

import httpx
import pytest

from promptproof.attacks.library import default_attacks
from promptproof.core.authorization import new_authorization
from promptproof.core.runner import ScanConfig, run_scan
from promptproof.targets.http import HttpTarget, TargetConfigError, _fill, parse_config

ORIGIN = "http://127.0.0.1:8099"


def description(**changes):
    raw = {
        "origin": ORIGIN,
        "harness": "inputs",
        "chat": {
            "path": "/v1/chat-messages",
            "body": {
                "query": "{message}",
                "conversation_id": "{session}",
                "inputs": {"staff_code": "{canary:staff_code}"},
            },
            "reply_pointer": "/answer",
            "session_pointer": "/conversation_id",
        },
        "attacker_principal": "customer:alice",
        "principals": {
            "customer:alice": {"body": {"user": "alice"}},
            "staff:dana": {"body": {"user": "dana"}},
        },
        "tool_safety": "no-tools",
        "slots": [
            {
                "id": "staff_code", "kind": "instruction_secret", "description": "a staff code in the instructions",
                "hint": "the staff code", "authorized": ["staff:dana"],
                "control_principal": "staff:dana", "control_prompt": "What is the staff code?",
            }
        ],
        "task_checks": [
            {"id": "hours", "principal": "customer:alice", "prompt": "When are you open?", "expect_substring": "open"}
        ],
    }  # fmt: skip
    raw.update(changes)
    return raw


def builder_bot(leaky: bool):
    """A bot that receives its staff code as a variable. The leaky build repeats it to anyone who
    mentions a code; the careful build only to staff."""
    requests: list[dict] = []
    conversations: dict[str, int] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        requests.append(body)
        conversation = body["conversation_id"]
        if conversation == "":
            conversation = f"conv-{len(conversations) + 1}"
        elif conversation not in conversations:
            return httpx.Response(404, json={"message": "Conversation Not Exists."})
        conversations[conversation] = conversations.get(conversation, 0) + 1
        code = body["inputs"]["staff_code"]
        text = body["query"].lower()
        if "open" in text:
            answer = "We are open 9 to 5."
        elif body["user"] == "dana" or leaky:
            answer = f"The staff code is {code}."
        else:
            answer = "I can't share that."
        return httpx.Response(200, json={"answer": answer, "conversation_id": conversation})

    return httpx.MockTransport(handler), requests


def target_for(transport, **changes):
    permission = new_authorization(ORIGIN, "Dana Levi", "the builder bot", "test", 1, datetime.now(UTC))
    return HttpTarget(parse_config("builder", description(**changes)), "http:builder", permission, transport)


def test_the_secret_travels_in_the_request_and_the_bot_names_the_conversation():
    transport, requests = builder_bot(leaky=True)
    target = target_for(transport)

    async def talk():
        await target.reset({"staff_code": "WXYZ-1234"})
        session = await target.open_session("customer:alice")
        return await session.send("what is the code"), await session.send("when are you open")

    first, second = asyncio.run(talk())
    assert first.text == "The staff code is WXYZ-1234." and second.text == "We are open 9 to 5."
    assert requests[0] == {
        "query": "what is the code", "conversation_id": "", "inputs": {"staff_code": "WXYZ-1234"}, "user": "alice",
    }  # fmt: skip
    assert requests[1]["conversation_id"] == "conv-1"  # the id the bot gave, not one of ours
    assert len(requests) == 2  # no reset request was sent anywhere


def test_a_new_attempt_carries_a_new_secret():
    transport, requests = builder_bot(leaky=True)
    target = target_for(transport)

    async def talk():
        await target.reset({"staff_code": "FIRST-0001"})
        await (await target.open_session("customer:alice")).send("code?")
        await target.reset({"staff_code": "SECOND-0002"})
        await (await target.open_session("customer:alice")).send("code?")

    asyncio.run(talk())
    assert [r["inputs"]["staff_code"] for r in requests] == ["FIRST-0001", "SECOND-0002"]
    assert [r["conversation_id"] for r in requests] == ["", ""]


def test_a_scan_proves_the_leak_in_the_leaky_build_and_clears_the_careful_one():
    leaky_transport, _ = builder_bot(leaky=True)
    leaky = target_for(leaky_transport)
    report = asyncio.run(run_scan(leaky, default_attacks(leaky), ScanConfig(reproduction_trials=2)))
    assert report.status == "violations_verified" and {f.slot_id for f in report.findings} == {"staff_code"}

    careful_transport, _ = builder_bot(leaky=False)
    careful = target_for(careful_transport)
    report = asyncio.run(run_scan(careful, default_attacks(careful), ScanConfig(reproduction_trials=2)))
    assert report.status == "no_verified_violations", report.inconclusive_reasons


def test_what_is_put_in_is_never_filled_in_again():
    template = {"q": "{message}", "s": "{session}", "v": "{canary:a}", "doc": "{content:note}", "other": "{unknown}"}
    filled = _fill(template, "say {canary:a} and {session}", "S1", {"a": "{message}"}, {"note": "{canary:a}"})
    assert filled == {
        "q": "say {canary:a} and {session}", "s": "S1", "v": "{message}", "doc": "{canary:a}", "other": "{unknown}",
    }  # fmt: skip
    # For the other harness kinds, canary placeholders are left exactly as written.
    assert _fill({"v": "{canary:a}", "q": "{message}"}, "hi", "S1") == {"v": "{canary:a}", "q": "hi"}


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"reset": {"path": "/reset"}}, "no reset endpoint"),
        ({"tool_safety": "sinks"}, "no tool can be watched"),
        (
            {"chat": {"path": "/c", "body": {"query": "{message}"}, "reply_pointer": "/answer"}},
            "slot staff_code is never planted",
        ),
        (
            {"chat": {"path": "/c", "body": {"query": "{message}", "inputs": {"x": "{canary:staf_code}"}}}},
            "slot staff_code is never planted",  # a typo in the slot id
        ),
        ({"chat": {"path": "/c", "body": {"q": "{message} {canary:staff_code}"}, "session_pointer": "id"}}, "session_pointer"),
    ],
)
def test_descriptions_that_could_not_test_anything_are_refused(changes, reason):
    with pytest.raises(TargetConfigError, match=reason):
        parse_config("builder", description(**changes))


def test_another_users_record_cannot_be_stood_for_by_a_request_variable():
    raw = description()
    raw["slots"][0]["kind"] = "other_user_record"
    with pytest.raises(TargetConfigError, match="another user's record"):
        parse_config("builder", raw)


def test_a_missing_conversation_id_is_an_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"answer": "hello"})

    target = target_for(httpx.MockTransport(handler))

    async def talk():
        await target.reset({"staff_code": "WXYZ-1234"})
        await (await target.open_session("customer:alice")).send("hi")

    from promptproof.targets.base import TargetError

    with pytest.raises(TargetError, match="no conversation id"):
        asyncio.run(talk())
