"""Claude as the assistant that is offered tools. The API here is an object inside the test: nothing is sent anywhere."""

import asyncio
from types import SimpleNamespace as Obj

import pytest

from botsting.llm.base import ModelError
from botsting.llm.claude import ClaudeToolModel
from botsting.llm.tools import ToolOutcome, ToolRequest, ToolSpec

TOOLS = [ToolSpec("find_products", "Find products.", {"type": "object", "properties": {"query": {"type": "string"}}})]


def usage(fresh=10, written=0, read=0, out=5):
    return Obj(input_tokens=fresh, cache_creation_input_tokens=written, cache_read_input_tokens=read, output_tokens=out)


class Api:
    """Stands in for the SDK's client: answers `messages.create` from a list, and keeps what it was sent."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.sent: list[dict] = []
        self.messages = self

    async def create(self, **request):
        self.sent.append({**request, "messages": list(request["messages"])})
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


def asks_for_a_tool():
    blocks = [
        Obj(type="thinking", thinking="", signature="sig"),
        Obj(type="text", text="Let me look."),
        Obj(type="tool_use", id="toolu_1", name="find_products", input={"query": "mug"}),
    ]
    return Obj(content=blocks, stop_reason="tool_use", usage=usage(fresh=3, written=900, read=0, out=40))


def answers(text="There are two mugs."):
    return Obj(content=[Obj(type="text", text=text)], stop_reason="end_turn", usage=usage(fresh=3, written=0, read=900, out=12))


def test_a_request_for_a_tool_and_then_an_answer():
    api = Api(asks_for_a_tool(), answers())
    talk = ClaudeToolModel("claude-haiku-5-5", client=api).converse("You help a shop owner.", TOOLS)

    async def run():
        first = await talk.say("How many mugs do we sell?")
        second = await talk.give([ToolOutcome("toolu_1", "2 products: Blue mug, Red mug")])
        return first, second

    first, second = asyncio.run(run())
    assert first.ended == "tools" and first.text == "Let me look."
    assert first.requests == (ToolRequest("toolu_1", "find_products", {"query": "mug"}),)
    assert (first.input_tokens, first.output_tokens) == (903, 40), "cached tokens are counted as input"
    assert second.ended == "answer" and second.text == "There are two mugs." and not second.requests
    assert (second.input_tokens, second.output_tokens) == (903, 12)

    sent_first, sent_second = api.sent
    assert sent_first["model"] == "claude-haiku-5-5" and sent_first["max_tokens"] == 16000
    assert sent_first["system"] == [{"type": "text", "text": "You help a shop owner.", "cache_control": {"type": "ephemeral"}}]
    assert sent_first["tools"] == [{"name": "find_products", "description": "Find products.", "input_schema": TOOLS[0].schema}]
    assert sent_first["messages"] == [{"role": "user", "content": "How many mugs do we sell?"}]
    assert set(sent_first) == {"model", "max_tokens", "system", "tools", "messages"}, "nothing else is set, and no fallback model"
    history = sent_second["messages"]
    assert [m["role"] for m in history] == ["user", "assistant", "user"]
    assert [b.type for b in history[1]["content"]] == ["thinking", "text", "tool_use"], "the model's turn goes back whole"
    assert history[2]["content"] == [{"type": "tool_result", "tool_use_id": "toolu_1", "content": "2 products: Blue mug, Red mug"}]


def test_every_outcome_goes_back_in_one_message_and_a_failure_is_marked():
    two = Obj(
        content=[Obj(type="tool_use", id="a", name="find_products", input={}), Obj(type="tool_use", id="b", name="find_products", input=None)],
        stop_reason="tool_use",
        usage=usage(),
    )
    api = Api(two, answers())
    talk = ClaudeToolModel("claude-haiku-5-5", client=api).converse("s", TOOLS)

    async def run():
        step = await talk.say("go")
        await talk.give([ToolOutcome("a", "fine"), ToolOutcome("b", "no such product", failed=True)])
        return step

    step = asyncio.run(run())
    assert [r.arguments for r in step.requests] == [{}, {}]
    assert api.sent[1]["messages"][-1]["content"] == [
        {"type": "tool_result", "tool_use_id": "a", "content": "fine"},
        {"type": "tool_result", "tool_use_id": "b", "content": "no such product", "is_error": True},
    ]


def test_a_model_that_declines_is_reported_as_declining_with_the_category():
    declined = Obj(content=[], stop_reason="refusal", stop_details=Obj(category="cyber", explanation="..."), usage=usage(out=0))
    step = asyncio.run(ClaudeToolModel("claude-haiku-5-5", client=Api(declined)).converse("s", TOOLS).say("go"))
    assert step.ended == "declined" and step.detail == "cyber" and not step.requests and step.text == ""


def test_a_reply_cut_off_at_the_length_limit_is_reported_as_cut_off():
    cut = Obj(content=[Obj(type="text", text="The first of the")], stop_reason="max_tokens", usage=usage())
    step = asyncio.run(ClaudeToolModel("claude-haiku-5-5", client=Api(cut)).converse("s", TOOLS).say("go"))
    assert step.ended == "cut-off" and step.text == "The first of the" and not step.requests


def test_a_failed_request_becomes_a_model_error_that_holds_nothing_from_the_request():
    api = Api(RuntimeError("request with x-api-key sk-ant-secret failed"))
    with pytest.raises(ModelError) as caught:
        asyncio.run(ClaudeToolModel("claude-haiku-5-5", client=api).converse("s", TOOLS).say("go"))
    assert str(caught.value) == "anthropic:claude-haiku-5-5: RuntimeError"


def test_the_model_must_be_named_and_is_part_of_the_fingerprint():
    with pytest.raises(ModelError, match="name the model"):
        ClaudeToolModel("")
    model = ClaudeToolModel("claude-haiku-5-5", client=Api())
    assert model.name == "anthropic:claude-haiku-5-5"
    assert asyncio.run(model.fingerprint()) == {"provider": "anthropic", "model": "claude-haiku-5-5", "max_tokens": "16000"}


def test_with_the_real_sdk_an_api_that_cannot_be_reached_is_a_plain_model_error():
    """Runs where the SDK is installed. The key is not a key and the address is a closed port on this machine."""
    anthropic = pytest.importorskip("anthropic")
    api = anthropic.AsyncAnthropic(api_key="not-a-key", base_url="http://127.0.0.1:9", max_retries=0, timeout=5.0)
    with pytest.raises(ModelError) as caught:
        asyncio.run(ClaudeToolModel("claude-haiku-5-5", client=api).converse("s", TOOLS).say("go"))
    assert str(caught.value) == "anthropic:claude-haiku-5-5: the API could not be reached"
