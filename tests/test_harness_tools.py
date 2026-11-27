"""Invoke guarded tools locally through each framework, without a model."""

import asyncio
import json
from functools import partial

import pytest
from test_harness import KEY, in_session

import botsting.harness as pp
from botsting.harness_tools import (
    claude_pre_tool_use,
    guard,
    guard_agents,
    guard_claude_agent,
    guard_langchain,
)


@pytest.fixture
def token(monkeypatch):
    monkeypatch.setenv(pp.KEY_ENV, KEY)
    monkeypatch.delenv(pp.LIVE_ENV, raising=False)
    return pp.make_session_token(KEY, "tools", {})


def arguments(calls):
    return [(call["tool"], call["arguments"]) for call in calls]


def test_guard_records_all_non_reads_with_decorator_semantics(token):
    effects = []

    def refund(order, amount=3):
        effects.append((order, amount))
        return "refunded"

    class Send:
        async def __call__(self, message):
            effects.append(message)
            return "sent"

    def lookup(order):
        effects.append(order)
        return "found"

    original = {"refund": refund, "send": partial(Send()), "lookup": lookup}
    tools = guard(
        original,
        reads=(name for name in ["lookup"]),
        results={"refund": lambda order, amount: f"{order}: {amount}", "send": None},
    )
    assert list(tools) == list(original)
    assert original["refund"] is refund and tools["lookup"] is lookup
    assert tools["refund"]("T-1") == "refunded"
    assert asyncio.run(tools["send"]("a refund please")) == "sent"
    assert tools["lookup"]("T-1") == "found"
    assert effects == [("T-1", 3), "a refund please", "T-1"]
    effects.clear()

    async def turn():
        assert tools["refund"]("T-2") == "T-2: 3"
        assert await tools["send"]("a refund please") is None
        assert tools["lookup"]("T-2") == "found"
        return pp.recorded_calls()

    calls, session = in_session(token, lambda: asyncio.run(turn()))
    assert calls == session.calls
    assert arguments(calls) == [
        ("refund", {"order": "T-2", "amount": "3"}),
        ("send", {"message": "a refund please"}),
    ]
    assert effects == ["T-2"]
    assert pp.recorded_calls() == []


@pytest.mark.parametrize("option", ["reads", "results", "live"])
def test_guard_rejects_unknown_names_at_setup(option):
    values = ("refnud",) if option == "reads" else {"refnud": None}
    with pytest.raises(pp.HarnessError, match=f"{option}.*refnud"):
        guard({"refund": lambda: None}, **{option: values})


def test_guard_passes_live_caps_through(token, monkeypatch):
    effects = []

    def refund(amount):
        effects.append(amount)
        return "refunded"

    tools = guard({"refund": refund}, live={"refund": pp.Cap(max={"amount": 5})})
    result, _ = in_session(token, tools["refund"], 3)
    assert result == {"status": "ok"}
    assert effects == []

    monkeypatch.setenv(pp.LIVE_ENV, "refund")
    monkeypatch.setattr(pp, "_ledger", {})
    monkeypatch.setattr(pp, "_run_first_seen", {})
    live_token = pp.make_session_token(KEY, "tools", {}, live=["refund"], run="guard")

    def turn():
        assert tools["refund"](6) == {"status": "ok"}
        assert tools["refund"](5) == "refunded"
        assert tools["refund"](3) == {"status": "ok"}
        return pp.recorded_calls()

    calls, _ = in_session(live_token, turn)
    assert [call["live"] for call in calls] == ["capped", "ran", "capped"]
    assert effects == [5]


def test_openai_agents_tools(token):
    agents = pytest.importorskip("agents")
    from agents.tool import invoke_function_tool
    from agents.tool_context import ToolContext

    effects = []

    @agents.function_tool(name_override="refund")
    def request_refund(amount: int) -> str:
        """Request a refund."""
        effects.append(amount)
        return "refunded"

    @agents.function_tool
    async def send(message: str) -> str:
        """Send a message."""
        effects.append(message)
        return "sent"

    @agents.function_tool
    def lookup(order: str) -> str:
        """Look up an order."""
        effects.append(order)
        return "found"

    async def acknowledge(ctx, raw):
        effects.append(json.loads(raw)["ticket-id"])
        return "acknowledged"

    ticket = agents.FunctionTool(
        name="acknowledge",
        description="Acknowledge a ticket.",
        params_json_schema={"type": "object", "properties": {"ticket-id": {"type": "string"}}},
        on_invoke_tool=acknowledge,
    )
    original = [request_refund, send, ticket, lookup]
    tools = guard_agents(original, reads=["lookup"])
    assert [tool.params_json_schema for tool in tools] == [tool.params_json_schema for tool in original]
    assert tools[3] is lookup and tools[0] is not request_refund
    with pytest.raises(pp.HarnessError, match="lokup"):
        guard_agents(original, reads=["lokup"])
    with pytest.raises(pp.HarnessError, match="FunctionTool"):
        guard_agents([*original, object()])

    async def turn():
        results = []
        inputs = ['{"amount": 5}', '{"message": "a refund please"}', '{"ticket-id": "42"}', '{"order": "T-1"}']
        for tool, args in zip(tools, inputs, strict=True):
            context = ToolContext(
                context=None,
                tool_name=tool.name,
                tool_call_id="call-1",
                tool_arguments=args,
            )
            results.append(await invoke_function_tool(function_tool=tool, context=context, arguments=args))
        return results, pp.recorded_calls()

    assert asyncio.run(turn()) == (["refunded", "sent", "acknowledged", "found"], [])
    assert effects == [5, "a refund please", "42", "T-1"]
    effects.clear()
    (results, calls), _ = in_session(token, lambda: asyncio.run(turn()))
    assert [json.loads(result) for result in results[:3]] == [{"status": "ok"}] * 3
    assert results[3] == "found"
    assert arguments(calls) == [
        ("refund", {"amount": "5"}),
        ("send", {"message": "a refund please"}),
        ("acknowledge", {"ticket-id": "42"}),
    ]
    assert effects == ["T-1"]


def test_openai_agents_refuses_to_weaken_callable_approval():
    agents = pytest.importorskip("agents")

    async def needs_approval(context, args, call_id):
        return args["amount"] > 5

    @agents.function_tool(needs_approval=needs_approval)
    def refund(amount: int = 5) -> str:
        """Request a refund."""
        return "refunded"

    with pytest.raises(pp.HarnessError, match="callable needs_approval"):
        guard_agents([refund])
    assert guard_agents([refund], reads=["refund"]) == [refund]


def test_langchain_tools(token):
    pytest.importorskip("langchain_core")
    from typing import Annotated

    from langchain_core.messages import ToolMessage
    from langchain_core.tools import BaseTool, InjectedToolArg, StructuredTool, tool

    effects = []

    def refund(amount: int) -> tuple[str, int]:
        effects.append(amount)
        return "refunded", amount

    @tool("send")
    async def send_message(message: str, state: Annotated[str, InjectedToolArg]) -> str:
        """Send a message."""
        effects.append(message)
        return "sent"

    class Lookup(BaseTool):
        name: str = "lookup"
        description: str = "Look up an order."

        def _run(self, order: str) -> str:
            effects.append(order)
            return "found"

    lookup = Lookup()
    original = [
        StructuredTool.from_function(refund, description="Request a refund.", response_format="content_and_artifact"),
        send_message,
        lookup,
    ]
    tools = guard_langchain(original, reads=["lookup"])
    assert type(tools[0]) is StructuredTool and tools[0].args_schema is original[0].args_schema
    assert tools[2] is lookup
    with pytest.raises(pp.HarnessError, match="lokup"):
        guard_langchain(original, reads=["lokup"])

    async def turn():
        refund_call = {"type": "tool_call", "id": "refund-1", "name": "refund", "args": {"amount": 5}}
        send_call = {
            "type": "tool_call",
            "id": "send-1",
            "name": "send",
            "args": {"message": "a refund please", "state": "injected state"},
        }
        synced = tools[0].invoke(refund_call)
        threaded = await tools[0].ainvoke(refund_call)
        sent = await tools[1].ainvoke(send_call)
        read = tools[2].invoke({"order": "T-1"})
        return (synced, threaded, sent, read), pp.recorded_calls()

    (synced, threaded, sent, read), calls = asyncio.run(turn())
    assert (synced.content, synced.artifact, threaded.content, sent.content, read) == (
        "refunded",
        5,
        "refunded",
        "sent",
        "found",
    )
    assert effects == [5, 5, "a refund please", "T-1"] and calls == []
    effects.clear()

    (results, calls), _ = in_session(token, lambda: asyncio.run(turn()))
    for result, call_id in zip(results[:3], ["refund-1", "refund-1", "send-1"]):
        assert isinstance(result, ToolMessage) and result.tool_call_id == call_id
        assert json.loads(result.content) == {"status": "ok"}
    assert results[3] == "found"
    assert arguments(calls) == [
        ("refund", {"amount": "5"}),
        ("refund", {"amount": "5"}),
        ("send", {"message": "a refund please"}),
    ]
    assert effects == ["T-1"]


def test_langchain_guards_custom_invocation_and_direct_run(token):
    pytest.importorskip("langchain_core")
    from langchain_core.tools import BaseTool

    effects = []

    class Custom(BaseTool):
        name: str = "custom"
        description: str = "Custom tool."

        def _run(self, text: str) -> str:
            effects.append(text)
            return text

        def invoke(self, input, config=None, **kwargs):
            return self._run(input)

    original = Custom()
    (tool,) = guard_langchain([original])
    assert tool.invoke("outside") == "outside"

    async def turn():
        assert json.loads(tool.invoke("via invoke")) == {"status": "ok"}
        assert json.loads(tool.run("via run")) == {"status": "ok"}
        assert json.loads(await tool.arun("via arun")) == {"status": "ok"}
        return pp.recorded_calls()

    calls, _ = in_session(token, lambda: asyncio.run(turn()))
    assert arguments(calls) == [
        ("custom", {"input": "via invoke"}),
        ("custom", {"input": "via run"}),
        ("custom", {"input": "via arun"}),
    ]
    assert effects == ["outside"]


def test_claude_in_process_tools(token):
    claude = pytest.importorskip("claude_agent_sdk")
    import anyio
    from mcp import ClientSession
    from mcp.shared.memory import create_client_server_memory_streams

    effects = []

    @claude.tool("refund", "Request a refund.", {"amount": int})
    async def request_refund(args):
        effects.append(args["amount"])
        return {"content": [{"type": "text", "text": "refunded"}]}

    @claude.tool("lookup", "Look up an order.", {"order": str})
    async def lookup(args):
        effects.append(args["order"])
        return {"content": [{"type": "text", "text": "found"}]}

    original = [request_refund, lookup]
    guarded = guard_claude_agent(original, reads=["lookup"], server_name="orders")
    assert guarded[1] is lookup and guarded[0].input_schema == request_refund.input_schema
    with pytest.raises(pp.HarnessError, match="lokup"):
        guard_claude_agent(original, reads=["lokup"])
    server = claude.create_sdk_mcp_server("orders", tools=guarded)["instance"]

    async def turn():
        async with create_client_server_memory_streams() as (client_streams, server_streams):
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(server.run, *server_streams, server.create_initialization_options())
                async with ClientSession(*client_streams) as client:
                    await client.initialize()
                    refund = await client.call_tool("refund", {"amount": 5})
                    read = await client.call_tool("lookup", {"order": "T-1"})
                tasks.cancel_scope.cancel()
        assert not any(result.model_dump(by_alias=True).get("isError") for result in (refund, read))
        return (refund.content[0].text, read.content[0].text), pp.recorded_calls()

    assert asyncio.run(turn()) == (("refunded", "found"), [])
    assert effects == [5, "T-1"]
    effects.clear()

    ((refund, read), calls), _ = in_session(token, lambda: asyncio.run(turn()))
    assert json.loads(refund) == {"status": "ok"} and read == "found"
    assert arguments(calls) == [("mcp__orders__refund", {"amount": "5"})]
    assert effects == ["T-1"]


def test_claude_pre_tool_use_denies_and_records_through_sdk_dispatch(token):
    pytest.importorskip("claude_agent_sdk")
    from claude_agent_sdk._internal.query import Query

    tools = ("Lookup", "Refund")
    with pytest.raises(pp.HarnessError, match="Lookpu"):
        claude_pre_tool_use(tools, reads=["Lookpu"])
    matcher = claude_pre_tool_use(tools, reads=["Lookup"])
    assert matcher.matcher is None and matcher.on_failure == "block"
    effects = []

    class Transport:
        async def write(self, message):
            self.response = json.loads(message)["response"]

    async def turn():
        transport = Transport()
        query = Query(transport=transport, is_streaming_mode=True)
        query.hook_callbacks["guard"] = matcher.hooks[0]
        results = []
        for name in (*tools, "FutureTool"):
            await query._handle_control_request(
                {
                    "type": "control_request",
                    "request_id": "request-1",
                    "request": {
                        "subtype": "hook_callback",
                        "callback_id": "guard",
                        "input": {"hook_event_name": "PreToolUse", "tool_name": name, "tool_input": {"order": "T-1"}},
                    },
                }
            )
            assert transport.response["subtype"] == "success"
            result = transport.response["response"].get("hookSpecificOutput", {})
            if result.get("permissionDecision") != "deny":
                effects.append(name)
            results.append(result)
        return results, pp.recorded_calls()

    assert asyncio.run(turn()) == ([{}, {}, {}], [])
    assert effects == ["Lookup", "Refund", "FutureTool"]
    effects.clear()
    (results, calls), _ = in_session(token, lambda: asyncio.run(turn()))
    assert results[0] == {}
    assert [result["permissionDecision"] for result in results[1:]] == ["deny", "deny"]
    assert all(result["permissionDecisionReason"] for result in results[1:])
    assert arguments(calls) == [("Refund", {"order": "T-1"}), ("FutureTool", {"order": "T-1"})]
    assert effects == ["Lookup"]


# -- after the third review --------------------------------------------------------------------


def test_a_partial_of_an_async_function_is_guarded_as_async(token):
    """On Python 3.11 inspect does not see through the partial; the stand-in must still be awaitable."""
    from functools import partial

    effects = []

    async def send_email(prefix, to):
        effects.append((prefix, to))
        return "sent"

    tools = guard({"send_email": partial(send_email, "re:")})
    assert asyncio.run(tools["send_email"]("qa@example.com")) == "sent" and effects == [("re:", "qa@example.com")]
    effects.clear()
    result, session = in_session(token, lambda: asyncio.run(tools["send_email"]("qa@example.com")))
    assert effects == [] and [c["tool"] for c in session.calls] == ["send_email"] and result == {"status": "ok"}


def test_a_claude_tool_call_that_arrives_outside_the_test_request_is_blocked_not_run(token, monkeypatch):
    """The SDK runs callbacks in the context of whoever connected the client. Connected at startup, a
    call made during a test has no session. It must not run for real in the middle of a test."""
    claude = pytest.importorskip("claude_agent_sdk")
    effects = []

    @claude.tool("refund", "Request a refund.", {"amount": int})
    async def request_refund(args):
        effects.append(args["amount"])
        return {"content": [{"type": "text", "text": "refunded"}]}

    (guarded,) = guard_claude_agent([request_refund], server_name="orders")
    matcher = claude_pre_tool_use(("Refund", "Lookup"), reads=["Lookup"])
    hook = matcher.hooks[0]

    async def outside():
        result = await guarded.handler({"amount": 5})
        refused = await hook({"tool_name": "Refund", "tool_input": {}}, "id-1", None)
        read = await hook({"tool_name": "Lookup", "tool_input": {}}, "id-2", None)
        return result, refused, read

    # No test anywhere in the process: everything runs as written.
    result, refused, read = asyncio.run(outside())
    assert effects == [5] and result["content"][0]["text"] == "refunded" and refused == {} and read == {}
    effects.clear()
    # A test request is in flight, but this call has no session.
    monkeypatch.setattr(pp, "_in_flight", 1)
    result, refused, read = asyncio.run(outside())
    assert effects == [] and result["is_error"] is True and "outside the test request" in result["content"][0]["text"]
    assert refused["hookSpecificOutput"]["permissionDecision"] == "deny" and read == {}
    assert "outside the test request" in refused["hookSpecificOutput"]["permissionDecisionReason"]
