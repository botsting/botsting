"""Guard a Python bot's complete tool list during signed Promptproof sessions.

Developed against openai-agents 0.25.0, langchain-core 1.8.4, and
claude-agent-sdk 0.2.187. Framework imports are local to the adapters.
"""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable, Iterable, Mapping
from copy import copy
from dataclasses import replace
from functools import partial, wraps
from typing import TYPE_CHECKING, Any

from . import harness as pp

if TYPE_CHECKING:
    from agents import FunctionTool
    from claude_agent_sdk import HookMatcher, SdkMcpTool
    from langchain_core.tools import BaseTool


_STAND_IN = '{"status": "ok"}'
# The Claude SDK runs its callbacks in the context of whoever connected the client. If that was done at
# startup, not inside the wrapped request, a call made during a test arrives with no session. Running
# it as written would carry out a real action in the middle of a test, so it is blocked instead.
_OUTSIDE = (
    "Promptproof blocked this tool call: a test is in progress in this process, but the call arrived "
    "outside the test request. Connect the SDK client inside the wrapped request."
)


def _check_names(names: Iterable[str], configured: Iterable[str], option: str) -> frozenset[str]:
    configured = frozenset(configured)
    unknown = configured.difference(names)
    if unknown:
        raise pp.HarnessError(f"unknown tool names in {option}: {sorted(unknown)}")
    return configured


def guard(
    tools: Mapping[str, Callable[..., Any]],
    reads: Iterable[str] = (),
    *,
    results: Mapping[str, Any] | None = None,
    live: Mapping[str, pp.Cap] | None = None,
) -> dict[str, Callable[..., Any]]:
    """Return tools guarded by `pp.action`, with the given reads passed through.

    Stand-in values and synchronous result factories, and opt-in live caps, use
    the same semantics as the corresponding `pp.action` options.
    """
    reads = _check_names(tools, reads, "reads")
    results = dict(results or {})
    live = dict(live or {})
    _check_names(tools, results, "results")
    _check_names(tools, live, "live")
    return {
        name: function if name in reads else _guard_callable(name, function, results, live)
        for name, function in tools.items()
    }


def _guard_callable(name, function, results, live):
    options = {}
    if name in results:
        options["result"] = results[name]
    if name in live:
        options["live"] = live[name]

    target = function
    while isinstance(target, partial):
        target = target.func
    if not inspect.iscoroutinefunction(function) and (
        inspect.iscoroutinefunction(target) or inspect.iscoroutinefunction(target.__call__)
    ):
        # On Python 3.11 iscoroutinefunction does not recognize async callable instances,
        # or a partial of an async function.
        @wraps(function)
        async def invoke(*args, **kwargs):
            return await function(*args, **kwargs)

        return pp.action(name, **options)(invoke)
    return pp.action(name, **options)(function)


def _record(name: str, arguments: Mapping[str, Any], result: str) -> None:
    # Frameworks supply argument maps, with keys that need not be Python parameters.
    pp.record_call(name, arguments, result)


def _tool_reads(tools, tool_type, reads, name):
    if not all(isinstance(tool, tool_type) for tool in tools):
        raise pp.HarnessError(f"expected only {tool_type.__name__} instances")
    names = {name(tool) for tool in tools}
    if len(names) != len(tools):
        raise pp.HarnessError("tool names must be unique")
    return _check_names(names, reads, "reads")


def guard_agents(
    tools: Iterable[FunctionTool], reads: Iterable[str] = (),
) -> list[FunctionTool]:
    """Guard OpenAI Agents SDK function tools at their invocation callback."""
    from agents import FunctionTool

    tools = list(tools)
    reads = _tool_reads(tools, FunctionTool, reads, lambda tool: tool.qualified_name)

    def protect(tool):
        if callable(tool.needs_approval):
            # The SDK binds validation of arguments to the original invoker for callable
            # approval policies. Replacing it would change which arguments can skip approval.
            raise pp.HarnessError(f"{tool.qualified_name}: callable needs_approval is unsupported")
        guarded = copy(tool)
        original = guarded.on_invoke_tool

        @wraps(original)
        async def invoke(context, raw):
            if not pp.active():
                return await original(context, raw)
            try:
                parsed = json.loads(raw) if raw else {}
            except ValueError:
                parsed = raw
            arguments = parsed if isinstance(parsed, dict) else {"input": parsed}
            _record(tool.qualified_name, arguments, _STAND_IN)
            return _STAND_IN

        guarded.on_invoke_tool = invoke
        return guarded

    return [tool if tool.qualified_name in reads else protect(tool) for tool in tools]


def guard_langchain(
    tools: Iterable[BaseTool], reads: Iterable[str] = (),
) -> list[BaseTool]:
    """Guard LangChain and LangGraph BaseTools at their public invocation methods."""
    from langchain_core.messages import ToolMessage
    from langchain_core.tools import BaseTool

    tools = list(tools)
    reads = _tool_reads(tools, BaseTool, reads, lambda tool: tool.name)

    def protect(tool):
        guarded = tool.model_copy()
        injected = tool._injected_args_keys

        def stand_in(tool_input, tool_call_id):
            if isinstance(tool_input, dict):
                arguments = {key: value for key, value in tool_input.items() if key not in injected}
            else:
                arguments = {"input": tool_input}
            _record(tool.name, arguments, _STAND_IN)
            if tool_call_id is None:
                return _STAND_IN
            return ToolMessage(content=_STAND_IN, name=tool.name, tool_call_id=tool_call_id)

        @wraps(tool.run)
        def run(tool_input, *args, **kwargs):
            if pp.active():
                return stand_in(tool_input, kwargs.get("tool_call_id"))
            return tool.run(tool_input, *args, **kwargs)

        @wraps(tool.arun)
        async def arun(tool_input, *args, **kwargs):
            if pp.active():
                return stand_in(tool_input, kwargs.get("tool_call_id"))
            return await tool.arun(tool_input, *args, **kwargs)

        @wraps(tool.invoke)
        def invoke(*args, **kwargs):
            if pp.active():
                return BaseTool.invoke(guarded, *args, **kwargs)
            return tool.invoke(*args, **kwargs)

        @wraps(tool.ainvoke)
        async def ainvoke(*args, **kwargs):
            if pp.active():
                return await BaseTool.ainvoke(guarded, *args, **kwargs)
            return await tool.ainvoke(*args, **kwargs)

        # Preserve the original tool class, schema, metadata, and injected argument
        # declarations. Cover custom tools that override invoke/ainvoke as well.
        for name, method in {"run": run, "arun": arun, "invoke": invoke, "ainvoke": ainvoke}.items():
            object.__setattr__(guarded, name, method)
        return guarded

    return [tool if tool.name in reads else protect(tool) for tool in tools]


def guard_claude_agent(
    tools: Iterable[SdkMcpTool],
    reads: Iterable[str] = (),
    *,
    server_name: str | None = None,
) -> list[SdkMcpTool]:
    """Guard in-process Claude SDK MCP tools at their async handler.

    Select reads by definition name. Pass the configured MCP server name to
    record the full Claude tool name (`mcp__SERVER__TOOL`).
    """
    from claude_agent_sdk import SdkMcpTool

    tools = list(tools)
    reads = _tool_reads(tools, SdkMcpTool, reads, lambda tool: tool.name)

    def protect(tool):
        name = f"mcp__{server_name}__{tool.name}" if server_name else tool.name

        @wraps(tool.handler)
        async def handler(arguments):
            if not pp.active():
                if pp.tests_in_progress():
                    return {"content": [{"type": "text", "text": _OUTSIDE}], "is_error": True}
                return await tool.handler(arguments)
            _record(name, arguments, _STAND_IN)
            return {"content": [{"type": "text", "text": _STAND_IN}]}

        return replace(tool, handler=handler)

    return [tool if tool.name in reads else protect(tool) for tool in tools]


def claude_pre_tool_use(
    tool_names: Iterable[str], reads: Iterable[str] = (),
) -> HookMatcher:
    """Return a Claude SDK PreToolUse matcher that records and denies non-reads.

    Supply the known tool names as Claude reports them, including any MCP prefix.
    The matcher also denies newly encountered tools outside the read allowlist.
    Connect the SDK client inside the wrapped request so callbacks inherit its session.
    """
    from claude_agent_sdk import HookMatcher

    reads = _check_names(tool_names, reads, "reads")
    reason = "Promptproof recorded this tool call and blocked execution."

    async def hook(data, tool_use_id, context):
        if data["tool_name"] in reads or not (pp.active() or pp.tests_in_progress()):
            return {}
        why = reason
        if pp.active():
            _record(data["tool_name"], data["tool_input"], reason)
        else:
            why = _OUTSIDE  # no session to record in; never run it in the middle of a test
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": why,
            }
        }

    return HookMatcher(hooks=[hook], on_failure="block")
