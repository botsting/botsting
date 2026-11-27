"""A chat model that can call tools: what BotSting needs from one.

Used when BotSting itself plays the assistant, for example against an MCP server: the
model is given the server's tools and an ordinary request, and BotSting records which
tools it asks for.

The model never runs a tool. It asks; the caller decides what happens and hands back a
result. A conversation keeps its own history, in whatever form its provider needs.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

# Why the model stopped: it answered, it asked for tools, its reply was cut off at the
# length limit, or it declined to continue.
Ended = Literal["answer", "tools", "cut-off", "declined"]


@dataclass(frozen=True)
class ToolSpec:
    """A tool as the model is told about it."""

    name: str
    description: str
    schema: Mapping[str, Any]  # JSON Schema of the arguments


@dataclass(frozen=True)
class ToolRequest:
    """The model asking for one tool call."""

    id: str
    name: str
    arguments: Mapping[str, Any]


@dataclass(frozen=True)
class ToolOutcome:
    """What the model is told came of a call it asked for."""

    id: str  # the request's id
    text: str
    failed: bool = False


@dataclass(frozen=True)
class Step:
    """One turn of the model: what it said, what it asked for, and what it cost."""

    text: str
    requests: tuple[ToolRequest, ...] = ()
    ended: Ended = "answer"
    input_tokens: int = 0
    output_tokens: int = 0
    detail: str = field(default="", compare=False)  # for "declined": the provider's reason, when it gives one


class ToolConversation(Protocol):
    async def say(self, text: str) -> Step:
        """The user says something. Raise ModelError on failure."""
        ...

    async def give(self, outcomes: Sequence[ToolOutcome]) -> Step:
        """Hand back one outcome for every tool the last step asked for. Raise ModelError on failure."""
        ...


class ToolModel(Protocol):
    name: str

    def converse(self, system: str, tools: Sequence[ToolSpec]) -> ToolConversation:
        """Start a conversation with these instructions and these tools on offer."""
        ...

    async def fingerprint(self) -> dict[str, str]:
        """What identifies this model and its settings. Must not raise."""
        ...
