"""The interface a chat model must offer to be used inside a toy target."""

from __future__ import annotations

from typing import Protocol, TypedDict


class ChatMessage(TypedDict):
    role: str  # "user" or "assistant"
    content: str


class ChatModel(Protocol):
    """A chat model: system text plus conversation in, one reply out."""

    name: str

    async def complete(self, system: str, messages: list[ChatMessage]) -> str:
        """Return the assistant's next message. Raise ModelError on failure."""
        ...


class ModelError(RuntimeError):
    """The model could not produce a reply (unreachable, timed out, bad response)."""
