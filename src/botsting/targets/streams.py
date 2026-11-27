"""Reading a reply that a bot streams, piece by piece, instead of sending as one JSON answer.

The scanner waits for the stream to end, then puts the pieces of text together. What it gives
back is a `Streamed` value, a dict with:

    text      the whole reply, joined in order
    events    what arrived, parsed, in order (for a pointer into them, such as a conversation id)
    streamed  which form it had: "sse", "ndjson" or "data-stream"
    kinds     the kinds of event seen, most frequent first (said when no text was recognised)

so the reply of a streamed bot is always at the pointer `/text`.

Forms read:

- Server-sent events (`text/event-stream`): `data:` lines, with or without `event:` names.
- Lines of JSON (`application/x-ndjson`, `application/jsonl`, or a body that is nothing but
  JSON objects, one per line).
- The Vercel AI SDK data stream (`0:"text"` lines).

Shapes of a piece that are recognised: OpenAI chat completions (`choices[].delta.content`),
OpenAI responses (`response.output_text.delta`), Anthropic messages (`content_block_delta`),
the Vercel AI SDK (`text-delta`), Ollama (`message.content`, `response`), a bare string, and an
object with the text under one of the usual names (`delta`, `token`, `content`, `text`, `chunk`,
`answer`, `output`). An event whose kind is not one of text is skipped, so a tool call or a
"done" event that carries words of its own is not mistaken for the reply.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any

_TEXT_KEYS = ("delta", "token", "content", "text", "chunk", "answer", "output")
# Event kinds whose data is a piece of the reply. Anything else that names its kind is skipped.
_TEXT_KINDS = frozenset(
    {
        "",
        "message",  # the default name of a server-sent event
        "text",
        "text-delta",
        "text_delta",
        "token",
        "delta",
        "chunk",
        "content",
        "answer",
        "output_text",
        "content_block_delta",
        "response.output_text.delta",
        "on_chat_model_stream",
        "data",
    }
)
_ERROR_KINDS = frozenset({"error", "response.error", "response.failed"})
_DATA_STREAM_LINE = re.compile(r"^([0-9a-z]):(.*)$")
_NDJSON_TYPES = ("ndjson", "jsonl", "x-json-stream", "stream+json", "json-seq")


class StreamError(Exception):
    """The stream itself reported a failure, or could not be read."""


class Streamed(dict):  # type: ignore[type-arg]
    """A streamed answer, put together. See the module notes for its keys."""

    def unreadable(self) -> str:
        """What to tell the person when no text was recognised in the stream."""
        seen = ", ".join(self["kinds"][:6]) or "none"
        return (
            f"the bot streamed its answer ({self['streamed']}), but no text was recognised in it. Kinds of event seen: {seen}. "
            "If the bot can answer without streaming during a test, the scan will work; and please tell us the format, so we can read it"
        )


def _text_under(value: Any) -> str:
    """The text in `value`: a string, or an object holding one under a usual name (one level down too)."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in _TEXT_KEYS:
            inner = value.get(key)
            if isinstance(inner, str):
                return inner
        for key in ("delta", "message", "data"):
            inner = value.get(key)
            if isinstance(inner, dict):
                for name in ("text", "content"):
                    if isinstance(inner.get(name), str):
                        return inner[name]
    return ""


def _error_text(payload: Any) -> str:
    """What an error event says, wherever it keeps its words."""
    if isinstance(payload, str):
        return payload
    if isinstance(payload, dict):
        for key in ("message", "error", "detail", "errorText", "text"):
            inner = payload.get(key)
            if isinstance(inner, str) and inner:
                return inner
            if isinstance(inner, dict):
                found = _error_text(inner)
                if found:
                    return found
    return ""


def _kind(name: str, payload: Any) -> str:
    if isinstance(payload, dict):
        for key in ("type", "event"):
            if isinstance(payload.get(key), str):
                return payload[key]
    return name


def piece(name: str, payload: Any) -> str:
    """The piece of reply text in one event, or "" when the event is not text."""
    kind = _kind(name, payload)
    if isinstance(payload, dict):
        choices = payload.get("choices")
        if isinstance(choices, list):  # OpenAI chat completions
            parts = []
            for choice in choices:
                delta = choice.get("delta") if isinstance(choice, dict) else None
                if isinstance(delta, dict) and isinstance(delta.get("content"), str):
                    parts.append(delta["content"])
            return "".join(parts)
        if kind == "content_block_delta":  # Anthropic messages
            delta = payload.get("delta")
            return delta["text"] if isinstance(delta, dict) and isinstance(delta.get("text"), str) else ""
        if kind not in _TEXT_KINDS and name not in _TEXT_KINDS - {""}:
            return ""
        if isinstance(payload.get("done"), bool) or "message" in payload or "response" in payload:  # Ollama
            message = payload.get("message")
            if isinstance(message, dict) and isinstance(message.get("content"), str):
                return message["content"]
            if isinstance(payload.get("response"), str):
                return payload["response"]
        return _text_under(payload)
    if kind not in _TEXT_KINDS:
        return ""
    return payload if isinstance(payload, str) else ""


def _events_sse(text: str) -> list[tuple[str, Any]]:
    """(event name, data) for each server-sent event. Data that is JSON is parsed; other data stays text."""
    events: list[tuple[str, Any]] = []
    name, lines = "", []

    def flush() -> None:
        nonlocal name, lines
        if lines:
            raw = "\n".join(lines)
            if raw.strip() != "[DONE]":
                events.append((name, _parsed(raw)))
        name, lines = "", []

    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if not line:
            flush()
        elif line.startswith(":"):
            continue  # a comment, often a keep-alive
        else:
            field, _, value = line.partition(":")
            value = value[1:] if value.startswith(" ") else value
            if field == "data":
                lines.append(value)
            elif field == "event":
                name = value.strip()
    flush()
    return events


def _parsed(raw: str) -> Any:
    """JSON objects, lists and strings are parsed. Anything else (a bare word, a number) is the text itself."""
    stripped = raw.strip()
    if stripped[:1] in ('{', '[', '"'):
        try:
            return json.loads(stripped)
        except ValueError:
            return raw
    return raw


def _events_lines(text: str) -> list[tuple[str, Any]] | None:
    """Events from a body that is one JSON object per line, or None if it is not that."""
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return None
    events: list[tuple[str, Any]] = []
    for line in lines:
        try:
            value = json.loads(line.lstrip("\x1e"))
        except ValueError:
            return None
        if not isinstance(value, dict):
            return None
        events.append(("", value))
    return events


def _events_data_stream(text: str, declared: bool) -> list[tuple[str, Any]] | None:
    """Events from the Vercel AI SDK data stream (`0:"text"`), or None if the body is not one."""
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return None
    events: list[tuple[str, Any]] = []
    for line in lines:
        match = _DATA_STREAM_LINE.match(line)
        if not match:
            return None
        try:
            value = json.loads(match.group(2))
        except ValueError:
            return None
        # "0" is a piece of text and "3" an error; the other codes are data, tool calls and the end.
        events.append(({"0": "text", "3": "error"}.get(match.group(1), f"part-{match.group(1)}"), value))
    # Not named as one by the bot: take it for a data stream only if it has a piece of text in it.
    return events if declared or any(name == "text" for name, _ in events) else None


def read_stream(content_type: str, body: bytes, declared: bool = False) -> Streamed | None:
    """`body` as a streamed answer, or None when it is not one (an ordinary JSON or text answer).

    `declared` says the response named itself a data stream in a header. Raises StreamError when
    the stream reports a failure and carries no reply text."""
    kind = content_type.split(";")[0].strip().lower()
    text = body.decode("utf-8", "replace")
    events: list[tuple[str, Any]] | None
    if kind == "text/event-stream":
        form, events = "sse", _events_sse(text)
    elif any(name in kind for name in _NDJSON_TYPES):
        form, events = "ndjson", _events_lines(text)
    elif declared or (kind in ("", "text/plain") and re.match(r'[0-9a-z]:["\[{]', text.lstrip())):
        form, events = "data-stream", _events_data_stream(text, declared)
    elif kind in ("", "text/plain", "application/octet-stream") and text.lstrip().startswith("{") and "\n" in text.strip():
        form, events = "ndjson", _events_lines(text)
        if events is not None and len(events) < 2:
            events = None
    else:
        return None
    if events is None:
        return None
    parts: list[str] = []
    kinds: Counter[str] = Counter()
    errors: list[str] = []
    for name, payload in events:
        found_kind = _kind(name, payload)
        kinds[found_kind or "(unnamed)"] += 1
        if found_kind in _ERROR_KINDS or name in _ERROR_KINDS:
            errors.append(_error_text(payload) or json.dumps(payload)[:200])
            continue
        found = piece(name, payload)
        # Some bots end with the whole reply once more. Taking it would say everything twice.
        if found and len(parts) > 1 and found == "".join(parts):
            continue
        parts.append(found)
    joined = "".join(parts)
    if errors and not joined.strip():
        raise StreamError(f"the bot's stream reported an error: {errors[0][:300]}")
    return Streamed(
        text=joined,
        events=[payload for _, payload in events][:2000],
        streamed=form,
        kinds=[name for name, _ in kinds.most_common()],
    )
