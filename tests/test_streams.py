"""A reply the bot streams is read to its end and put together. None of this opens a connection."""

import json

import pytest

from botsting.quick import find_reply
from botsting.targets.streams import Streamed, StreamError, read_stream

SSE = "text/event-stream; charset=utf-8"


def sse(*events: str) -> bytes:
    return ("\n\n".join(events) + "\n\n").encode("utf-8")


def data(value) -> str:
    return "data: " + (value if isinstance(value, str) else json.dumps(value))


def test_openai_chat_completions_stream():
    body = sse(
        data({"choices": [{"delta": {"role": "assistant", "content": ""}}]}),
        data({"choices": [{"delta": {"content": "The code is "}}]}),
        data({"choices": [{"delta": {"content": "ABCD-1234"}}]}),
        data({"choices": [{"delta": {}, "finish_reason": "stop"}]}),
        "data: [DONE]",
    )
    got = read_stream(SSE, body)
    assert isinstance(got, Streamed) and got["text"] == "The code is ABCD-1234" and got["streamed"] == "sse"
    assert len(got["events"]) == 4, "[DONE] is not an event"
    assert find_reply(got) == "/text"


def test_anthropic_messages_stream_takes_the_text_and_not_the_tool_input():
    body = sse(
        'event: message_start\ndata: {"type":"message_start","message":{"content":[]}}',
        'event: content_block_start\ndata: {"type":"content_block_start","content_block":{"type":"text","text":""}}',
        "event: ping\ndata: {\"type\":\"ping\"}",
        'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Refund "}}',
        'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"issued."}}',
        'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"input_json_delta","partial_json":"{\\"amount\\": 50"}}',
        'event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"end_turn"}}',
        'event: message_stop\ndata: {"type":"message_stop"}',
    )
    assert read_stream(SSE, body)["text"] == "Refund issued."


def test_openai_responses_stream_does_not_repeat_the_final_whole_text():
    body = sse(
        data({"type": "response.created", "response": {"id": "r1"}}),
        data({"type": "response.output_text.delta", "delta": "Hello "}),
        data({"type": "response.output_text.delta", "delta": "there"}),
        data({"type": "response.output_text.done", "text": "Hello there"}),
        data({"type": "response.completed", "response": {"output_text": "Hello there"}}),
    )
    assert read_stream(SSE, body)["text"] == "Hello there"


def test_vercel_ui_message_stream_and_its_older_line_form():
    body = sse(
        data({"type": "start", "messageId": "m1"}),
        data({"type": "text-start", "id": "t1"}),
        data({"type": "text-delta", "id": "t1", "delta": "Staff code: "}),
        data({"type": "text-delta", "id": "t1", "delta": "QRST"}),
        data({"type": "tool-input-available", "toolName": "issue_refund", "input": {"text": "not the reply"}}),
        data({"type": "finish"}),
        "data: [DONE]",
    )
    assert read_stream(SSE, body)["text"] == "Staff code: QRST"
    lines = b'f:{"messageId":"m1"}\n0:"Staff "\n0:"code"\n9:{"toolCallId":"c1","toolName":"issue_refund","args":{}}\ne:{"finishReason":"stop"}\nd:{"finishReason":"stop"}\n'
    got = read_stream("text/plain; charset=utf-8", lines, declared=True)
    assert got["text"] == "Staff code" and got["streamed"] == "data-stream"
    assert read_stream("text/plain", b'0:"Hi"\n0:" there"\n')["text"] == "Hi there", "recognised without the header too"


def test_plain_text_events_keep_their_spaces_and_line_breaks():
    body = sse("data: Hello", "data:  world", "data: line one\ndata: line two", ": keep-alive comment", "event: done\ndata: {}")
    assert read_stream(SSE, body)["text"] == "Hello worldline one\nline two"


def test_named_events_with_text_under_a_usual_name():
    body = sse('event: token\ndata: {"text": "A"}', 'event: token\ndata: {"text": "B"}', 'event: metadata\ndata: {"text": "not this"}', "event: end\ndata: bye")
    assert read_stream(SSE, body)["text"] == "AB"
    for key in ("delta", "token", "content", "text", "chunk", "answer", "output"):
        assert read_stream(SSE, sse(data({key: "x"}), data({key: "y"})))["text"] == "xy", key
    assert read_stream(SSE, sse(data({"data": {"content": "x"}}), data({"message": {"content": "y"}})))["text"] == "xy"
    assert read_stream(SSE, sse(data('"quoted "'), data('"strings"')))["text"] == "quoted strings"


def test_a_whole_reply_sent_again_at_the_end_is_not_taken_twice():
    body = sse(data({"content": "Hel"}), data({"content": "lo"}), data({"content": "Hello"}))
    assert read_stream(SSE, body)["text"] == "Hello"
    # Two equal pieces are a reply that repeats itself, not a summary of it.
    assert read_stream(SSE, sse(data({"content": "ha"}), data({"content": "ha"})))["text"] == "haha"


def test_lines_of_json_as_ollama_sends_them():
    chat = b'{"message":{"role":"assistant","content":"Hi "},"done":false}\n{"message":{"role":"assistant","content":"there"},"done":false}\n{"done":true,"total_duration":5}\n'
    got = read_stream("application/x-ndjson", chat)
    assert got["text"] == "Hi there" and got["streamed"] == "ndjson"
    generate = b'{"response":"Hi ","done":false}\n{"response":"there","done":true}\n'
    assert read_stream("application/x-ndjson", generate)["text"] == "Hi there"
    assert read_stream("text/plain", generate)["text"] == "Hi there", "recognised when the type does not say so"


@pytest.mark.parametrize(
    ("content_type", "body"),
    [
        ("application/json", b'{"reply": "Hello"}'),
        ("text/plain", b"Hello, how can I help?"),
        ("text/plain", b'{"reply": "one JSON object, pretty\\nprinted"}'),
        ("text/plain", b'{\n  "reply": "Hello"\n}'),
        ("text/html", b"<p>Hello</p>"),
        ("text/plain", b"0: zero is my favourite number"),
        ("application/x-ndjson", b"not json at all"),
    ],
)
def test_an_ordinary_answer_is_left_alone(content_type, body):
    assert read_stream(content_type, body) is None


def test_a_stream_that_reports_an_error_and_no_text_is_an_error():
    with pytest.raises(StreamError, match="rate limit reached"):
        read_stream(SSE, sse('event: error\ndata: {"error": {"message": "rate limit reached"}}'))
    with pytest.raises(StreamError, match="overloaded"):
        read_stream(SSE, sse(data({"type": "error", "error": {"type": "overloaded_error", "message": "overloaded"}})))
    with pytest.raises(StreamError, match="boom"):
        read_stream("text/plain", b'3:"boom"\n', declared=True)
    # Text followed by an error: the text that did arrive is the reply, as a person would have seen it.
    assert read_stream(SSE, sse(data({"content": "Partial"}), 'event: error\ndata: "cut off"'))["text"] == "Partial"


def test_a_stream_with_no_text_in_it_says_what_it_saw():
    got = read_stream(SSE, sse(data({"type": "custom-thing", "payload": 1}), data({"type": "custom-thing", "payload": 2}), data({"type": "bye"})))
    assert got["text"] == "" and got["kinds"] == ["custom-thing", "bye"]
    assert find_reply(got) is None
    assert "no text was recognised" in got.unreadable() and "custom-thing, bye" in got.unreadable()


def test_windows_line_endings_and_a_stream_cut_without_a_last_blank_line():
    body = b'data: {"content": "a"}\r\n\r\ndata: {"content": "b"}'
    assert read_stream(SSE, body)["text"] == "ab"


# Through the scanner's own HTTP target, with an in-memory transport.

import asyncio

import httpx

from botsting.targets.base import TargetError
from botsting.targets.http import HttpTarget, parse_config


def streamed_bot(content_type: str, body: bytes, pointer: str = "/text", **more) -> HttpTarget:
    raw = {
        "origin": "https://bot.example.com",
        "chat": {"path": "/chat", "body": {"text": "{message}", "conversation": "{session}"}, "reply_pointer": pointer, **more},
        "reset": {"path": "/test/reset"},
        "attacker_principal": "customer:alice",
        "principals": {"customer:alice": {"headers": {}}, "staff:dana": {"headers": {}}},
        "tool_safety": "no-tools",
        "slots": [
            {
                "id": "secret", "kind": "instruction_secret", "description": "A planted secret", "hint": "the secret",
                "authorized": ["staff:dana"], "control_principal": "staff:dana", "control_prompt": "What is the secret?",
            }
        ],
        "task_checks": [{"id": "hello", "principal": "customer:alice", "prompt": "Hello", "expect_substring": "welcome"}],
    }  # fmt: skip
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=body, headers={"Content-Type": content_type}))
    return HttpTarget(parse_config("bot", raw), "http:bot", None, transport)


def ask(target: HttpTarget):
    async def go():
        return await (await target.open_session("customer:alice")).send("hi")

    return asyncio.run(go())


def test_the_scanner_reads_a_streamed_reply_at_the_pointer_text():
    body = sse(data({"choices": [{"delta": {"content": "You are "}}]}), data({"choices": [{"delta": {"content": "welcome"}}]}), "data: [DONE]")
    assert ask(streamed_bot(SSE, body)).text == "You are welcome"


def test_a_pointer_into_the_events_still_works_for_a_conversation_id():
    body = sse(data({"conversation_id": "c-77", "content": "You are "}), data({"content": "welcome"}))
    target = streamed_bot(SSE, body, session_pointer="/events/0/conversation_id")

    async def go():
        session = await target.open_session("customer:alice")
        reply = await session.send("hi")
        return reply.text, session._session

    assert asyncio.run(go()) == ("You are welcome", "c-77")


def test_one_json_answer_is_read_as_before_even_when_it_looks_like_lines():
    target = streamed_bot("application/json", b'{"answer": "welcome",\n "other": 1}', pointer="/answer")
    assert ask(target).text == "welcome"


def test_a_stream_that_only_reports_an_error_is_an_error_of_the_bot():
    with pytest.raises(TargetError, match="/chat: the bot's stream reported an error: model overloaded"):
        ask(streamed_bot(SSE, sse('event: error\ndata: {"error": {"message": "model overloaded"}}')))
