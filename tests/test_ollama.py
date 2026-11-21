"""Tests for OllamaModel over httpx.MockTransport. No Ollama, no network."""

import asyncio
import json
from collections.abc import Callable

import httpx
import pytest

from promptproof.llm.base import ChatModel, ModelError
from promptproof.llm.ollama import OllamaModel

Handler = Callable[[httpx.Request], httpx.Response]


def make_model(handler: Handler, **kwargs: object) -> tuple[OllamaModel, list[httpx.Request]]:
    requests: list[httpx.Request] = []

    def recording_handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return handler(request)

    transport: httpx.AsyncTransport = httpx.MockTransport(recording_handler)
    model = OllamaModel("llama3", transport=transport, **kwargs)  # type: ignore[arg-type]
    return model, requests


def ok_reply(content: str) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"message": {"role": "assistant", "content": content}, "done": True})

    return handler


def complete(model: OllamaModel, system: str = "You are a toy agent.") -> str:
    messages: list = [{"role": "user", "content": "hi"}]
    return asyncio.run(model.complete(system, messages))


# --- success and request shape -------------------------------------------------


def test_satisfies_chat_model_protocol() -> None:
    model, _ = make_model(ok_reply("Hello there"))
    subject: ChatModel = model
    assert subject.name == "ollama:llama3"


def test_success_returns_reply_text() -> None:
    model, _ = make_model(ok_reply("Hello there"))
    assert complete(model) == "Hello there"


def test_request_shape() -> None:
    model, requests = make_model(ok_reply("ok"))
    system = "You are a toy agent."
    turns: list = [
        {"role": "user", "content": "q1"},
        {"role": "assistant", "content": "a1"},
        {"role": "user", "content": "q2"},
    ]
    asyncio.run(model.complete(system, turns))
    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert str(request.url) == "http://127.0.0.1:11434/api/chat"
    assert request.headers["content-type"] == "application/json"
    body = json.loads(request.content)
    assert body["model"] == "llama3"
    assert body["stream"] is False
    assert body["messages"][0] == {"role": "system", "content": system}
    assert body["messages"][1:] == turns
    assert body["options"]["temperature"] == 0.7
    assert "seed" not in body["options"]


def test_seed_included_when_set() -> None:
    model, requests = make_model(ok_reply("ok"), seed=42)
    asyncio.run(model.complete("sys", []))
    body = json.loads(requests[0].content)
    assert body["options"]["seed"] == 42
    assert body["messages"] == [{"role": "system", "content": "sys"}]


def test_host_trailing_slash_stripped() -> None:
    model, requests = make_model(ok_reply("ok"), host="http://127.0.0.1:11434/")
    asyncio.run(model.complete("sys", []))
    assert str(requests[0].url) == "http://127.0.0.1:11434/api/chat"


# --- failures: every kind must surface as ModelError and nothing else ----------


def test_connection_refused_is_model_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused", request=request)

    model, _ = make_model(handler)
    with pytest.raises(ModelError, match="Could not reach Ollama"):
        complete(model)


def test_timeout_is_model_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    model, _ = make_model(handler)
    with pytest.raises(ModelError, match="Timed out after 120s"):
        complete(model)


def test_404_suggests_pull() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "model 'llama3' not found, try pulling it first"})

    model, _ = make_model(handler)
    with pytest.raises(ModelError) as excinfo:
        complete(model)
    message = str(excinfo.value)
    assert "404" in message
    assert "ollama pull llama3" in message


def test_http_500_is_model_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    model, _ = make_model(handler)
    with pytest.raises(ModelError, match="HTTP 500"):
        complete(model)


def test_malformed_json_body_is_model_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="this is not json")

    model, _ = make_model(handler)
    with pytest.raises(ModelError, match="not valid JSON"):
        complete(model)


def test_body_without_message_object_is_model_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"done": True})

    model, _ = make_model(handler)
    with pytest.raises(ModelError, match="message"):
        complete(model)


def test_non_string_content_is_model_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"message": {"role": "assistant", "content": 42}})

    model, _ = make_model(handler)
    with pytest.raises(ModelError, match="content"):
        complete(model)


def test_empty_reply_is_model_error() -> None:
    model, _ = make_model(ok_reply("   "))
    with pytest.raises(ModelError, match="empty reply"):
        complete(model)


def test_json_array_body_is_model_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[1, 2, 3])

    model, _ = make_model(handler)
    with pytest.raises(ModelError, match="not an object"):
        complete(model)


def test_unexpected_transport_error_is_wrapped() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise RuntimeError("boom")

    model, _ = make_model(handler)
    with pytest.raises(ModelError, match="boom"):
        complete(model)


def test_fingerprint_reports_the_served_digest_and_settings() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/tags"
        return httpx.Response(200, json={"models": [{"name": "other:latest", "digest": "aaa"}, {"name": "llama3.2:latest", "digest": "abc123"}]})

    model = OllamaModel("llama3.2", temperature=0.2, seed=7, transport=httpx.MockTransport(handler))
    assert asyncio.run(model.fingerprint()) == {
        "model": "ollama:llama3.2",
        "digest": "abc123",
        "temperature": "0.2",
        "max_tokens": "600",
        "seed": "7",
    }


def test_fingerprint_never_raises() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    for transport in (httpx.MockTransport(refuse), httpx.MockTransport(lambda r: httpx.Response(500, text="oops"))):
        fingerprint = asyncio.run(OllamaModel("llama3.2", transport=transport).fingerprint())
        assert fingerprint["digest"] == "unavailable" and fingerprint["model"] == "ollama:llama3.2"
