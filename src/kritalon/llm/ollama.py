"""A ChatModel backed by a local Ollama server's non-streaming /api/chat endpoint.

Every failure — server unreachable, timeout, HTTP error, malformed body, empty
reply — raises ModelError with a message telling the user what to try next.
No other exception type escapes `complete`.
"""

from __future__ import annotations

import httpx

from kritalon.llm.base import ChatMessage, ModelError

_DEFAULT_HOST = "http://127.0.0.1:11434"


class OllamaModel:
    """A chat model served by Ollama. Satisfies the ChatModel protocol."""

    def __init__(
        self,
        model: str,
        host: str = _DEFAULT_HOST,
        temperature: float = 0.7,
        timeout_seconds: float = 120,
        seed: int | None = None,
        max_tokens: int = 600,
        transport: httpx.AsyncTransport | None = None,
    ) -> None:
        # The practice bots count as running in this process, which exempts them from
        # authorization. That only holds while their model is on this machine too.
        from kritalon.core.authorization import is_loopback_origin

        if not is_loopback_origin(host.rstrip("/")):
            raise ValueError(f"the Ollama server must be on this machine (localhost or 127.0.0.1), not {host!r}")
        self.model = model
        self.host = host.rstrip("/")
        self.temperature = temperature
        self.timeout_seconds = timeout_seconds
        self.seed = seed
        # A model asked to hex-encode its prompt can generate until the request times
        # out. A support bot has no reason to write that much, so replies are capped.
        self.max_tokens = max_tokens
        self._transport = transport
        self.name = f"ollama:{model}"

    async def complete(self, system: str, messages: list[ChatMessage]) -> str:
        payload = self._payload(system, messages)
        try:
            async with httpx.AsyncClient(
                transport=self._transport, timeout=httpx.Timeout(self.timeout_seconds)
            ) as client:
                response = await client.post(f"{self.host}/api/chat", json=payload)
        except httpx.TimeoutException as exc:
            raise ModelError(
                f"Timed out after {self.timeout_seconds:g}s talking to Ollama at {self.host} "
                f"({type(exc).__name__}). The model may still be loading; raise timeout_seconds "
                "or check that the server answers quickly (`ollama list` should be instant)."
            ) from exc
        except httpx.HTTPError as exc:
            raise ModelError(
                f"Could not reach Ollama at {self.host} ({type(exc).__name__}: {exc}). "
                "Is Ollama running there? Start it with `ollama serve` and check the host setting."
            ) from exc
        except Exception as exc:
            raise ModelError(
                f"Unexpected error talking to Ollama at {self.host}: {type(exc).__name__}: {exc}"
            ) from exc

        if response.status_code != 200:
            detail = _error_detail(response)
            if response.status_code == 404:
                raise ModelError(
                    f"Ollama at {self.host} returned HTTP 404 for model '{self.model}' ({detail}). "
                    f"The model is probably not pulled; run `ollama pull {self.model}`."
                )
            raise ModelError(
                f"Ollama at {self.host} returned HTTP {response.status_code}: {detail}"
            )
        return _extract_reply(response, self.host, self.model)

    async def fingerprint(self) -> dict[str, str]:
        """Model name, the digest of the weights actually served, and the sampling settings.

        A name such as "llama3.2" can be re-pulled to different weights, so the digest
        is what pins a result. Never raises; an unreachable server gives "unavailable".
        """
        digest = "unavailable"
        try:
            async with httpx.AsyncClient(transport=self._transport, timeout=httpx.Timeout(10)) as client:
                response = await client.get(f"{self.host}/api/tags")
            body: object = response.json() if response.status_code == 200 else None
            models = body.get("models") if isinstance(body, dict) else None
            for entry in models if isinstance(models, list) else []:
                if isinstance(entry, dict) and entry.get("name") in (self.model, f"{self.model}:latest"):
                    if isinstance(entry.get("digest"), str):
                        digest = entry["digest"]
                    break
        except Exception:
            pass
        return {
            "model": self.name,
            "digest": digest,
            "temperature": f"{self.temperature:g}",
            "max_tokens": str(self.max_tokens),
            "seed": "none" if self.seed is None else str(self.seed),
        }

    def _payload(self, system: str, messages: list[ChatMessage]) -> dict[str, object]:
        options: dict[str, object] = {"temperature": self.temperature, "num_predict": self.max_tokens}
        if self.seed is not None:
            options["seed"] = self.seed
        return {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, *messages],
            "stream": False,
            "options": options,
        }


def _error_detail(response: httpx.Response) -> str:
    """Best-effort human-readable detail from an error response. Never raises."""
    snippet = response.text.strip()[:300]
    try:
        body: object = response.json()
    except ValueError:
        return snippet if snippet else "(no body)"
    if isinstance(body, dict):
        error = body.get("error")
        if isinstance(error, str) and error.strip():
            return error.strip()
    return snippet if snippet else "(no body)"


def _extract_reply(response: httpx.Response, host: str, model: str) -> str:
    try:
        body: object = response.json()
    except ValueError as exc:
        snippet = response.text.strip()[:200]
        raise ModelError(
            f"Ollama at {host} replied with a body that is not valid JSON "
            f"(starts with: {snippet!r})."
        ) from exc
    if not isinstance(body, dict):
        raise ModelError(
            f"Ollama at {host} replied with JSON that is not an object "
            f"(got {type(body).__name__})."
        )
    message = body.get("message")
    if not isinstance(message, dict):
        raise ModelError(
            f"Ollama at {host} replied without a 'message' object; the body does not "
            "look like a /api/chat response."
        )
    content = message.get("content")
    if not isinstance(content, str):
        raise ModelError(
            f"Ollama at {host} replied with 'message.content' that is not a string."
        )
    if not content.strip():
        raise ModelError(
            f"Ollama at {host} returned an empty reply from model '{model}'. "
            "Try the same prompt with `ollama run` to see whether the model answers."
        )
    return content
