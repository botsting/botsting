"""Claude as the assistant that is offered tools, through Anthropic's own SDK.

    pip install "botsting[anthropic]"

The key is read by the SDK from the environment (ANTHROPIC_API_KEY, or a profile made with
`ant auth login`). BotSting never reads it, stores it or prints it.

Three choices made here on purpose:

- No fallback to another model. This is a test instrument: a result must belong to the
  model that was named, so when that model declines, the step says so and stops.
- The instructions and the tool list are marked for caching. They are the same in every
  request of a scan and, with a large tool list, most of each request.
- Thinking and effort are left at the model's defaults, which is how most assistants run it.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from botsting.llm.base import ModelError
from botsting.llm.tools import Step, ToolOutcome, ToolRequest, ToolSpec

MAX_TOKENS = 16000


def _client() -> Any:
    try:
        import anthropic
    except ImportError as exc:
        raise ModelError('the Anthropic SDK is not installed; install it with: pip install "botsting[anthropic]"') from exc
    return anthropic.AsyncAnthropic()


def _explain(exc: Exception) -> str:
    """One line about a failed request. Never the request, and never anything from the environment."""
    try:
        import anthropic
    except ImportError:
        return type(exc).__name__
    if isinstance(exc, anthropic.AuthenticationError | anthropic.PermissionDeniedError):
        return "the key was refused, or may not use this model"
    if isinstance(exc, anthropic.NotFoundError):
        return "no such model"
    if isinstance(exc, anthropic.RateLimitError):
        return "the rate limit was reached, also after retries"
    if isinstance(exc, anthropic.APIStatusError):
        return f"the API answered {exc.status_code}"
    if isinstance(exc, anthropic.APIConnectionError):
        return "the API could not be reached"
    return type(exc).__name__


class ClaudeToolModel:
    def __init__(self, model: str, client: Any = None, max_tokens: int = MAX_TOKENS) -> None:
        if not model:
            raise ModelError("name the model, for example anthropic:claude-haiku-5-5")
        self.model = model
        self.name = f"anthropic:{model}"
        self._client = client
        self._max_tokens = max_tokens

    def client(self) -> Any:
        if self._client is None:
            self._client = _client()
        return self._client

    def converse(self, system: str, tools: Sequence[ToolSpec]) -> ClaudeConversation:
        return ClaudeConversation(self, system, tools)

    async def fingerprint(self) -> dict[str, str]:
        return {"provider": "anthropic", "model": self.model, "max_tokens": str(self._max_tokens)}


class ClaudeConversation:
    def __init__(self, model: ClaudeToolModel, system: str, tools: Sequence[ToolSpec]) -> None:
        self._model = model
        # Tools come before the instructions in what the API reads, so one mark on the
        # instructions covers both.
        self._system = [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]
        self._tools = [{"name": tool.name, "description": tool.description, "input_schema": dict(tool.schema)} for tool in tools]
        self._messages: list[dict[str, Any]] = []

    async def say(self, text: str) -> Step:
        self._messages.append({"role": "user", "content": text})
        return await self._step()

    async def give(self, outcomes: Sequence[ToolOutcome]) -> Step:
        # Every outcome goes back in one message: splitting them teaches the model to stop asking for several at once.
        self._messages.append(
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": outcome.id, "content": outcome.text, **({"is_error": True} if outcome.failed else {})}
                    for outcome in outcomes
                ],
            }
        )
        return await self._step()

    async def _step(self) -> Step:
        try:
            response = await self._model.client().messages.create(
                model=self._model.model,
                max_tokens=self._model._max_tokens,
                system=self._system,
                tools=self._tools,
                messages=self._messages,
            )
        except ModelError:
            raise
        except Exception as exc:
            raise ModelError(f"{self._model.name}: {_explain(exc)}") from exc
        content = list(response.content or [])
        usage = response.usage
        spent = {
            "input_tokens": sum(
                int(getattr(usage, part, 0) or 0) for part in ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")
            ),
            "output_tokens": int(getattr(usage, "output_tokens", 0) or 0),
        }
        text = "\n".join(block.text for block in content if block.type == "text" and block.text).strip()
        if response.stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            return Step(text, ended="declined", detail=str(getattr(details, "category", "") or ""), **spent)
        # The whole content goes back as it came, thinking blocks included: the API needs them unchanged.
        self._messages.append({"role": "assistant", "content": content})
        requests = tuple(ToolRequest(block.id, block.name, dict(block.input or {})) for block in content if block.type == "tool_use")
        if response.stop_reason == "max_tokens":
            return Step(text, ended="cut-off", **spent)
        if requests:
            return Step(text, requests, "tools", **spent)
        return Step(text, **spent)
