"""A small client for an MCP server reached over HTTP (the "streamable HTTP" transport).

It does what a scan needs and no more: start a session, list the tools, call one.

It keeps the rules of the HTTP connector: requests go only to the described origin and
path, redirects are not followed, proxy settings are ignored, an answer is read up to a
fixed size, and a header written as `${NAME}` is read from the environment when it is
sent and appears in no error.

The server may answer a request with one JSON message or with a stream of events that
holds it. Both are read. Anything the server asks of the client in such a stream is left
unanswered: this client offers no abilities of its own.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import httpx

from botsting.targets.base import TargetError
from botsting.targets.http import _env, _OnlyHere

# Versions of the protocol this client can speak, newest first. The first is offered.
VERSIONS = ("2025-06-18", "2025-11-25", "2025-03-26")
MAX_ANSWER_BYTES = 4_000_000
MAX_RESULT_CHARS = 100_000
MAX_TOOLS = 1000
_SESSION = "Mcp-Session-Id"
_EVENT_BREAK = re.compile(r"\r\n\r\n|\n\n|\r\r")


class McpError(TargetError):
    """The server could not be reached, or did not answer as an MCP server does."""


@dataclass(frozen=True)
class McpTool:
    name: str
    description: str
    schema: Mapping[str, Any]
    # What the server says about the tool. A server may leave these out or get them wrong.
    read_only: bool = False
    destructive: bool | None = None


@dataclass(frozen=True)
class McpResult:
    text: str
    failed: bool = False


def _events(text: str) -> list[Any]:
    """The JSON messages in a stream of server-sent events."""
    found: list[Any] = []
    for event in _EVENT_BREAK.split(text):
        lines = [line[5:].removeprefix(" ") for line in re.split(r"\r\n|\n|\r", event) if line.startswith("data:")]
        if not lines:
            continue
        try:
            found.append(json.loads("\n".join(lines)))
        except ValueError:
            continue  # a keep-alive or something that is not a message
    return found


def _result_text(result: Mapping[str, Any]) -> str:
    parts: list[str] = []
    content = result.get("content")
    for item in content if isinstance(content, list) else []:
        if not isinstance(item, Mapping):
            continue
        if item.get("type") == "text" and isinstance(item.get("text"), str):
            parts.append(item["text"])
        elif item.get("type") == "resource" and isinstance(item.get("resource"), Mapping) and isinstance(item["resource"].get("text"), str):
            parts.append(item["resource"]["text"])
        else:
            parts.append(f"[{item.get('type', 'content')} left out]")
    if not parts and result.get("structuredContent") is not None:
        parts.append(json.dumps(result["structuredContent"], ensure_ascii=False))
    text = "\n".join(parts)
    if len(text) > MAX_RESULT_CHARS:
        text = text[:MAX_RESULT_CHARS] + f"\n[cut after {MAX_RESULT_CHARS} characters]"
    return text


class McpClient:
    def __init__(
        self,
        origin: str,
        path: str,
        headers: Mapping[str, str] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 60.0,
    ) -> None:
        self._url = origin + path
        self._path = path
        self._headers = dict(headers or {})
        self._transport = _OnlyHere(origin, frozenset({path}), transport or httpx.AsyncHTTPTransport(retries=0))
        self._timeout = timeout
        self._next_id = 0
        self._session = ""
        self._version = ""
        self.server: dict[str, str] = {}

    async def _send(self, message: Mapping[str, Any]) -> tuple[bytes, httpx.Headers]:
        headers = {"User-Agent": "botsting-scan", "Accept": "application/json, text/event-stream"}
        headers.update({name: _env(value) for name, value in self._headers.items()})
        if self._session:
            headers[_SESSION] = self._session
        if self._version:
            headers["MCP-Protocol-Version"] = self._version
        what = str(message.get("method", "a message"))
        async with httpx.AsyncClient(transport=self._transport, timeout=self._timeout, follow_redirects=False, trust_env=False) as client:
            try:
                async with client.stream("POST", self._url, json=message, headers=headers) as response:
                    if response.is_redirect:
                        raise McpError(f"{self._path} answered {what} with a redirect; redirects are not followed")
                    if response.status_code in (401, 403):
                        raise McpError(f"{self._path} refused {what} (HTTP {response.status_code}): check the credentials in the description")
                    if response.status_code == 404 and self._session:
                        raise McpError(f"{self._path} no longer knows this session (HTTP 404)")
                    if not 200 <= response.status_code < 300:
                        raise McpError(f"{self._path} answered {what} with HTTP {response.status_code}")
                    data = b""
                    async for chunk in response.aiter_bytes():
                        data += chunk
                        if len(data) > MAX_ANSWER_BYTES:
                            raise McpError(f"{self._path} answered {what} with more than {MAX_ANSWER_BYTES} bytes")
                    return data, response.headers
            except httpx.HTTPError as exc:
                raise McpError(f"could not reach {self._path}: {type(exc).__name__}") from exc

    async def _notify(self, method: str) -> None:
        await self._send({"jsonrpc": "2.0", "method": method})

    async def _request(self, method: str, params: Mapping[str, Any] | None = None) -> tuple[Mapping[str, Any], httpx.Headers]:
        self._next_id += 1
        number = self._next_id
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": number, "method": method}
        if params is not None:
            message["params"] = dict(params)
        data, headers = await self._send(message)
        text = data.decode("utf-8", "replace")
        if "text/event-stream" in headers.get("content-type", ""):
            messages = _events(text)
        else:
            try:
                parsed = json.loads(text)
            except ValueError as exc:
                raise McpError(f"{self._path} answered {method} with something that is not JSON") from exc
            messages = parsed if isinstance(parsed, list) else [parsed]
        for answer in messages:
            if not isinstance(answer, Mapping) or answer.get("id") != number or "method" in answer:
                continue
            error = answer.get("error")
            if isinstance(error, Mapping):
                raise McpError(f"{method} failed: {str(error.get('message', 'no reason given'))[:300]} (code {error.get('code')})")
            result = answer.get("result")
            if isinstance(result, Mapping):
                return result, headers
        raise McpError(f"{self._path} did not answer {method}")

    async def start(self) -> dict[str, str]:
        """Open a session. Returns the server's name and version as it gives them."""
        self._session = self._version = ""
        result, headers = await self._request(
            "initialize",
            {"protocolVersion": VERSIONS[0], "capabilities": {}, "clientInfo": {"name": "botsting", "version": "1"}},
        )
        version = result.get("protocolVersion")
        if version not in VERSIONS:
            raise McpError(f"the server speaks protocol version {str(version)[:40]!r}, which this client does not")
        self._version = str(version)
        self._session = headers.get(_SESSION, "")
        info = result.get("serverInfo")
        info = info if isinstance(info, Mapping) else {}
        self.server = {"name": str(info.get("name", ""))[:200], "version": str(info.get("version", ""))[:100], "protocol": self._version}
        await self._notify("notifications/initialized")
        return dict(self.server)

    async def tools(self) -> tuple[McpTool, ...]:
        found: list[McpTool] = []
        cursor: str | None = None
        for _page in range(MAX_TOOLS):
            result, _ = await self._request("tools/list", {"cursor": cursor} if cursor else None)
            listed = result.get("tools")
            for item in listed if isinstance(listed, list) else []:
                if not isinstance(item, Mapping) or not isinstance(item.get("name"), str):
                    raise McpError("the server listed a tool without a name")
                notes = item.get("annotations")
                notes = notes if isinstance(notes, Mapping) else {}
                schema = item.get("inputSchema")
                destructive = notes.get("destructiveHint")
                found.append(
                    McpTool(
                        name=item["name"],
                        description=str(item.get("description") or ""),
                        schema=schema if isinstance(schema, Mapping) else {"type": "object"},
                        read_only=notes.get("readOnlyHint") is True,
                        destructive=destructive if isinstance(destructive, bool) else None,
                    )
                )
            cursor = result.get("nextCursor") if isinstance(result.get("nextCursor"), str) else None
            if not cursor:
                return tuple(found)
            if len(found) > MAX_TOOLS:
                break
        raise McpError(f"the server lists more than {MAX_TOOLS} tools, or its list never ends")

    async def call(self, name: str, arguments: Mapping[str, Any]) -> McpResult:
        result, _ = await self._request("tools/call", {"name": name, "arguments": dict(arguments)})
        return McpResult(_result_text(result), failed=result.get("isError") is True)
