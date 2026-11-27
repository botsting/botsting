"""The MCP client: it starts a session, lists tools and calls one, and goes nowhere else.

The server here is a function inside the test process. Nothing listens anywhere.
"""

import asyncio
import json

import httpx
import pytest

from botsting.mcp_client import MAX_ANSWER_BYTES, MAX_RESULT_CHARS, McpClient, McpError

ORIGIN = "http://127.0.0.1:5165"
TOOLS = [
    {"name": "find_products", "description": "Find products.", "inputSchema": {"type": "object"}, "annotations": {"readOnlyHint": True}},
    {"name": "delete_product", "description": "Delete one.", "inputSchema": {"type": "object"}, "annotations": {"destructiveHint": True}},
    {"name": "plain_tool"},
]


class Server:
    """A stand-in MCP server. `streamed` makes it answer with events instead of one JSON message."""

    def __init__(self, streamed: bool = False, version: str = "2025-06-18", pages: int = 1) -> None:
        self.streamed = streamed
        self.version = version
        self.pages = pages
        self.seen: list[httpx.Request] = []
        self.bodies: list[dict] = []

    def answer(self, request: httpx.Request, result: dict | None = None, error: dict | None = None, **headers: str) -> httpx.Response:
        number = json.loads(request.content)["id"]
        message = {"jsonrpc": "2.0", "id": number, **({"error": error} if error else {"result": result})}
        if self.streamed:
            # A server may send its own messages and keep-alives around the answer.
            stream = (
                ": keep-alive\n\n"
                'event: message\ndata: {"jsonrpc":"2.0","id":"srv-1","method":"ping"}\n\n'
                f"event: message\r\ndata: {json.dumps(message)}\r\n\r\n"
            )
            return httpx.Response(200, content=stream.encode(), headers={"content-type": "text/event-stream", **headers})
        return httpx.Response(200, json=message, headers=headers)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(request)
        body = json.loads(request.content)
        self.bodies.append(body)
        method = body["method"]
        if method == "initialize":
            return self.answer(
                request,
                {"protocolVersion": self.version, "capabilities": {"tools": {}}, "serverInfo": {"name": "Stand-in", "version": "1.2"}},
                **{"Mcp-Session-Id": "session-abc"},
            )
        if method == "notifications/initialized":
            return httpx.Response(202)
        if method == "tools/list":
            page = int((body.get("params") or {}).get("cursor", "0"))
            result: dict = {"tools": TOOLS if page == self.pages - 1 else [{"name": f"filler_{page}"}]}
            if page < self.pages - 1:
                result["nextCursor"] = str(page + 1)
            return self.answer(request, result)
        if method == "tools/call":
            params = body["params"]
            if params["name"] == "broken":
                return self.answer(request, error={"code": -32602, "message": "Unknown tool: broken"})
            if params["name"] == "failing":
                return self.answer(request, {"content": [{"type": "text", "text": "No such product."}], "isError": True})
            if params["name"] == "mixed":
                content = [
                    {"type": "text", "text": "First."},
                    {"type": "image", "data": "AAAA", "mimeType": "image/png"},
                    {"type": "resource", "resource": {"uri": "x://y", "text": "From a resource."}},
                ]
                return self.answer(request, {"content": content})
            if params["name"] == "structured":
                return self.answer(request, {"content": [], "structuredContent": {"count": 2}})
            if params["name"] == "long":
                return self.answer(request, {"content": [{"type": "text", "text": "x" * (MAX_RESULT_CHARS + 50)}]})
            return self.answer(request, {"content": [{"type": "text", "text": f"called {params['name']} with {json.dumps(params['arguments'])}"}]})
        return httpx.Response(400)


def client(server, **options) -> McpClient:
    return McpClient(ORIGIN, "/mcp", transport=httpx.MockTransport(server), **options)


@pytest.mark.parametrize("streamed", [False, True])
def test_a_session_is_started_tools_are_listed_and_one_is_called(streamed):
    server = Server(streamed=streamed)
    mcp = client(server)

    async def run():
        about = await mcp.start()
        return about, await mcp.tools(), await mcp.call("find_products", {"query": "mug"})

    about, tools, result = asyncio.run(run())
    assert about == {"name": "Stand-in", "version": "1.2", "protocol": "2025-06-18"}
    assert [(t.name, t.read_only, t.destructive) for t in tools] == [("find_products", True, None), ("delete_product", False, True), ("plain_tool", False, None)]
    assert tools[2].schema == {"type": "object"} and tools[2].description == ""
    assert result.text == 'called find_products with {"query": "mug"}' and not result.failed
    assert [b["method"] for b in server.bodies] == ["initialize", "notifications/initialized", "tools/list", "tools/call"]
    assert "id" not in server.bodies[1], "a notification carries no id"
    first, *later = server.seen
    assert "mcp-session-id" not in first.headers and "mcp-protocol-version" not in first.headers
    assert all(r.headers["mcp-session-id"] == "session-abc" and r.headers["mcp-protocol-version"] == "2025-06-18" for r in later)
    assert all("application/json" in r.headers["accept"] and "text/event-stream" in r.headers["accept"] for r in server.seen)


def test_a_tool_list_sent_in_pages_is_read_to_the_end():
    mcp = client(Server(pages=3))

    async def run():
        await mcp.start()
        return await mcp.tools()

    assert [t.name for t in asyncio.run(run())] == ["filler_0", "filler_1", "find_products", "delete_product", "plain_tool"]


def test_a_tool_list_that_never_ends_is_given_up_on(monkeypatch):
    monkeypatch.setattr("botsting.mcp_client.MAX_TOOLS", 5)
    mcp = client(Server(pages=10**9))

    async def run():
        await mcp.start()
        await mcp.tools()

    with pytest.raises(McpError, match="never ends"):
        asyncio.run(run())


def test_what_a_tool_returns_becomes_text_and_a_failure_is_kept_as_one():
    mcp = client(Server())

    async def run():
        await mcp.start()
        return [await mcp.call(name, {}) for name in ("failing", "mixed", "structured", "long")]

    failing, mixed, structured, long = asyncio.run(run())
    assert failing.failed and failing.text == "No such product."
    assert mixed.text == "First.\n[image left out]\nFrom a resource." and not mixed.failed
    assert structured.text == '{"count": 2}'
    assert len(long.text) < MAX_RESULT_CHARS + 60 and long.text.endswith(f"[cut after {MAX_RESULT_CHARS} characters]")


def test_an_error_from_the_server_is_reported_with_its_reason():
    mcp = client(Server())

    async def run():
        await mcp.start()
        await mcp.call("broken", {})

    with pytest.raises(McpError, match=r"tools/call failed: Unknown tool: broken \(code -32602\)"):
        asyncio.run(run())


def test_a_server_on_a_version_this_client_does_not_speak_is_refused():
    with pytest.raises(McpError, match="protocol version '1999-01-01'"):
        asyncio.run(client(Server(version="1999-01-01")).start())


def test_a_credential_comes_from_the_environment_and_is_in_no_error(monkeypatch):
    monkeypatch.setenv("STAND_IN_TOKEN", "s3cr3t-value")
    seen: list[str] = []

    def refuse(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["authorization"])
        return httpx.Response(401, text="bad token s3cr3t-value")

    mcp = client(refuse, headers={"Authorization": "Bearer ${STAND_IN_TOKEN}"})
    with pytest.raises(McpError) as caught:
        asyncio.run(mcp.start())
    assert seen == ["Bearer s3cr3t-value"]
    assert "s3cr3t" not in str(caught.value) and "check the credentials" in str(caught.value)


def test_a_missing_credential_is_named_before_anything_is_sent(monkeypatch):
    monkeypatch.delenv("STAND_IN_TOKEN", raising=False)
    server = Server()
    mcp = client(server, headers={"Authorization": "Bearer ${STAND_IN_TOKEN}"})
    with pytest.raises(Exception, match="STAND_IN_TOKEN is not set"):
        asyncio.run(mcp.start())
    assert not server.seen


@pytest.mark.parametrize(
    ("response", "said"),
    [
        (httpx.Response(302, headers={"location": "https://elsewhere.example/mcp"}), "redirect"),
        (httpx.Response(500), "HTTP 500"),
        (httpx.Response(200, text="<html>hello</html>"), "not JSON"),
        (httpx.Response(200, json={"jsonrpc": "2.0", "id": 99, "result": {}}), "did not answer initialize"),
        (httpx.Response(200, content=b"x" * (MAX_ANSWER_BYTES + 1)), "more than"),
        (httpx.Response(200, content=b": nothing\n\n", headers={"content-type": "text/event-stream"}), "did not answer initialize"),
    ],
)
def test_an_answer_that_is_not_what_an_mcp_server_sends_is_an_error_not_a_crash(response, said):
    with pytest.raises(McpError, match=said):
        asyncio.run(client(lambda request: response).start())


def test_a_server_that_cannot_be_reached_is_an_error_without_the_address_details():
    def unreachable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused to 127.0.0.1:5165 token=abc")

    with pytest.raises(McpError) as caught:
        asyncio.run(client(unreachable).start())
    assert "could not reach /mcp: ConnectError" in str(caught.value) and "token=abc" not in str(caught.value)


def test_nothing_is_sent_to_any_other_address():
    server = Server()
    mcp = client(server)
    asyncio.run(mcp.start())
    assert {(r.url.scheme, r.url.host, r.url.port, r.url.path, r.url.query) for r in server.seen} == {("http", "127.0.0.1", 5165, "/mcp", b"")}
    # The guard is on the transport, so it holds for whatever builds a request.
    mcp._url = "http://127.0.0.1:5165/admin"
    with pytest.raises(McpError, match="could not reach"):
        asyncio.run(mcp.start())
    mcp._url = "http://example.com/mcp"
    with pytest.raises(McpError, match="could not reach"):
        asyncio.run(mcp.start())
    assert len(server.seen) == 2
