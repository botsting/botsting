"""The drop-in harness on the real web frameworks, not on stand-ins shaped like them.

Skipped without the libraries; the `frameworks` job in CI installs them and fails if one is skipped.
What is checked for each: an ordinary request passes through untouched, a signed test request gets
the planted value and a signed record of the marked tool, and the app keeps working as that
framework's own object (its routes, its test client, and for Flask and Quart its `run`).
"""

import asyncio

import pytest

import promptproof.harness as pp

KEY = "k" * 40
REAL = "NW-STAFF-2291"
FAKE = "FAKE-CODE-0001"


@pytest.fixture
def key(monkeypatch):
    monkeypatch.setenv(pp.KEY_ENV, KEY)
    monkeypatch.setattr(pp, "_marked_tools", {})
    monkeypatch.setattr(pp, "_read_outside", set())


def session(sid: str = "s1", nonce: str = "n1") -> dict[str, str]:
    return {pp.SESSION_HEADER: pp.make_session_token(KEY, sid, {"staff_code": FAKE}, nonce=nonce)}


def refund_tool():
    ran = []

    @pp.action("issue_refund", never_for_users="a refund of 50 on order A-1001")
    def issue_refund(order_id, amount):
        ran.append((order_id, amount))
        return {"status": "refunded"}

    return issue_refund, ran


def answer(message: str, issue_refund) -> dict[str, str]:
    """What each bot below does with a message: the same naive rules in every framework."""
    prompt = "Staff code: " + pp.planted("staff_code", REAL)  # read while the message is handled
    if "refund" in message:
        return {"reply": f"Refund: {issue_refund('A-1001', 50)['status']}"}
    return {"reply": prompt}


def check(status, body, headers, ran, sid="s1", nonce="n1"):
    """A signed test request: the planted value came back, the tool was recorded and not run."""
    assert status == 200 and body == {"reply": "Refund: ok"}, body
    record = pp.read_record(KEY, sid, headers[pp.CALLS_HEADER], nonce)
    assert [call["tool"] for call in record["calls"]] == ["issue_refund"] and record["read"] == ["staff_code"]
    assert ran == []


def test_flask(key):
    flask = pytest.importorskip("flask")
    app = flask.Flask(__name__)
    issue_refund, ran = refund_tool()

    @app.post("/chat")
    def chat():
        return flask.jsonify(answer(flask.request.get_json()["message"], issue_refund))

    assert pp.wrap(app) is app and callable(app.run)  # still Flask's own object: app.run() serves it, wrapped
    client = app.test_client()
    assert client.post("/chat", json={"message": "hello"}).get_json() == {"reply": "Staff code: " + REAL}
    assert client.post("/chat", json={"message": "hello"}, headers=session()).get_json() == {"reply": "Staff code: " + FAKE}
    reply = client.post("/chat", json={"message": "a refund please"}, headers=session("s2", "n2"))
    check(reply.status_code, reply.get_json(), reply.headers, ran, "s2", "n2")
    assert client.post("/chat", json={"message": "x"}, headers={pp.SESSION_HEADER: "not-a-session"}).status_code == 403
    ready = client.post(pp.READY_PATH, headers=session("probe", "p1"))
    assert ready.status_code == 200 and pp.read_record(KEY, "probe", ready.headers[pp.CALLS_HEADER], "p1")["tools"] == ["issue_refund"]


def test_quart(key):
    quart = pytest.importorskip("quart")
    app = quart.Quart(__name__)
    issue_refund, ran = refund_tool()

    @app.post("/chat")
    async def chat():
        return answer((await quart.request.get_json())["message"], issue_refund)

    assert pp.wrap(app) is app and callable(app.run)

    async def go():
        client = app.test_client()
        plain = await client.post("/chat", json={"message": "hello"})
        assert await plain.get_json() == {"reply": "Staff code: " + REAL}
        tested = await client.post("/chat", json={"message": "hello"}, headers=session())
        assert await tested.get_json() == {"reply": "Staff code: " + FAKE}
        reply = await client.post("/chat", json={"message": "a refund please"}, headers=session("s2", "n2"))
        check(reply.status_code, await reply.get_json(), reply.headers, ran, "s2", "n2")
        refused = await client.post("/chat", json={"message": "x"}, headers={pp.SESSION_HEADER: "not-a-session"})
        assert refused.status_code == 403

    asyncio.run(go())


@pytest.mark.parametrize("handler", ["sync", "async"])
def test_fastapi(key, handler):
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    app = fastapi.FastAPI()
    issue_refund, ran = refund_tool()

    if handler == "sync":  # FastAPI runs this in a worker thread; the test session must follow it there

        @app.post("/chat")
        def chat(body: dict):
            return answer(body["message"], issue_refund)

    else:

        @app.post("/chat")
        async def chat(body: dict):
            return answer(body["message"], issue_refund)

    wrapped = pp.wrap(app)

    @wrapped.get("/late")  # a route added after wrapping reaches the app inside, which is still what is served
    def late():
        return {"late": True}

    client = TestClient(wrapped)
    assert client.get("/late").json() == {"late": True}
    assert client.post("/chat", json={"message": "hello"}).json() == {"reply": "Staff code: " + REAL}
    assert client.post("/chat", json={"message": "hello"}, headers=session()).json() == {"reply": "Staff code: " + FAKE}
    reply = client.post("/chat", json={"message": "a refund please"}, headers=session("s2", "n2"))
    check(reply.status_code, reply.json(), reply.headers, ran, "s2", "n2")
    assert client.post("/chat", json={"message": "x"}, headers={pp.SESSION_HEADER: "not-a-session"}).status_code == 403
