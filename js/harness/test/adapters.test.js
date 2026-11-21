// The plain-Node adapter over real HTTP on 127.0.0.1, mirroring the Python web-app
// tests. Nothing leaves this machine.

import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import { after, test } from "node:test";
import * as pp from "../index.js";

const KEY = "k".repeat(40);
const OTHER_KEY = "z".repeat(40);
const closers = [];
const realRefunds = [];

after(() => {
  for (const close of closers) close();
});

function serve(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, "127.0.0.1", () => {
      closers.push(() => {
        server.closeAllConnections(); // fetch keeps idle keep-alive sockets open
        server.close();
      });
      resolve(`http://127.0.0.1:${server.address().port}`);
    });
  });
}

const issueRefund = pp.action("issue_refund", (order_id, amount) => {
  realRefunds.push([order_id, amount]);
  return { status: "refunded for real" };
});

function chatBot(req, res) {
  const path = (req.url || "").split("?")[0];
  if (path !== "/chat") {
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("not found");
    return;
  }
  let body = "";
  req.on("data", (chunk) => (body += chunk));
  req.on("end", () => {
    const message = (JSON.parse(body || "{}").message || "") + "";
    let reply = "Hello.";
    if (message.includes("refund")) {
      issueRefund("A-1", 10);
      reply = "Refund issued.";
    }
    if (message.includes("code")) reply = "The code is " + pp.planted("admin_code", "(none)");
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ reply }));
  });
}

const post = (baseUrl, path = "/chat", headers = {}, message = "a refund and the code") =>
  fetch(baseUrl + path, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify({ message }),
  });

function fresh(key = KEY) {
  process.env[pp.KEY_ENV] = key;
  realRefunds.length = 0;
}

// -- an ordinary user sees no difference -------------------------------------------------------

test("a request with no session header passes through untouched", async () => {
  fresh();
  const baseUrl = await serve(pp.wrapNode(chatBot));
  const response = await post(baseUrl);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { reply: "The code is (none)" });
  assert.equal(response.headers.get(pp.CALLS_HEADER), null);
  assert.deepEqual(realRefunds, [["A-1", 10]]); // the tool ran as written
});

// -- a request that claims to be a test but is not valid is refused, never run ------------------

test("a message that claims to be a test but is not valid is refused, not run", async () => {
  fresh();
  const baseUrl = await serve(pp.wrapNode(chatBot));
  const bad = [
    ["junk", "junk"],
    ["someone else's key", pp.makeSessionToken(OTHER_KEY, "s1", {})],
    ["expired", pp.makeSessionToken(KEY, "s1", {}, {}, { now: Date.now() / 1000 - 4000 })],
    ["damaged", pp.makeSessionToken(KEY, "s1", {}).slice(0, -3) + "AAA"],
  ];
  for (const [, token] of bad) {
    realRefunds.length = 0;
    const response = await post(baseUrl, "/chat", { [pp.SESSION_HEADER]: token });
    assert.equal(response.status, 403);
    assert.match(await response.text(), /was not run/);
    assert.equal(response.headers.get(pp.CALLS_HEADER), null);
    assert.deepEqual(realRefunds, []);
  }
});

test("bytes that are not ASCII in the session header are refused too", async () => {
  fresh();
  const baseUrl = await serve(pp.wrapNode(chatBot));
  const response = await fetch(baseUrl + "/chat", {
    method: "POST",
    headers: { "content-type": "application/json", [pp.SESSION_HEADER]: "junk.µµ" },
    body: JSON.stringify({ message: "a refund please" }),
  });
  assert.equal(response.status, 403);
  assert.deepEqual(realRefunds, []);
});

test("two session headers are refused", async () => {
  fresh();
  const good = pp.makeSessionToken(KEY, "s1", {});
  const seen = [];
  const wrapped = pp.wrapNode((req, res) => {
    seen.push(req.url);
    chatBot(req, res);
  });
  const baseUrl = await serve(wrapped);
  // fetch cannot send a duplicated header; speak the protocol directly
  const answer = await new Promise((resolve, reject) => {
    const socket = net.connect(new URL(baseUrl).port, "127.0.0.1", () => {
      socket.write(
        `POST /chat HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\ncontent-type: application/json\r\n` +
          `${pp.SESSION_HEADER}: ${good}\r\n${pp.SESSION_HEADER}: junk\r\n` +
          `content-length: 20\r\n\r\n{"message":"refund"}`
      );
    });
    let raw = "";
    socket.on("data", (chunk) => (raw += chunk.toString("latin1")));
    socket.on("end", () => resolve(raw));
    socket.on("error", reject);
  });
  assert.match(answer, /^HTTP\/1\.1 403/);
  assert.match(answer, /was not run/);
  assert.deepEqual(seen, []);
  assert.deepEqual(realRefunds, []);
});

// -- a real test session ------------------------------------------------------------------------

test("a valid session is served with planted secrets and a signed call record", async () => {
  fresh();
  const baseUrl = await serve(pp.wrapNode(chatBot));
  const token = pp.makeSessionToken(KEY, "s1", { admin_code: "FAKE-CODE" }, {}, { nonce: "n1" });
  const response = await post(baseUrl, "/chat", { [pp.SESSION_HEADER]: token }, "a refund and the code");
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { reply: "The code is FAKE-CODE" });
  assert.deepEqual(realRefunds, []);
  const calls = pp.readCallsHeader(KEY, "s1", response.headers.get(pp.CALLS_HEADER), "n1");
  assert.deepEqual(calls, [
    {
      id: "call-1",
      tool: "issue_refund",
      arguments: { order_id: "A-1", amount: "10" },
      accepted: true,
      result: '{"status": "ok"}',
    },
  ]);
});

test("the readiness check answers only for a valid session", async () => {
  fresh();
  const baseUrl = await serve(pp.wrapNode(chatBot));
  const token = pp.makeSessionToken(KEY, "probe-1", {}, {}, { nonce: "probe-nonce" });
  const ready = await post(baseUrl, pp.READY_PATH, { [pp.SESSION_HEADER]: token }, "");
  assert.equal(ready.status, 200);
  assert.equal(await ready.text(), "promptproof harness ready\n");
  const calls = pp.readCallsHeader(KEY, "probe-1", ready.headers.get(pp.CALLS_HEADER), "probe-nonce");
  assert.deepEqual(calls, []); // carries no canaries: an empty, signed record
  // without a session header the harness does not reveal itself: the bot's own answer
  assert.equal((await post(baseUrl, pp.READY_PATH, {}, "")).status, 404);
  const refused = await post(baseUrl, pp.READY_PATH, { [pp.SESSION_HEADER]: "junk" }, "");
  assert.equal(refused.status, 403);
});

test("the ownership proof is served from the environment, for GET only", async () => {
  process.env[pp.KEY_ENV] = KEY;
  delete process.env[pp.CHALLENGE_ENV];
  const baseUrl = await serve(pp.wrapNode(chatBot));
  assert.equal((await fetch(baseUrl + pp.CHALLENGE_PATH)).status, 404); // not set: the bot's answer
  process.env[pp.CHALLENGE_ENV] = "promptproof-challenge=abc123";
  const proof = await fetch(baseUrl + pp.CHALLENGE_PATH);
  assert.equal(proof.status, 200);
  assert.equal(await proof.text(), "promptproof-challenge=abc123\n");
  assert.equal((await post(baseUrl, pp.CHALLENGE_PATH)).status, 404); // the bot's own answer
  delete process.env[pp.CHALLENGE_ENV];
});

test("calls after a streaming reply has started are blocked but not reported", async () => {
  fresh();
  const streamingBot = (req, res) => {
    issueRefund("early", 1);
    res.writeHead(200, { "content-type": "application/json" });
    issueRefund("late", 2);
    res.end("{}");
  };
  const baseUrl = await serve(pp.wrapNode(streamingBot));
  const token = pp.makeSessionToken(KEY, "s1", {}, {}, { nonce: "n" });
  const response = await post(baseUrl, "/chat", { [pp.SESSION_HEADER]: token }, "hi");
  const calls = pp.readCallsHeader(KEY, "s1", response.headers.get(pp.CALLS_HEADER), "n");
  assert.deepEqual(calls.map((c) => c.arguments.order_id), ["early"]);
  assert.deepEqual(realRefunds, []);
});

test("a bot that sends its own record as well fails closed", async () => {
  fresh();
  const lyingBot = (req, res) => {
    const fake = Buffer.from('{"calls":[],"dropped":0}').toString("base64url") + "." + "A".repeat(43);
    res.writeHead(200, {
      "content-type": "application/json",
      [pp.CALLS_HEADER.toLowerCase()]: fake,
    });
    res.end('{"reply": "Hello."}');
  };
  const baseUrl = await serve(pp.wrapNode(lyingBot));
  const token = pp.makeSessionToken(KEY, "s1", {});
  const response = await post(baseUrl, "/chat", { [pp.SESSION_HEADER]: token }, "hi");
  const joined = response.headers.get(pp.CALLS_HEADER);
  assert.notEqual(joined, null);
  assert.throws(() => pp.readCallsHeader(KEY, "s1", joined), /not signed/); // the fake and the true record, joined
});

test("a reply that never sends headers still gets its record attached", async () => {
  fresh();
  const lazyBot = (req, res) => {
    setTimeout(() => {
      issueRefund("A-9", 3);
      res.end("done"); // implicit 200
    }, 5);
  };
  const baseUrl = await serve(pp.wrapNode(lazyBot));
  const token = pp.makeSessionToken(KEY, "s1", {});
  const response = await post(baseUrl, "/chat", { [pp.SESSION_HEADER]: token }, "hi");
  assert.equal(response.status, 200);
  const calls = pp.readCallsHeader(KEY, "s1", response.headers.get(pp.CALLS_HEADER));
  assert.deepEqual(calls.map((c) => c.arguments.order_id), ["A-9"]);
  assert.deepEqual(realRefunds, []);
});
