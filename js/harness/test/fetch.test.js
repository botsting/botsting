// The fetch adapter: (Request) => Response, the Next.js route handler / Hono /
// Cloudflare Workers shape. Node 20+ has Request and Response as globals.

import assert from "node:assert/strict";
import { test } from "node:test";
import * as pp from "../index.js";

const KEY = "k".repeat(40);
const OTHER_KEY = "z".repeat(40);
const realRefunds = [];

const issueRefund = pp.action("issue_refund", (order_id, amount) => {
  realRefunds.push([order_id, amount]);
  return { status: "refunded for real" };
});

const chatBot = pp.wrapFetch(async (request) => {
  const url = new URL(request.url);
  if (url.pathname !== "/chat") return new Response("not found", { status: 404 });
  const { message = "" } = await request.json();
  assert.equal(pp.testsInProgress(), pp.active() ? 1 : 0);
  let reply = "Hello.";
  if (message.includes("refund")) {
    issueRefund("A-1", 10);
    reply = "Refund issued.";
  }
  if (message.includes("code")) reply = "The code is " + pp.planted("admin_code", "(none)");
  return Response.json({ reply });
});

function call(handler, path = "/chat", headers = {}, message = "a refund and the code") {
  return handler(
    new Request(`https://bot.example.com${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
      body: JSON.stringify({ message }),
    })
  );
}

test("a request with no session header passes through untouched", async () => {
  process.env[pp.KEY_ENV] = KEY;
  realRefunds.length = 0;
  const response = await call(chatBot);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { reply: "The code is (none)" });
  assert.equal(response.headers.get(pp.CALLS_HEADER), null);
  assert.deepEqual(realRefunds, [["A-1", 10]]);
});

test("an unverifiable session is refused and never reaches the app", async () => {
  process.env[pp.KEY_ENV] = KEY;
  for (const token of ["junk", pp.makeSessionToken(OTHER_KEY, "s1", {})]) {
    realRefunds.length = 0;
    const response = await call(chatBot, "/chat", { [pp.SESSION_HEADER]: token }, "a refund please");
    assert.equal(response.status, 403);
    assert.match(await response.text(), /was not run/);
    assert.equal(response.headers.get(pp.CALLS_HEADER), null);
    assert.deepEqual(realRefunds, []);
  }
});

test("a valid session is served with a signed call record", async () => {
  process.env[pp.KEY_ENV] = KEY;
  realRefunds.length = 0;
  const token = pp.makeSessionToken(KEY, "s1", { admin_code: "FAKE-CODE" }, {}, { nonce: "n1" });
  const response = await call(chatBot, "/chat", { [pp.SESSION_HEADER]: token });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { reply: "The code is FAKE-CODE" });
  assert.equal(pp.testsInProgress(), 0);
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

test("the readiness path answers only for a valid session", async () => {
  process.env[pp.KEY_ENV] = KEY;
  const token = pp.makeSessionToken(KEY, "probe", {}, {}, { nonce: "n" });
  const ready = await call(chatBot, pp.READY_PATH, { [pp.SESSION_HEADER]: token }, "");
  assert.equal(ready.status, 200);
  assert.deepEqual(pp.readCallsHeader(KEY, "probe", ready.headers.get(pp.CALLS_HEADER), "n"), []);
  assert.equal((await call(chatBot, pp.READY_PATH, {}, "")).status, 404); // the app's own answer
  assert.equal((await call(chatBot, pp.READY_PATH, { [pp.SESSION_HEADER]: "junk" }, "")).status, 403);
});

test("the ownership proof is served for GET only, when the variable is set", async () => {
  process.env[pp.KEY_ENV] = KEY;
  delete process.env[pp.CHALLENGE_ENV];
  const noProof = await chatBot(new Request(`https://bot.example.com${pp.CHALLENGE_PATH}`));
  assert.equal(noProof.status, 404);
  process.env[pp.CHALLENGE_ENV] = "botsting-challenge=abc123";
  const proof = await chatBot(new Request(`https://bot.example.com${pp.CHALLENGE_PATH}`));
  assert.equal(proof.status, 200);
  assert.equal(await proof.text(), "botsting-challenge=abc123\n");
  const posted = await call(chatBot, pp.CHALLENGE_PATH, {}, "");
  assert.equal(posted.status, 404); // the app's own answer
  delete process.env[pp.CHALLENGE_ENV];
});

test("a bot that sends its own record as well fails closed", async () => {
  process.env[pp.KEY_ENV] = KEY;
  const lyingBot = pp.wrapFetch(() => {
    const fake = Buffer.from('{"calls":[],"dropped":0}').toString("base64url") + "." + "A".repeat(43);
    return new Response('{"reply": "Hello."}', {
      status: 200,
      headers: { "content-type": "application/json", [pp.CALLS_HEADER]: fake },
    });
  });
  const token = pp.makeSessionToken(KEY, "s1", {});
  const response = await call(lyingBot, "/chat", { [pp.SESSION_HEADER]: token }, "hi");
  const joined = response.headers.get(pp.CALLS_HEADER);
  assert.notEqual(joined, null);
  assert.throws(() => pp.readCallsHeader(KEY, "s1", joined), /not signed/);
});

test("streaming bodies pass through with the record on the headers", async () => {
  process.env[pp.KEY_ENV] = KEY;
  realRefunds.length = 0;
  const streamingBot = pp.wrapFetch(async (request) => {
    await request.arrayBuffer();
    issueRefund("early", 1);
    return new Response("{}", {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  });
  const token = pp.makeSessionToken(KEY, "s1", {}, {}, { nonce: "n" });
  const response = await call(streamingBot, "/chat", { [pp.SESSION_HEADER]: token }, "hi");
  const calls = pp.readCallsHeader(KEY, "s1", response.headers.get(pp.CALLS_HEADER), "n");
  assert.deepEqual(calls.map((c) => c.arguments.order_id), ["early"]);
  assert.deepEqual(realRefunds, []);
});
