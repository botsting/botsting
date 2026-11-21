// The harness's signing and session logic, mirroring the Python tests one for one
// where they apply (tests/test_harness.py).

import assert from "node:assert/strict";
import { test, beforeEach } from "node:test";
import * as pp from "../index.js";

const KEY = "k".repeat(40);
const OTHER_KEY = "z".repeat(40);

const realRefunds = [];

const issueRefund = pp.action("issue_refund", (order_id, amount) => {
  realRefunds.push([order_id, amount]);
  return { status: "refunded for real" };
});

const sendEmail = pp.action(
  "send_email",
  async (to, body) => {
    realRefunds.push([to, -1]);
    return "sent for real";
  },
  { result: (args) => `queued to ${args.to}` }
);

// Run a function as the harness would inside a request carrying the token.
function inSession(token, fn) {
  const session = pp.openSession(token);
  if (session === null) return [fn(), null];
  return [session.run(fn), session];
}

beforeEach(() => {
  realRefunds.length = 0;
  delete process.env[pp.KEY_ENV];
});

// -- doing nothing unless asked properly ------------------------------------------------------

test("without a key everything runs as written", () => {
  // the token is signed, but this deployment has no key, so nothing is a test session
  const token = pp.makeSessionToken(KEY, "s1", { admin_code: "FAKE" });
  const [result, session] = inSession(token, () => issueRefund("A-1", 5));
  assert.equal(session, null);
  assert.deepEqual(result, { status: "refunded for real" });
  assert.deepEqual(realRefunds, [["A-1", 5]]);
  assert.equal(pp.planted("admin_code", "default"), "default");
  assert.equal(pp.active(), false);
});

test("a request without a valid session is an ordinary request", () => {
  process.env[pp.KEY_ENV] = KEY;
  const bad = [
    () => pp.makeSessionToken(OTHER_KEY, "s1", { admin_code: "FAKE" }), // someone else's key
    () => pp.makeSessionToken(KEY, "s1", { admin_code: "FAKE" }, {}, { now: Date.now() / 1000 - 400 }), // expired
    () => pp.makeSessionToken(KEY, "s1", { admin_code: "FAKE" }).slice(0, -3) + "AAA", // bad signature
    () => "not a token",
    () => null,
  ];
  for (const make of bad) {
    const [result, session] = inSession(make(), () => issueRefund("A-1", 5));
    assert.equal(session, null, `a session opened for ${make()}`);
    assert.deepEqual(result, { status: "refunded for real" });
    assert.deepEqual(realRefunds, [["A-1", 5]]);
    realRefunds.length = 0;
  }
});

test("a changed fixture breaks the signature", () => {
  process.env[pp.KEY_ENV] = KEY;
  const token = pp.makeSessionToken(KEY, "s1", { admin_code: "FAKE" });
  const [payload, macPart] = token.split(".");
  const body = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  body.fixtures.admin_code = "SOMETHING ELSE";
  const keys = Object.keys(body).sort();
  const canonical = {};
  for (const k of keys) canonical[k] = body[k];
  let json = "{";
  for (const k of keys) {
    // compact separators, like the Python token builder
    json += (json.length > 1 ? "," : "") + JSON.stringify(k) + ":" + JSON.stringify(canonical[k]);
  }
  json += "}";
  const forged = Buffer.from(json, "utf8").toString("base64url") + "." + macPart;
  assert.equal(pp.openSession(forged), null);
});

test("a short key is refused", () => {
  assert.throws(() => pp.checkKey("short"), /at least 32/);
  assert.throws(() => pp.makeSessionToken("short", "s1", {}), pp.HarnessError);
  process.env[pp.KEY_ENV] = "short";
  assert.throws(() => pp.wrapNode(() => {}), /at least 32/);
  assert.throws(() => pp.express(), /at least 32/);
  assert.throws(() => pp.wrapFetch(() => new Response("x")), /at least 32/);
  delete process.env[pp.KEY_ENV];
});

// -- inside a test session ----------------------------------------------------------------------

test("in a test session tools are recorded and never run", async () => {
  process.env[pp.KEY_ENV] = KEY;
  const token = pp.makeSessionToken(KEY, "s1", { admin_code: "FAKE-CODE" }, { ticket: "planted text" });
  const [values, session] = inSession(token, () => {
    assert.equal(pp.active(), true);
    assert.equal(pp.planted("admin_code"), "FAKE-CODE");
    assert.equal(pp.content("ticket"), "planted text");
    assert.equal(pp.planted("unknown", "d"), "d");
    return [issueRefund("A-1", 12.5), sendEmail("x@example.com", "hello")];
  });
  const [first, second] = await Promise.all(values);
  assert.deepEqual(realRefunds, []);
  assert.deepEqual(first, { status: "ok" });
  assert.equal(second, "queued to x@example.com");
  const calls = pp.readCallsHeader(KEY, "s1", session.headerValue());
  assert.deepEqual(calls, [
    {
      id: "call-1",
      tool: "issue_refund",
      arguments: { order_id: "A-1", amount: "12.5" },
      accepted: true,
      result: '{"status": "ok"}',
    },
    {
      id: "call-2",
      tool: "send_email",
      arguments: { to: "x@example.com", body: "hello" },
      accepted: true,
      result: "queued to x@example.com",
    },
  ]);
});

test("the call record cannot be forged or moved to another session", () => {
  process.env[pp.KEY_ENV] = KEY;
  const token = pp.makeSessionToken(KEY, "s1", {});
  const [, session] = inSession(token, () => issueRefund("A-1", 1));
  const header = session.headerValue();
  assert.throws(() => pp.readCallsHeader(KEY, "s2", header), /not signed/); // replayed into another conversation
  assert.throws(() => pp.readCallsHeader(OTHER_KEY, "s1", header), /not signed/);
  const empty = pp.openSession(pp.makeSessionToken(KEY, "s1", {})).headerValue();
  assert.throws(
    () => pp.readCallsHeader(KEY, "s1", empty.split(".")[0] + "." + header.split(".")[1]),
    /not signed/
  ); // swapped body
  assert.throws(() => pp.readCallsHeader(KEY, "s1", null), /did not see this as a test session/);
});

test("too many calls in one reply is an error, not a silent gap", () => {
  process.env[pp.KEY_ENV] = KEY;
  const token = pp.makeSessionToken(KEY, "s1", {});
  const [, session] = inSession(token, () => {
    for (let i = 0; i < pp.MAX_CALLS + 3; i++) issueRefund(`A-${i}`, 1);
  });
  assert.throws(() => pp.readCallsHeader(KEY, "s1", session.headerValue()), /3 were not recorded/);
});

test("a very large tool argument is an error, not a silent gap", () => {
  process.env[pp.KEY_ENV] = KEY;
  const token = pp.makeSessionToken(KEY, "s1", {});
  const [, session] = inSession(token, () => issueRefund("A".repeat(pp.MAX_RECORD_BYTES + 1), 1));
  assert.deepEqual(session.calls, []);
  assert.equal(session.dropped, 1);
  assert.throws(() => pp.readCallsHeader(KEY, "s1", session.headerValue()), /1 were not recorded/);
});

test("oversized content is refused before sending", () => {
  assert.throws(() => pp.makeSessionToken(KEY, "s1", {}, { doc: "x".repeat(6000) }), /bytes in the header/);
});

test("a record cannot be reused for a later message of the same session", () => {
  process.env[pp.KEY_ENV] = KEY;
  const first = pp.openSession(pp.makeSessionToken(KEY, "s1", {}, {}, { nonce: "message-1" }));
  const header = first.headerValue(); // "no calls", honestly signed for message 1
  assert.deepEqual(pp.readCallsHeader(KEY, "s1", header, "message-1"), []);
  assert.throws(() => pp.readCallsHeader(KEY, "s1", header, "message-2"), /not signed/);
});

test("the parts of a signature cannot run together", () => {
  const d = Buffer.from("d");
  assert.notEqual(pp.mac(KEY, d, ["ab", "c"]), pp.mac(KEY, d, ["a", "bc"]));
  assert.notEqual(pp.mac(KEY, d, ["a\nb"]), pp.mac(KEY, d, ["a", "b"]));
});

test("a scanner survives a garbled record from the bot", () => {
  const values = ["x.µµ", "nodot", "....", Buffer.from("not json").toString("base64url") + "." + "A".repeat(43)];
  for (const value of values) assert.throws(() => pp.readCallsHeader(KEY, "s1", value), pp.HarnessError);
});

test("a token may not outlive the maximum lifetime", () => {
  assert.throws(() => pp.makeSessionToken(KEY, "s1", {}, {}, { lifetimeSeconds: 901 }), /at most 900/);
  assert.throws(() => pp.makeSessionToken(KEY, "s1", {}, {}, { lifetimeSeconds: 0 }), /at most 900/);
});

test("newKey makes a key the checker accepts", () => {
  const made = pp.newKey();
  assert.equal(pp.checkKey(made), made);
});

test("recordedCalls lists the session's calls and nothing outside one", () => {
  process.env[pp.KEY_ENV] = KEY;
  const token = pp.makeSessionToken(KEY, "s1", {});
  const session = pp.openSession(token);
  assert.deepEqual(pp.recordedCalls(), []); // outside a test session
  session.run(() => {
    issueRefund("A-1", 1);
    const seen = pp.recordedCalls();
    assert.deepEqual(seen.map((c) => c.tool), ["issue_refund"]);
    seen[0].tool = "changed"; // a copy, not the record itself
    assert.equal(session.calls[0].tool, "issue_refund");
  });
  assert.deepEqual(pp.recordedCalls(), []);
});
