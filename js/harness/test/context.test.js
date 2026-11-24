// What the test session follows, and what it does not. The session lives in an
// AsyncLocalStorage: it follows await, timers and promise chains started inside the
// request, but it is not carried into a worker thread's own event loop.

import assert from "node:assert/strict";
import { Worker } from "node:worker_threads";
import { test } from "node:test";
import * as pp from "../index.js";

const KEY = "k".repeat(40);
const realRefunds = [];

const issueRefund = pp.action("issue_refund", (order_id, amount) => {
  realRefunds.push([order_id, amount]);
  return { status: "refunded for real" };
});

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

test("the session follows await and promise chains", async () => {
  process.env[pp.KEY_ENV] = KEY;
  realRefunds.length = 0;
  const session = pp.openSession(pp.makeSessionToken(KEY, "s1", {}));
  await session.run(async () => {
    assert.equal(pp.active(), true);
    await delay(1); // a timer, then back
    assert.equal(pp.active(), true); // the Python harness loses a bare thread; AsyncLocalStorage does not
    issueRefund("carried", 1);
  });
  assert.deepEqual(session.calls.map((c) => c.arguments.order_id), ["carried"]);
  assert.deepEqual(realRefunds, []);
  assert.equal(pp.active(), false);
});

test("the session is not shared between requests", async () => {
  process.env[pp.KEY_ENV] = KEY;
  const first = pp.openSession(pp.makeSessionToken(KEY, "s1", {}));
  const second = pp.openSession(pp.makeSessionToken(KEY, "s2", {}));
  await first.run(async () => {
    await delay(2);
    issueRefund("mine", 1);
    assert.equal(second.sid, "s2"); // readable, but not the active session
    assert.equal(pp.planted("x", "none"), "none");
  });
  assert.deepEqual(first.calls.map((c) => c.arguments.order_id), ["mine"]);
  assert.deepEqual(second.calls, []);
});

test("a tool run in a worker thread is not covered", async () => {
  // The stated limit: a worker thread runs its own event loop, and the session does not
  // cross into it. A wrapped tool there runs for real.
  process.env[pp.KEY_ENV] = KEY;
  const session = pp.openSession(pp.makeSessionToken(KEY, "s1", {}));
  const fromWorker = await session.run(
    () =>
      new Promise((resolve, reject) => {
        const worker = new Worker(new URL("./worker.mjs", import.meta.url));
        worker.on("message", resolve);
        worker.on("error", reject);
      })
  );
  assert.deepEqual(fromWorker, { ran: 1, result: { status: "refunded for real" }, active: false });
  assert.deepEqual(session.calls, []); // nothing was recorded there
});

test("a dispatcher can record a call only inside a test session", () => {
  const session = new pp.Session("s1", {}, {}, KEY);
  const result = { status: "simulated" };
  assert.throws(() => pp.recordCall("example", {}), pp.HarnessError);
  session.run(() => {
    assert.equal(pp.recordCall("example", { count: 2, enabled: true }, result), result);
    assert.deepEqual(pp.recordCall("example", {}), { status: "ok" });
  });
  const [first, second] = pp.readCallsHeader(KEY, "s1", session.headerValue());
  assert.deepEqual(first, {
    id: "call-1",
    tool: "example",
    arguments: { count: "2", enabled: "true" },
    accepted: true,
    result: '{"status": "simulated"}',
  });
  assert.equal(second.id, "call-2");
});

test("in-flight test sessions can be detected outside the request context", async () => {
  const session = new pp.Session("s1", {}, {}, KEY);
  const other = new pp.Session("s2", {}, {}, KEY);
  const error = new Error("dispatch failed");
  let finish;
  const pending = new Promise((resolve) => { finish = resolve; });
  const first = session.run(() => pending);
  const second = other.run(async () => {
    await pending;
    throw error;
  });
  assert.equal(pp.active(), false);
  assert.equal(pp.testsInProgress(), 2);
  finish();
  await first;
  await assert.rejects(second, error);
  assert.equal(pp.testsInProgress(), 0);
  assert.throws(() => session.run(() => { throw error; }), error);
  assert.equal(pp.testsInProgress(), 0);
});
