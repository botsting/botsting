// Interop helper for the Python tests (tests/test_harness_js.py). Reads
// {"token": ..., "slot": ..., "liveAmounts"?: [...]} from stdin, opens the session the
// way a wrapped request would, records one call (or one per live amount, so Python can
// ask for a real refund inside a cap and a refused one outside it), and prints
// {"session", "sid", "runId", "planted", "read", "calls", "ranForReal", "realAmounts"}
// as JSON on stdout. A token Python signed must open here, and the calls header this
// prints must verify with Python's read_calls_header. Two more shapes:
// {"record", "sessionId", "nonce"} verifies a Python-signed record here, and
// {"make": {"sessionId", "nonce", "read"?, "mark"?: {tool: ask}}} signs a readiness
// record here (tools and rules included) for Python to verify.

import * as pp from "../index.js";

const real = [];
const refund = pp.action(
  "issue_refund",
  (order_id, amount) => {
    real.push([order_id, amount]);
    return { status: "refunded for real" };
  },
  { live: pp.cap({ max: { amount: 10 }, total: { amount: 25 }, calls: 3 }) }
);

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => (input += chunk));
process.stdin.on("end", () => {
  const { token, slot, liveAmounts, record, sessionId, nonce, make } = JSON.parse(input);
  if (record !== undefined) {
    process.stdout.write(JSON.stringify(pp.readRecord(process.env[pp.KEY_ENV], sessionId, record, nonce)));
    return;
  }
  if (make !== undefined) {
    for (const [name, ask] of Object.entries(make.mark || {})) pp.markTool(name, ask);
    const session = new pp.Session(make.sessionId, {}, {}, process.env[pp.KEY_ENV], make.nonce);
    session.read.push(...(make.read || []));
    process.stdout.write(JSON.stringify({ calls: session.headerValue(true) }));
    return;
  }
  const session = pp.openSession(token);
  if (session === null) {
    process.stdout.write(JSON.stringify({ session: false }));
    return;
  }
  let planted = null;
  let calls = null;
  let read = null;
  session.run(() => {
    planted = pp.planted(slot, "(none)");
    if (Array.isArray(liveAmounts)) for (const amount of liveAmounts) refund("A-1", amount);
    else refund("A-1", 10);
    calls = session.headerValue();
    read = [...session.read];
  });
  process.stdout.write(
    JSON.stringify({
      session: true,
      sid: session.sid,
      runId: session.runId,
      live: [...session.live],
      planted,
      read,
      calls,
      ranForReal: real.length,
      realAmounts: real.map(([, amount]) => amount),
    })
  );
});
