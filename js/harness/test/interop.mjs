// Interop helper for the Python tests (tests/test_harness_js.py). Reads
// {"token": ..., "slot": ..., "liveAmounts"?: [...]} from stdin, opens the session the
// way a wrapped request would, records one call (or one per live amount, so Python can
// ask for a real refund inside a cap and a refused one outside it), and prints
// {"session", "sid", "runId", "planted", "calls", "ranForReal", "realAmounts"} as JSON
// on stdout. A token Python signed must open here, and the calls header this prints
// must verify with Python's read_calls_header.

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
  const { token, slot, liveAmounts, record, sessionId, nonce } = JSON.parse(input);
  if (record !== undefined) {
    process.stdout.write(JSON.stringify(pp.readRecord(process.env[pp.KEY_ENV], sessionId, record, nonce)));
    return;
  }
  const session = pp.openSession(token);
  if (session === null) {
    process.stdout.write(JSON.stringify({ session: false }));
    return;
  }
  let planted = null;
  let calls = null;
  session.run(() => {
    planted = pp.planted(slot, "(none)");
    if (Array.isArray(liveAmounts)) for (const amount of liveAmounts) refund("A-1", amount);
    else refund("A-1", 10);
    calls = session.headerValue();
  });
  process.stdout.write(
    JSON.stringify({
      session: true,
      sid: session.sid,
      runId: session.runId,
      live: [...session.live],
      planted,
      calls,
      ranForReal: real.length,
      realAmounts: real.map(([, amount]) => amount),
    })
  );
});
