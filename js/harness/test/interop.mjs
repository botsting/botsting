// Interop helper for the Python tests (tests/test_harness_js.py). Reads
// {"token": ..., "slot": ...} from stdin, opens the session the way a wrapped request
// would, records one call, and prints {"session", "sid", "planted", "calls", "ranForReal"}
// as JSON on stdout. A token Python signed must open here, and the calls header this
// prints must verify with Python's read_calls_header.

import * as pp from "../index.js";

const real = [];
const refund = pp.action("issue_refund", (order_id, amount) => {
  real.push([order_id, amount]);
  return { status: "refunded for real" };
});

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => (input += chunk));
process.stdin.on("end", () => {
  const { token, slot } = JSON.parse(input);
  const session = pp.openSession(token);
  if (session === null) {
    process.stdout.write(JSON.stringify({ session: false }));
    return;
  }
  let planted = null;
  let calls = null;
  session.run(() => {
    planted = pp.planted(slot, "(none)");
    refund("A-1", 10);
    calls = session.headerValue();
  });
  process.stdout.write(
    JSON.stringify({ session: true, sid: session.sid, planted, calls, ranForReal: real.length })
  );
});
