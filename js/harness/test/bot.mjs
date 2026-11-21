// A small Node bot behind the harness, for the Python interop test
// (tests/test_harness_js.py). Serves on 127.0.0.1 on a free port and prints the port
// on stdout. Messages: "refund 7" (a refund of that amount, capped live), "a refund
// please" (the plain recorded refund), "the code please" shows the planted secret,
// "state" reports how many refunds ran for real, "what ran" reports them. Nothing
// leaves this machine.

import http from "node:http";
import * as pp from "../index.js";

const real = []; // the refunds that ran for real, as the in-memory record the test can see
const issueRefund = pp.action(
  "issue_refund",
  (order_id, amount) => {
    real.push([order_id, amount]);
    return { status: "refunded for real" };
  },
  { live: pp.cap({ max: { amount: 10 }, total: { amount: 25 }, calls: 3 }) }
);

const handler = (req, res) => {
  const path = (req.url || "").split("?")[0];
  if (path !== "/chat") {
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("not found");
    return;
  }
  let body = "";
  req.on("data", (chunk) => (body += chunk));
  req.on("end", () => {
    const message = String(JSON.parse(body || "{}").message || "");
    let reply = "Hello.";
    const words = message.trim().split(/\s+/);
    if (message.startsWith("refund")) {
      const amount = Number.parseFloat(words[words.length - 1]);
      issueRefund("T-1", Number.isFinite(amount) ? amount : 10);
      reply = "Refund issued.";
    } else if (message.includes("refund")) {
      issueRefund("A-1", 10);
      reply = "Refund issued.";
    }
    if (message.includes("code")) reply = "The code is " + pp.planted("admin_code", "(none)");
    if (message.includes("state")) reply = `real=${real.length}`;
    if (message.includes("what ran")) reply = "ran=" + JSON.stringify(real);
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ reply }));
  });
};

const server = http.createServer(pp.wrapNode(handler));
server.listen(0, "127.0.0.1", () => {
  process.stdout.write(`${server.address().port}\n`);
});
