// The Express adapter, exercised through the smallest possible Express-shaped
// pipeline (no dependencies: the middleware only needs req/res/next).

import assert from "node:assert/strict";
import http from "node:http";
import { after, test } from "node:test";
import * as pp from "../index.js";

const KEY = "k".repeat(40);
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

// A stand-in for Express's dispatch: middleware, then a route.
function appWith(middleware) {
  return (req, res) => {
    const route = (req, res) => {
      if ((req.url || "").split("?")[0] !== "/chat") {
        res.writeHead(404, { "content-type": "text/plain" });
        res.end("not found");
        return;
      }
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        assert.equal(pp.testsInProgress(), pp.active() ? 1 : 0);
        const message = JSON.parse(body || "{}").message || "";
        let reply = "Hello.";
        if (message.includes("refund")) {
          issueRefund("A-1", 10);
          reply = "Refund issued.";
        }
        if (message.includes("code")) reply = "The code is " + pp.planted("admin_code", "(none)");
        res.setHeader("content-type", "application/json"); // what res.json() does underneath
        res.end(JSON.stringify({ reply }));
      });
    };
    middleware(req, res, (err) => {
      if (err) {
        res.writeHead(500, { "content-type": "text/plain" });
        res.end("error");
        return;
      }
      route(req, res);
    });
  };
}

const post = (baseUrl, headers = {}, message = "a refund and the code") =>
  fetch(baseUrl + "/chat", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify({ message }),
  });

test("an ordinary request reaches the route and runs tools as written", async () => {
  process.env[pp.KEY_ENV] = KEY;
  realRefunds.length = 0;
  const baseUrl = await serve(appWith(pp.express()));
  const response = await post(baseUrl);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { reply: "The code is (none)" });
  assert.equal(response.headers.get(pp.CALLS_HEADER), null);
  assert.deepEqual(realRefunds, [["A-1", 10]]);
});

test("an unverifiable session is refused before any route", async () => {
  process.env[pp.KEY_ENV] = KEY;
  realRefunds.length = 0;
  const baseUrl = await serve(appWith(pp.express()));
  const response = await post(baseUrl, { [pp.SESSION_HEADER]: "junk" }, "a refund please");
  assert.equal(response.status, 403);
  assert.match(await response.text(), /was not run/);
  assert.equal(response.headers.get(pp.CALLS_HEADER), null);
  assert.deepEqual(realRefunds, []);
});

test("a valid session reaches the route with the session active", async () => {
  process.env[pp.KEY_ENV] = KEY;
  realRefunds.length = 0;
  const baseUrl = await serve(appWith(pp.express()));
  const token = pp.makeSessionToken(KEY, "s1", { admin_code: "FAKE-CODE" }, {}, { nonce: "n1" });
  const response = await post(baseUrl, { [pp.SESSION_HEADER]: token }, "a refund and the code");
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { reply: "The code is FAKE-CODE" });
  assert.equal(pp.testsInProgress(), 0);
  assert.deepEqual(realRefunds, []);
  const calls = pp.readCallsHeader(KEY, "s1", response.headers.get(pp.CALLS_HEADER), "n1");
  assert.deepEqual(calls.map((c) => [c.tool, c.arguments]), [
    ["issue_refund", { order_id: "A-1", amount: "10" }],
  ]);
});

test("the readiness path answers for a valid session", async () => {
  process.env[pp.KEY_ENV] = KEY;
  const baseUrl = await serve(appWith(pp.express()));
  const token = pp.makeSessionToken(KEY, "probe", {});
  const response = await fetch(baseUrl + pp.READY_PATH, {
    method: "POST",
    headers: { [pp.SESSION_HEADER]: token },
    body: "{}",
  });
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "promptproof harness ready\n");
  assert.deepEqual(pp.readCallsHeader(KEY, "probe", response.headers.get(pp.CALLS_HEADER)), []);
});
