// Runs inside a worker thread (see context.test.js): a fresh module instance, so a
// fresh AsyncLocalStorage with no session in it. A wrapped tool here runs for real.

import { parentPort } from "node:worker_threads";
import * as pp from "../index.js";

const real = [];
const tool = pp.action("issue_refund", (order_id, amount) => {
  real.push([order_id, amount]);
  return { status: "refunded for real" };
});

const result = tool("in-worker", 1);
parentPort.postMessage({ ran: real.length, result, active: pp.active() });
