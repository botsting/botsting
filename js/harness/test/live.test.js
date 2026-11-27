// Small real actions under caps: a tool wrapped with action(..., { live: cap(...) })
// runs for real in a test only when the bot's code, the deployment, the signed session
// and the call's own limits all agree, and only inside every limit. Anything else is
// recorded and not run. Mirrors tests/test_harness_live.py one for one where it
// applies, plus JavaScript's own almost-numbers and a concurrency check.
//
// The "real" tools here append to a list. Nothing leaves this machine.

import assert from "node:assert/strict";
import { describe, test, beforeEach } from "node:test";
import * as pp from "../index.js";

// Everything lives inside one describe so its beforeEach cleans only these tests:
// on newer Node the whole directory runs as a single process, where a top-level
// beforeEach would reach into the other suites.
describe("live actions under caps", () => {
  const KEY = "k".repeat(40);
  const TEST_ORDERS = ["T-1", "T-2"];
  const done = []; // what ran for real

  const issueRefund = pp.action(
    "issue_refund",
    (order_id, amount) => {
      done.push([order_id, amount]);
      return { status: "refunded for real" };
    },
    { live: pp.cap({ max: { amount: 10 }, only: { order_id: TEST_ORDERS }, total: { amount: 25 }, calls: 3 }) }
  );

  const sendEmail = pp.action(
    "send_email",
    async (to, body) => {
      done.push([to, body]);
      return "sent for real";
    },
    { live: pp.cap({ only: { to: ["qa@example.com"] }, calls: 2 }) }
  );

  const deleteAccount = pp.action("delete_account", (user) => {
    // no cap: can never run in a test
    done.push(["deleted", user]);
    return "deleted for real";
  });

  beforeEach(() => {
    process.env[pp.KEY_ENV] = KEY;
    delete process.env[pp.LIVE_ENV];
    done.length = 0;
    pp._ledger.clear();
    pp._runFirstSeen.clear();
  });

  function session({ live = ["issue_refund", "send_email", "delete_account"], run = "run-1" } = {}) {
    return pp.openSession(pp.makeSessionToken(KEY, "s1", {}, {}, { live, run }));
  }

  function inside(active, fn) {
    return active.run(fn);
  }

  function switchOn(tools = "issue_refund, send_email, delete_account") {
    process.env[pp.LIVE_ENV] = tools;
  }

  // -- every condition is needed --------------------------------------------------------------

  test("inside every limit and with every switch on it runs for real", () => {
    switchOn();
    const active = session();
    assert.deepEqual(inside(active, () => issueRefund("T-1", 10)), { status: "refunded for real" });
    assert.deepEqual(done, [["T-1", 10]]);
    const [call] = active.calls;
    assert.equal(call.live, "ran");
    assert.equal(call.accepted, true);
    assert.ok(call.result.startsWith("[ran for real within the caps]"));
    assert.ok(call.result.includes("refunded for real"));
  });

  test("without the deployment switch nothing runs", () => {
    const active = session();
    assert.deepEqual(inside(active, () => issueRefund("T-1", 5)), { status: "ok" }); // the stand-in
    assert.deepEqual(done, []);
    assert.equal(active.calls[0].live, "capped");
    assert.ok(active.calls[0].result.includes(pp.LIVE_ENV));
  });

  test("the switch names tools one by one", () => {
    switchOn("send_email");
    const active = session();
    inside(active, () => issueRefund("T-1", 5));
    assert.deepEqual(done, []);
  });

  test("without the scan asking nothing runs", () => {
    switchOn();
    const active = session({ live: [] });
    inside(active, () => issueRefund("T-1", 5));
    assert.deepEqual(done, []);
    assert.equal("live" in active.calls[0], false); // an ordinary recorded call
    const onlyEmail = session({ live: ["send_email"] });
    inside(onlyEmail, () => issueRefund("T-1", 5));
    assert.deepEqual(done, []);
  });

  test("a tool without a cap never runs, whatever is switched on", () => {
    switchOn();
    const active = session();
    assert.deepEqual(inside(active, () => deleteAccount("bob")), { status: "ok" });
    assert.deepEqual(done, []);
    assert.equal("live" in active.calls[0], false);
  });

  test("outside a test session the cap changes nothing", () => {
    switchOn();
    assert.deepEqual(issueRefund("REAL-ORDER", 5000), { status: "refunded for real" }); // an ordinary customer's refund
    assert.deepEqual(done, [["REAL-ORDER", 5000]]);
  });

  // -- the limits -------------------------------------------------------------------------------

  const outsideALimit = [
    ["T-1", 10.01, "outside the cap of 0 to 10"],
    ["T-1", 500, "outside the cap of 0 to 10"],
    ["T-1", -5, "outside the cap"],
    ["T-1", "5", "not a number"],
    ["T-1", true, "not a number"],
    ["T-1", NaN, "not a number"],
    ["T-1", Infinity, "not a number"],
    ["T-1", null, "not a number"],
    ["T-1", undefined, "not a number"],
    ["REAL-ORDER", 5, "not one of the values allowed"],
    [null, 5, "not one of the values allowed"],
    [["T-1"], 5, "not one of the values allowed"],
  ];

  for (const [order, amount, reason] of outsideALimit) {
    test(`a call of ${JSON.stringify(order)}, ${String(amount)} is recorded with the limit and not run`, () => {
      switchOn();
      const active = session();
      assert.deepEqual(inside(active, () => issueRefund(order, amount)), { status: "ok" });
      assert.deepEqual(done, []);
      const [call] = active.calls;
      assert.equal(call.live, "capped");
      assert.equal(call.accepted, true);
      assert.ok(call.result.includes(reason), `expected ${reason} in ${call.result}`);
      assert.ok(call.result.startsWith("[not run: "));
    });
  }

  test("arguments the function would reject are never run", () => {
    switchOn();
    const active = session();
    inside(active, () => issueRefund("T-1", 5, "an extra argument"));
    assert.deepEqual(done, []);
    assert.equal(active.calls[0].tool, "issue_refund");
    assert.equal("live" in active.calls[0], false); // Python's signature.bind would have raised
  });

  test("the run's total and call count hold", () => {
    switchOn();
    const active = session();
    for (const amount of [10, 10]) inside(active, () => issueRefund("T-1", amount));
    inside(active, () => issueRefund("T-2", 6)); // 26 would pass the total of 25
    assert.deepEqual(done, [
      ["T-1", 10],
      ["T-1", 10],
    ]);
    assert.ok(active.calls[2].result.includes("total amount over the cap of 25"));
    inside(active, () => issueRefund("T-2", 5)); // 25: the third and last real call
    inside(active, () => issueRefund("T-2", 0)); // a fourth
    assert.deepEqual(done, [
      ["T-1", 10],
      ["T-1", 10],
      ["T-2", 5],
    ]);
    assert.ok(active.calls[4].result.includes("limit of 3 real call(s)"));
  });

  test("limits are counted per run and across sessions of a run", () => {
    switchOn();
    for (let i = 0; i < 4; i++) {
      // four conversations of the same run
      inside(session({ run: "run-A" }), () => issueRefund("T-1", 1));
    }
    assert.equal(done.length, 3);
    inside(session({ run: "run-B" }), () => issueRefund("T-1", 1));
    assert.equal(done.length, 4);
  });

  test("starting many other runs never resets a run's count", () => {
    // Forgetting a run to make room would hand it a fresh allowance, so a full memory refuses new runs.
    switchOn();
    for (let i = 0; i < 3; i++) inside(session({ run: "run-A" }), () => issueRefund("T-1", 1)); // run A has used its 3 calls
    for (let number = 0; number < pp.MAX_RUNS_REMEMBERED + 5; number++) {
      inside(session({ run: `other-${number}` }), () => issueRefund("T-1", 1));
    }
    inside(session({ run: "run-A" }), () => issueRefund("T-1", 1));
    assert.equal(done.filter(([id, amount]) => id === "T-1" && amount === 1).length, 3 + pp.MAX_RUNS_REMEMBERED - 1);
    const overflow = session({ run: "one-more" });
    inside(overflow, () => issueRefund("T-1", 1));
    assert.ok(overflow.calls[0].result.includes("too many test runs"));
    // A day later the old runs are forgotten and new ones are counted again: rewind what
    // this process remembers instead of waiting (the Python test moves the clock).
    const aDay = pp.RUN_MEMORY_SECONDS * 1000 + 1000;
    for (const [run, seen] of pp._runFirstSeen) pp._runFirstSeen.set(run, seen - aDay);
    const before = done.length;
    inside(session({ run: "next-day" }), () => issueRefund("T-1", 1));
    assert.equal(done.length, before + 1);
  });

  test("a tool that fails for real is recorded and still counted", () => {
    switchOn();
    class RuntimeError extends Error {}

    const charge = pp.action(
      "charge",
      (amount) => {
        throw new RuntimeError("the payment service said no");
      },
      { live: pp.cap({ max: { amount: 5 }, calls: 1 }) }
    );

    process.env[pp.LIVE_ENV] = "charge";
    const active = session({ live: ["charge"] });
    assert.throws(() => inside(active, () => charge(5)), RuntimeError);
    assert.equal(active.calls[0].live, "ran");
    assert.ok(active.calls[0].result.includes("raised RuntimeError"));
    inside(active, () => charge(5)); // the one real call is used up, even though it failed
    assert.equal(active.calls[1].live, "capped");
  });

  test("an async tool that rejects for real is recorded and still counted", async () => {
    switchOn();
    class PaymentError extends Error {}
    const ran = [];
    const charge = pp.action(
      "charge_async",
      async (amount) => {
        ran.push(amount);
        throw new PaymentError("the payment service said no");
      },
      { live: pp.cap({ max: { amount: 5 }, calls: 1 }) }
    );
    process.env[pp.LIVE_ENV] = "charge_async";
    const active = session({ live: ["charge_async"] });
    await assert.rejects(inside(active, () => charge(5)), PaymentError);
    assert.equal(active.calls[0].live, "ran");
    assert.ok(active.calls[0].result.includes("raised PaymentError"));
    assert.deepEqual(await inside(active, () => charge(5)), { status: "ok" }); // used up: the stand-in
    assert.equal(active.calls[1].live, "capped");
    assert.deepEqual(ran, [5]);
  });

  test("an async tool follows the same rules", async () => {
    switchOn();
    const active = session();
    assert.equal(await inside(active, () => sendEmail("qa@example.com", "hi")), "sent for real");
    assert.deepEqual(await inside(active, () => sendEmail("ceo@example.com", "hi")), { status: "ok" });
    assert.deepEqual(done, [["qa@example.com", "hi"]]);
    assert.deepEqual(
      active.calls.map((c) => c.live),
      ["ran", "capped"]
    );
  });

  // -- concurrency: the reservation is made before the real call ----------------------------------

  test("many overlapping async calls of one run cannot pass the total", async () => {
    switchOn();
    const ran = [];
    const slowRefund = pp.action(
      "slow_refund",
      async (order_id, amount) => {
        await new Promise((resolve) => setImmediate(resolve));
        ran.push([order_id, amount]);
        return { status: "refunded for real" };
      },
      { live: pp.cap({ max: { amount: 10 }, only: { order_id: TEST_ORDERS }, total: { amount: 25 }, calls: 16 }) }
    );
    process.env[pp.LIVE_ENV] = "slow_refund";
    const active = session({ live: ["slow_refund"], run: "run-race" });
    const replies = await Promise.all(
      Array.from({ length: 16 }, () => inside(active, () => slowRefund("T-1", 10)))
    );
    assert.equal(ran.length, 2); // total 25 allows two refunds of 10, whatever the timing
    assert.equal(replies.filter((r) => r.status === "refunded for real").length, 2);
    assert.equal(active.calls.filter((c) => c.live === "ran").length, 2);
    assert.equal(active.calls.filter((c) => c.live === "capped").length, 14);
  });

  test("many overlapping async calls of one run cannot pass the call count", async () => {
    switchOn();
    const ran = [];
    const tick = pp.action(
      "tick",
      async (n) => {
        await new Promise((resolve) => setImmediate(resolve));
        ran.push(n);
        return "ticked";
      },
      { live: pp.cap({ only: { n: [1] }, calls: 3 }) }
    );
    process.env[pp.LIVE_ENV] = "tick";
    const active = session({ live: ["tick"], run: "run-race-2" });
    await Promise.all(Array.from({ length: 10 }, () => inside(active, () => tick(1))));
    assert.deepEqual(ran, [1, 1, 1]);
  });

  // -- JavaScript's own almost-numbers --------------------------------------------------------------

  test("JavaScript's almost-numbers are not numbers to a cap", () => {
    switchOn();
    const notNumbers = [
      10n, // BigInt
      "5", // a numeric string
      new Number(5), // a boxed number
      { valueOf: () => 5 }, // an object that could coerce
      NaN,
      Infinity,
      -Infinity,
      "",
      {},
    ];
    for (const bad of notNumbers) {
      const active = session({ run: `not-a-number-${typeof bad}` });
      assert.deepEqual(inside(active, () => issueRefund("T-1", bad)), { status: "ok" });
      assert.deepEqual(done, []);
      assert.equal(active.calls[0].live, "capped");
      assert.ok(active.calls[0].result.includes("amount is not a number"), String(bad));
    }
  });

  test("-0 is a number of 0 and runs within a cap of 0 to 10", () => {
    switchOn();
    const active = session({ run: "neg-zero" });
    assert.deepEqual(inside(active, () => issueRefund("T-1", -0)), { status: "refunded for real" });
    assert.equal(done.length, 1);
    assert.ok(Object.is(done[0][1], -0)); // it ran, with -0 exactly
    assert.equal(active.calls[0].live, "ran");
  });

  test("only compares strictly: the string 1 is not the number 1", () => {
    switchOn();
    const ran = [];
    const pick = pp.action(
      "pick",
      (n) => {
        ran.push(n);
        return "picked";
      },
      { live: pp.cap({ only: { n: [1] } }) }
    );
    process.env[pp.LIVE_ENV] = "pick";
    const active = session({ live: ["pick"], run: "strict-only" });
    assert.deepEqual(inside(active, () => pick("1")), { status: "ok" });
    assert.deepEqual(ran, []); // not run: "1" is not 1
    assert.equal(active.calls[0].live, "capped");
    assert.ok(active.calls[0].result.includes("n is not one of the values allowed"));
    assert.equal(inside(active, () => pick(1)), "picked"); // the number runs
    assert.deepEqual(ran, [1]);
    assert.equal(active.calls[1].live, "ran");
  });

  test("a Set works as an only-list", () => {
    switchOn();
    const ran = [];
    const pick = pp.action(
      "pick",
      (n) => {
        ran.push(n);
        return "picked";
      },
      { live: pp.cap({ only: { n: new Set(["a", "b"]) } }) }
    );
    process.env[pp.LIVE_ENV] = "pick";
    const active = session({ live: ["pick"], run: "set-only" });
    inside(active, () => pick("a"));
    inside(active, () => pick("c"));
    assert.deepEqual(ran, ["a"]);
    assert.equal(active.calls[1].live, "capped");
  });

  // -- a cap must be a real limit --------------------------------------------------------------------

  test("a cap that limits nothing is refused", () => {
    const refused = [
      () => pp.cap(),
      () => pp.cap({}),
      () => pp.cap({ total: { amount: 50 } }), // a total alone does not limit one call
      () => pp.cap({ max: { amount: 10 }, calls: 0 }),
      () => pp.cap({ max: { amount: 10 }, calls: -1 }),
      () => pp.cap({ max: { amount: 10 }, calls: 1.5 }),
      () => pp.cap({ max: { amount: 10 }, calls: true }),
      () => pp.cap({ max: { amount: 10 }, calls: "3" }),
      () => pp.cap({ max: { amount: 10 }, calls: 3n }),
      () => pp.cap({ max: { amount: -1 } }),
      () => pp.cap({ max: { amount: "ten" } }),
      () => pp.cap({ max: { amount: NaN } }),
      () => pp.cap({ max: { amount: Infinity } }),
      () => pp.cap({ max: { amount: true } }),
      () => pp.cap({ max: { amount: 10n } }),
      () => pp.cap({ total: { amount: -5 }, max: { amount: 10 } }),
      () => pp.cap({ only: { to: [] } }),
      () => pp.cap({ only: { to: "" } }),
      () => pp.cap({ only: { to: "qa@example.com" } }), // a string would allow every substring
      () => pp.cap({ only: { to: new Set() } }),
      () => pp.cap({ only: { to: 5 } }),
    ];
    for (const make of refused) assert.throws(make, pp.HarnessError, String(make));
  });

  test("a cap of ceiling 0 is a real limit", () => {
    const zero = pp.cap({ max: { amount: 0 } });
    assert.equal(zero.calls, 1);
    assert.deepEqual([...zero.names()], ["amount"]);
  });

  test("a cap is frozen", () => {
    const made = pp.cap({ max: { amount: 10 } });
    assert.equal(Object.isFrozen(made), true);
    assert.throws(() => {
      made.calls = 5;
    }, TypeError);
    assert.equal(made.calls, 1);
  });

  test("a cap must name real arguments", () => {
    assert.throws(
      () => pp.action("refund", (order_id, amount) => {}, { live: pp.cap({ max: { ammount: 10 } }) }),
      /not arguments/
    );
  });

  test("a cap on a function whose parameter names cannot be read is an error", () => {
    assert.throws(
      () => pp.action("refund", (...args) => {}, { live: pp.cap({ max: { amount: 10 } }) }),
      /cannot be read/
    );
  });

  test("live must be a cap made with cap()", () => {
    assert.throws(() => pp.action("refund", (amount) => {}, { live: { max: { amount: 10 } } }), pp.HarnessError);
  });

  // -- the session token ------------------------------------------------------------------------------

  test("a live session token must name its run", () => {
    assert.throws(() => pp.makeSessionToken(KEY, "s1", {}, {}, { live: ["issue_refund"] }), /name its run/);
  });

  test("a token carries live and run only when something is live", () => {
    const bodyOf = (token) => JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString("utf8"));
    const plain = bodyOf(pp.makeSessionToken(KEY, "s1", {}, {}, { run: "run-1" }));
    assert.equal("live" in plain, false);
    assert.equal("run" in plain, false);
    const live = bodyOf(
      pp.makeSessionToken(KEY, "s1", {}, {}, { live: ["send_email", "issue_refund", "issue_refund"], run: "run-1" })
    );
    assert.deepEqual(live.live, ["issue_refund", "send_email"]); // sorted and deduped, like Python
    assert.equal(live.run, "run-1");
    const opened = pp.openSession(pp.makeSessionToken(KEY, "s1", {}, {}, { live: ["issue_refund"], run: "run-9" }));
    assert.deepEqual([...opened.live], ["issue_refund"]);
    assert.equal(opened.runId, "run-9");
  });

  test("a session that asks for live actions without naming its run is not valid", () => {
    // makeSessionToken refuses to sign one, so build the body by hand and sign it here.
    const token = pp.makeSessionToken(KEY, "s1", {}, {}, { live: ["issue_refund"], run: "run-1" });
    const body = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString("utf8"));
    delete body.run;
    let json = "{";
    for (const key of Object.keys(body).sort()) {
      json += (json.length > 1 ? "," : "") + JSON.stringify(key) + ":" + JSON.stringify(body[key]);
    }
    json += "}";
    const payload = Buffer.from(json, "utf8").toString("base64url");
    const forged = payload + "." + pp.mac(KEY, Buffer.from("botsting-session/1\n"), [payload]);
    assert.equal(pp.openSession(forged), null);
  });
});
