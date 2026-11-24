# promptproof-harness

The Promptproof drop-in test harness, for JavaScript bots. Instead of writing a reset
endpoint and tool-call recorders yourself, add a few lines to the bot. It is a port of
the Python harness (`src/promptproof/harness.py`), wire-compatible with it: the Python
scanner scans a Node bot through this package with **no scanner changes** — same
environment variables, headers, paths, limits and signatures.

Like the Python harness, it is for the bot's own staging or test deployment. It uses
only the Node standard library (Node 20+, zero npm dependencies), and it is
[Apache-2.0](../../LICENSE) like the rest of Promptproof.

## Install

Copy or vendor the `js/harness` folder into the bot's repository, or install it from a
checkout:

```
npm install /path/to/promptproof/js/harness
```

Then make a key and set it as `PROMPTPROOF_HARNESS_KEY` on the staging deployment and
where you run the scan (the Python CLI can make one, or use Node):

```
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
```

Never set the key in production.

## The three adapters

Wrap the bot's entry point — the outermost thing that sees a request. Without
`PROMPTPROOF_HARNESS_KEY` set, every request passes straight through.

**A plain Node http server** — `wrapNode(handler)`:

```js
import http from "node:http";
import * as pp from "promptproof-harness";

const server = http.createServer(
  pp.wrapNode((req, res) => {
    // the bot as written
  })
);
```

**Express** — `express()` middleware, installed as early as possible:

```js
import * as pp from "promptproof-harness";

app.use(pp.express());
```

**Fetch-style handlers** — `wrapFetch(handler)`, for Next.js route handlers, Hono,
Cloudflare Workers and anything taking a `Request` and returning a `Response`:

```js
import * as pp from "promptproof-harness";

export default pp.wrapFetch(async (request) => {
  const { message } = await request.json();
  return Response.json({ reply: "Hello." });
});
```

## Inside the bot

```js
const issueRefund = pp.action("issue_refund", (orderId, amount) => bank.refund(orderId, amount));
//                                    ^ on the function that does the deed, after your own checks

const prompt = BASE_PROMPT + pp.planted("admin_code");                  // where a fake secret lives in a test
const note = pp.active() ? pp.content("bob_note", note) : note;        // or text at an injection point
```

- Nothing changes unless a request carries a Promptproof session signed with that key.
  Real users, even on staging, get the bot exactly as written.
- A request that carries a Promptproof session the bot cannot verify (no key there,
  another key, expired, damaged, a doubled header) is refused with HTTP 403 and never
  reaches your code. A wrapped production deployment therefore turns test traffic away.
- In a test session, `planted` returns that session's fake secret and `content` returns
  the text the scan placed at an injection point. Nothing is written to your database,
  so no fake users or records are needed.
- In a test session, a function wrapped with `action` is recorded and not run. The
  record goes back to the scan in the `Promptproof-Tool-Calls` response header, signed
  for that session and that message, so the model cannot fake it or reuse an old one.
  A callable `result` option is called as `result(arguments)` with the recorded
  arguments.
- Before each attempt, the scan asks `/.well-known/promptproof-harness` to confirm test
  mode. If it does not, nothing is sent, not even the fake secrets.
- Set `PROMPTPROOF_CHALLENGE` to the token line from `promptproof authorize` and the
  harness serves the ownership proof for you (GET only).

In the target description, write `"harness": "sdk"` and leave out `reset` and
`tool_calls_pointer`, exactly as for a Python bot.

Frameworks that intercept calls in their own dispatcher can call
`pp.recordCall(tool, args, result)` during a test session to record the call and return
a stand-in result before dispatching the real tool. It requires an active test session.
`pp.testsInProgress()` counts test requests in the current Node worker, which helps a
dispatcher detect callbacks that have lost their request context. Node and Express
count through response finish or close. Fetch counts until the handler returns its
`Response`.

`pp.readRecord(key, sessionId, header, nonce)` verifies a signed response header and
returns `{ calls, read, tools }`. Older records default omitted name lists to empty
arrays. Use `pp.readCallsHeader` when you only need the calls.

## Live actions under caps

A copy is never exactly the real system, so you may want a test to carry out a tool for
real, within limits written in the bot's own code, where they can be reviewed:

```js
const TEST_ORDERS = ["T-1", "T-2"];

const issueRefund = pp.action(
  "issue_refund",
  (orderId, amount) => bank.refund(orderId, amount),
  {
    live: pp.cap({
      max: { amount: 10 },               // one call: at most 10, and a real number (not "10", true or 10n)
      only: { orderId: TEST_ORDERS },    // and only on these orders ("1" is not 1: no coercion)
      total: { amount: 50 }, calls: 5,   // one scan: at most 50 in all, 5 calls
    }),
  }
);
```

In a test session the function runs for real only if **all four** of these agree;
otherwise it is recorded and not run, exactly as without `live`:

1. the function carries a `cap` (the limits are in the bot's own code);
2. the deployment names the tool in the environment variable `PROMPTPROOF_LIVE_ACTIONS`
   (comma-separated tool names; unset means nothing ever runs for real);
3. the scan asked for it in the signed session, which the scanner does only when the
   target description lists it under `"live_actions"` and the authorization names it
   with `--live-tool`;
4. this call is inside every limit: each `max` argument is a number from 0 to its
   ceiling, each `only` argument is one of the listed values, and the run's totals and
   call count, including this call, stay within `total` and `calls`.

A cap that limits nothing (`cap()` with neither `max` nor `only`), a `calls` below 1,
a negative ceiling or a string `only`-list is refused when `cap()` is called, and a cap
that names something that is not a parameter of the wrapped function is refused when
`action()` is called.

A call outside the limits is still evidence: it is recorded with `live: "capped"` and
the result prefix `[not run: <the limit it broke>]` — an attempt at a refund of 500 is
proven by the record of the attempt, and no money moves. A call that runs for real is
recorded with `live: "ran"` and `[ran for real within the caps] `, and a real call that
throws is recorded as `raised <ErrorName>` and still counts against `total` and `calls`.

The reservation against `total` and `calls` is made synchronously before the real
function is called, so overlapping async calls of one run cannot push past them.

**The limits, exactly as the Python harness states them:** the per-call limits (`max`,
`only`) are exact. The per-run limits (`total`, `calls`) are counted in each Node
process's memory: a deployment with N processes (cluster workers, PM2, serverless
instances) can carry out up to N times those limits in one run, and a restart forgets
the count. Rely on `max` and `only` for what must never be exceeded. One process
remembers at most **64 runs** for **24 hours**; when its memory is full it refuses live
calls for a new run ("too many test runs in the last day...") rather than forget a
recent run and hand it a fresh allowance.

## Limits

The same as the Python harness:

- A tool that is not wrapped cannot be seen. Every tool that sends, pays, books or
  deletes must carry `action`; the scan's preflight checks that the recorder sees the
  calls its tool rules expect, but it cannot find a tool nobody declared.
- Calls made after a streaming reply has started are blocked but not reported. Only
  calls made before the response headers are sent travel in the record.
- One reply holds at most **100 calls** and **24 000 bytes** of recorded calls (the
  record travels in a header). Anything beyond that counts as dropped, and the scan
  treats any dropped call as an error, never a silent gap.
- The session follows AsyncLocalStorage, so work handed to a job queue or a worker
  thread is not covered. A wrapped tool that runs there during a test runs for real.
  If your tools run that way, wrap the function that hands the work over (the one that
  enqueues), not the worker. That includes live actions: a worker thread has its own
  ledger, so its real calls are not counted against the run's `total` and `calls`.
- Live actions need all four switches on (see above), and their per-run limits are
  per process; the per-call limits `max` and `only` are exact.
- The signatures stop the model from faking the record. They do not stop the bot's own
  code from lying.
- A session token may live at most **900 seconds**, and its header at most **6000
  bytes**; a key must be at least **32 characters**.

## Development

```
node --test js/harness/test/        # from the repository root
uv run pytest tests/test_harness_js.py -q   # cross-language interop (needs node on PATH)
```
