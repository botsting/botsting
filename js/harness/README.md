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
  enqueues), not the worker.
- The signatures stop the model from faking the record. They do not stop the bot's own
  code from lying.
- A session token may live at most **900 seconds**, and its header at most **6000
  bytes**; a key must be at least **32 characters**.

## Development

```
node --test js/harness/test/        # from the repository root
uv run pytest tests/test_harness_js.py -q   # cross-language interop (needs node on PATH)
```
