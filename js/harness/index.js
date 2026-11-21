// The drop-in test harness for JavaScript bots: a few lines in the bot's own code
// instead of a test endpoint. Port of promptproof/harness.py; wire-compatible with
// the Python scanner, which needs no changes to scan a Node bot.
//
//   import * as pp from "promptproof-harness";
//
//   const server = http.createServer(pp.wrapNode(handler));   // a plain Node bot
//   app.use(pp.express());                                    // an Express bot
//   export default pp.wrapFetch(handler);                     // a fetch-style bot (Next.js, Hono, Cloudflare)
//
//   const issueRefund = pp.action("issue_refund", (orderId, amount) => refunds.push(...));  // risky tool
//   const prompt = BASE_PROMPT + pp.planted("admin_code");    // where a fake secret lives in a test
//
// When is it on? Only for a request that carries a valid Promptproof session, signed
// with the key in PROMPTPROOF_HARNESS_KEY. Set that key on the staging or test
// deployment only. A request without the Promptproof-Session header (every real user)
// reaches the bot untouched: tools run as written and planted() returns its default.
//
// A request that carries the header but is not a valid session here (no key on this
// deployment, another key, an expired or damaged session) is refused with HTTP 403
// and never reaches the bot. It says it is a test message; running it as an ordinary
// one, with real tools, is the one thing that must not happen.
//
// What a test session does: planted() returns the fake secret the scan chose for that
// slot, content() returns text the scan placed at an injection point, and a function
// wrapped with action() is recorded and never run — the call and its arguments go back
// to the scanner in the Promptproof-Tool-Calls response header, signed for that
// session and that one message so the record cannot be made up, moved to another
// conversation or reused for a later message.
//
// Small real actions, under caps: a tool wrapped with action(..., { live: cap(...) })
// may be carried out for real during a test session, only when four things agree —
// the cap in this code, the deployment switch PROMPTPROOF_LIVE_ACTIONS, the scan's
// signed session naming the tool and its run, and the call being inside every limit.
// Otherwise it is recorded and not run, exactly as without `live`. See README.md.
//
// The signatures are byte-identical to the Python harness: the MAC input is
// domain + json.dumps(list_of_parts) with Python's default separators (", ") and
// ASCII escaping, reproduced exactly by the py* helpers below.
//
// What it does not do: it cannot see a tool that is not wrapped, and it follows the
// request, not the work — the session lives in an AsyncLocalStorage, so work handed
// to a job queue or a worker thread is not covered (see README.md). It uses only the
// Node standard library.

import { AsyncLocalStorage, AsyncResource } from "node:async_hooks";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export const KEY_ENV = "PROMPTPROOF_HARNESS_KEY";
export const CHALLENGE_ENV = "PROMPTPROOF_CHALLENGE";
export const LIVE_ENV = "PROMPTPROOF_LIVE_ACTIONS";
export const CHALLENGE_PATH = "/.well-known/promptproof-challenge.txt";
export const READY_PATH = "/.well-known/promptproof-harness";
export const SESSION_HEADER = "Promptproof-Session";
export const CALLS_HEADER = "Promptproof-Tool-Calls";
export const MIN_KEY_LENGTH = 32;
export const MAX_TOKEN_BYTES = 6000; // most servers refuse headers much larger than 8 KB
export const MAX_CALLS = 100;
export const MAX_RECORD_BYTES = 24_000; // of recorded calls in one reply; the record travels in a header
export const MAX_LIFETIME_SECONDS = 900;
export const MAX_RUNS_REMEMBERED = 64; // runs whose real calls this process keeps count of
export const RUN_MEMORY_SECONDS = 24 * 3600; // far longer than any scan; a run's count is never dropped while it could go on

const SESSION_DOMAIN = Buffer.from("promptproof-session/1\n");
const CALLS_DOMAIN = Buffer.from("promptproof-calls/1\n");
const DEFAULT_RESULT = { status: "ok" };
const READY = Buffer.from("promptproof harness ready\n");
const REFUSED = Buffer.from(
  "promptproof: this request carries a test session that is not valid here, so it was not run\n"
);

export class HarnessError extends Error {
  constructor(message) {
    super(message);
    this.name = "HarnessError";
  }
}

// -- Python-exact JSON, so every signed byte matches ---------------------------------------
//
// Python json.dumps(..., ensure_ascii=True) escapes ", \, the short escapes \b \t \n
// \f \r, every other control character and everything non-ASCII as \uXXXX (lowercase
// hex, surrogate pairs for astral characters). Key order is insertion order unless
// sort_keys is given, and separators are (", ", ": ") by default or (",", ":") compact.

function pyEscape(value) {
  let out = '"';
  for (const ch of value) {
    const cp = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (cp === 0x08) out += "\\b";
    else if (cp === 0x09) out += "\\t";
    else if (cp === 0x0a) out += "\\n";
    else if (cp === 0x0c) out += "\\f";
    else if (cp === 0x0d) out += "\\r";
    else if (cp >= 0x20 && cp <= 0x7e) out += ch; // Python leaves space..tilde literal, DEL included in the escapes
    else if (cp >= 0x10000) {
      // astral: Python emits a UTF-16 surrogate pair
      const v = cp - 0x10000;
      const hi = (0xd800 + (v >> 10)).toString(16).padStart(4, "0");
      const lo = (0xdc00 + (v & 0x3ff)).toString(16).padStart(4, "0");
      out += "\\u" + hi + "\\u" + lo;
    } else out += "\\u" + cp.toString(16).padStart(4, "0");
  }
  return out + '"';
}

function pyNumber(value) {
  if (Number.isInteger(value) && Math.abs(value) < 1e21) return String(value);
  return String(value); // JS and Python both print the shortest round-trip form for common values
}

function pyG(value) {
  // Python's f"{value:g}": at most 6 significant digits, trailing zeros stripped,
  // exponential form when the leading digit sits at 1e6 or beyond 1e-5 (1.23457e+06, 1e-05).
  if (Number.isNaN(value)) return "nan";
  if (value === Infinity) return "inf";
  if (value === -Infinity) return "-inf";
  const neg = value < 0 || Object.is(value, -0);
  const x = Math.abs(value);
  if (x === 0) return neg ? "-0" : "0";
  const exponentOf = (v) => parseInt(v.slice(v.indexOf("e") + 1), 10);
  const strip = (s) => (s.includes(".") ? s.replace(/0+$/, "").replace(/\.$/, "") : s);
  const e = exponentOf(x.toExponential()); // where the leading digit sits, before rounding
  let digits = strip(x.toPrecision(6));
  let exponent = 0;
  if (digits.includes("e")) {
    // rounding carried into a new decade (999999.6 -> 1e+06)
    const [mantissa, exp] = digits.split("e");
    digits = strip(mantissa);
    exponent = parseInt(exp, 10);
  }
  if (exponent !== 0 || e < -4 || e >= 6) {
    if (exponent === 0) {
      exponent = e;
      digits = strip(x.toExponential(5).split("e")[0]);
    }
    const sign = exponent < 0 ? "-" : "+";
    return (neg ? "-" : "") + digits + "e" + sign + String(Math.abs(exponent)).padStart(2, "0");
  }
  return (neg ? "-" : "") + digits;
}

function pyCmp(a, b) {
  // Python sorts strings by code point, not by UTF-16 unit.
  const A = Array.from(a);
  const B = Array.from(b);
  const n = Math.min(A.length, B.length);
  for (let i = 0; i < n; i++) {
    const x = A[i].codePointAt(0);
    const y = B[i].codePointAt(0);
    if (x !== y) return x < y ? -1 : 1;
  }
  return A.length - B.length;
}

function pyDumps(value, { compact = false, sortKeys = false } = {}) {
  const itemSep = compact ? "," : ", ";
  const kvSep = compact ? ":" : ": ";
  function enc(v) {
    if (v === null || v === undefined) return "null";
    if (typeof v === "string") return pyEscape(v);
    if (typeof v === "number") return pyNumber(v);
    if (typeof v === "boolean") return v ? "true" : "false";
    if (Array.isArray(v)) return "[" + v.map(enc).join(itemSep) + "]";
    if (typeof v === "object") {
      let keys = Object.keys(v);
      if (sortKeys) keys = keys.slice().sort(pyCmp);
      return "{" + keys.map((k) => pyEscape(k) + kvSep + enc(v[k])).join(itemSep) + "}";
    }
    return enc(String(v)); // Python's default=str for anything not serializable
  }
  try {
    return enc(value);
  } catch {
    return enc(String(value)); // circular structures: Python falls back to str() too
  }
}

// Python int(): truncates floats, accepts decimal strings, refuses anything else.
function pyInt(value) {
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("cannot convert float to integer");
    return value < 0 ? Math.ceil(value) : Math.floor(value);
  }
  if (typeof value === "boolean") return value ? 1 : 0;
  if (typeof value === "string") {
    if (/^[+-]?\d+$/.test(value.trim())) return parseInt(value, 10);
    throw new TypeError("invalid literal for int()");
  }
  throw new TypeError("an integer is required");
}

// Python str() for the JSON types a token can carry.
function pyStr(value) {
  if (value === null) return "None";
  if (value === true) return "True";
  if (value === false) return "False";
  if (typeof value === "number") return pyNumber(value);
  return String(value);
}

// -- signing (shared with the scanner and the Python harness) -------------------------------

const b64 = (data) => Buffer.from(data).toString("base64url"); // Node's base64url omits padding, like rstrip("=")
const unb64 = (text) => Buffer.from(text, "base64url");

export function mac(key, domain, parts) {
  // A list, so parts cannot run together; the bytes are Python's json.dumps exactly.
  const message = Buffer.concat([
    Buffer.isBuffer(domain) ? domain : Buffer.from(domain),
    Buffer.from(pyDumps([...parts]), "ascii"),
  ]);
  return createHmac("sha256", Buffer.from(key, "utf8")).update(message).digest("base64url");
}

function same(given, expected) {
  // Constant-time comparison that also accepts whatever bytes arrived in a header.
  const a = Buffer.from(given, "utf8");
  const b = Buffer.from(expected, "utf8");
  if (a.length === 0 || a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export function checkKey(key) {
  if (typeof key !== "string" || key.length < MIN_KEY_LENGTH) {
    throw new HarnessError(
      `${KEY_ENV} must be at least ${MIN_KEY_LENGTH} characters; make one with promptproof harness-key`
    );
  }
  return key;
}

export function newKey() {
  return randomBytes(32).toString("base64url");
}

export function makeSessionToken(
  key,
  sessionId,
  fixtures,
  content = {},
  { lifetimeSeconds = 300, now = null, nonce = "", live = [], run = "" } = {}
) {
  // What the scanner puts in the Promptproof-Session header of each message. The
  // nonce should be new for every message: the harness signs it into that message's
  // tool-call record.
  checkKey(key);
  if (!(lifetimeSeconds > 0) || lifetimeSeconds > MAX_LIFETIME_SECONDS) {
    throw new HarnessError(`a session token may live at most ${MAX_LIFETIME_SECONDS} seconds`);
  }
  const body = {
    v: 1,
    sid: sessionId,
    n: nonce,
    exp: pyInt((now === null ? Date.now() / 1000 : now) + lifetimeSeconds),
    fixtures: { ...fixtures },
    content: { ...content },
  };
  const liveTools = [...(live ?? [])];
  if (liveTools.length > 0) {
    // Tools the scan asks to have carried out for real, and the run their totals are counted under.
    if (!run) throw new HarnessError("a session that asks for live actions must name its run");
    body.live = [...new Set(liveTools)].sort(pyCmp);
    body.run = run;
  }
  const payload = b64(Buffer.from(pyDumps(body, { compact: true, sortKeys: true }), "utf8"));
  const token = payload + "." + mac(key, SESSION_DOMAIN, [payload]);
  if (token.length > MAX_TOKEN_BYTES) {
    throw new HarnessError(
      `the planted secrets and content come to ${token.length} bytes in the header, more than ${MAX_TOKEN_BYTES}; ` +
        "use shorter injection content"
    );
  }
  return token;
}

export function readCallsHeader(key, sessionId, value, nonce = "") {
  // What the scanner does with the Promptproof-Tool-Calls header. Raises HarnessError
  // if it was not made by a harness holding the key for this very session and message,
  // or if calls were left out.
  if (value === null || value === undefined) {
    throw new HarnessError(
      `the reply has no ${CALLS_HEADER} header: the harness did not see this as a test session ` +
        `(is ${KEY_ENV} the same on both sides, and is the app wrapped?)`
    );
  }
  const trimmed = String(value).trim();
  const dot = trimmed.indexOf(".");
  const payload = dot < 0 ? trimmed : trimmed.slice(0, dot);
  const macPart = dot < 0 ? "" : trimmed.slice(dot + 1);
  if (!macPart || !same(macPart, mac(key, CALLS_DOMAIN, [sessionId, nonce, payload]))) {
    throw new HarnessError("the tool-call record is not signed by the harness for this session and message");
  }
  let record;
  try {
    record = JSON.parse(unb64(payload).toString("utf8"));
    if (record === null || typeof record !== "object" || Array.isArray(record)) throw new TypeError("not an object");
    if (!("calls" in record)) throw new TypeError("no calls");
    var dropped = pyInt(record.dropped); // eslint-disable-line no-var
  } catch (error) {
    throw new HarnessError(`the tool-call record is unreadable: ${error && error.message ? error.message : error}`);
  }
  if (!Array.isArray(record.calls)) {
    throw new HarnessError("the tool-call record must hold a list of calls");
  }
  if (dropped) {
    throw new HarnessError(
      `the bot made more tool calls in one reply than the record holds (${MAX_CALLS} calls, ` +
        `${MAX_RECORD_BYTES} bytes); ${dropped} were not recorded`
    );
  }
  return record.calls;
}

// -- the session -----------------------------------------------------------------------------

export class Session {
  constructor(sid, fixtures, content, key, nonce = "", live = new Set(), runId = "") {
    this.sid = sid;
    this.fixtures = fixtures;
    this.content = content;
    this.key = key;
    this.nonce = nonce;
    this.live = live; // tools the scan asks to have carried out for real ("live" on the wire)
    this.runId = runId; // the run their totals are counted under ("run" on the wire)
    this.calls = [];
    this.dropped = 0;
    this.size = 0;
  }

  add(call) {
    // Record a call, or count it as dropped: the scanner treats any dropped call as an error.
    const size = pyDumps(call, { compact: true }).length;
    if (this.calls.length >= MAX_CALLS || this.size + size > MAX_RECORD_BYTES) {
      this.dropped += 1;
      return;
    }
    this.size += size;
    this.calls.push(call);
  }

  headerValue() {
    const record = { calls: this.calls, dropped: this.dropped };
    const payload = b64(Buffer.from(pyDumps(record, { compact: true }), "utf8"));
    return payload + "." + mac(this.key, CALLS_DOMAIN, [this.sid, this.nonce, payload]);
  }

  run(fn) {
    return storage.run(this, fn);
  }
}

const storage = new AsyncLocalStorage();

function envKey() {
  const key = process.env[KEY_ENV];
  if (!key) return null;
  return checkKey(key);
}

function required(body, name) {
  if (!(name in body)) throw new TypeError(`missing ${name}`);
  return body[name];
}

// A signed token is still read strictly, as the Python harness does: the right types or nothing.
function stringMap(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("not a mapping");
  }
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (typeof v !== "string") throw new TypeError("not text");
    out[k] = v;
  }
  return out;
}

function strictText(value) {
  if (typeof value !== "string") throw new TypeError("not text");
  return value;
}

function liveSet(value) {
  if (!Array.isArray(value)) throw new TypeError("not a list");
  return new Set(value.map(strictText));
}

export function openSession(token, now = null) {
  // A session for a validly signed, unexpired token; null for anything else.
  const key = envKey();
  if (key === null || !token || token.length > MAX_TOKEN_BYTES) return null;
  const trimmed = String(token).trim();
  const dot = trimmed.indexOf(".");
  const payload = dot < 0 ? trimmed : trimmed.slice(0, dot);
  const macPart = dot < 0 ? "" : trimmed.slice(dot + 1);
  if (!macPart || !same(macPart, mac(key, SESSION_DOMAIN, [payload]))) return null;
  let body;
  try {
    body = JSON.parse(unb64(payload).toString("utf8"));
    if (body === null || typeof body !== "object" || Array.isArray(body)) return null;
    var expires = required(body, "exp"); // eslint-disable-line no-var
    if (!Number.isInteger(expires)) return null;
    var sid = strictText(required(body, "sid")); // eslint-disable-line no-var
    var nonce = "n" in body ? strictText(body.n) : ""; // eslint-disable-line no-var
    var live = liveSet("live" in body ? body.live : []); // eslint-disable-line no-var
    var runId = "run" in body ? strictText(body.run) : ""; // eslint-disable-line no-var
    var fixtures = stringMap(required(body, "fixtures")); // eslint-disable-line no-var
    var content = stringMap("content" in body ? body.content : {}); // eslint-disable-line no-var
  } catch {
    return null;
  }
  if (body.v !== 1 || expires < (now === null ? Date.now() / 1000 : now)) return null;
  if (live.size > 0 && !runId) return null; // a session that asks for live actions must name its run
  return new Session(sid, fixtures, content, key, nonce, live, runId);
}

// -- what the bot's code calls ----------------------------------------------------------------

export function active() {
  // True while handling a request from a Promptproof scan.
  return storage.getStore() !== undefined;
}

export function planted(slotId, default_ = "") {
  // The fake secret for this slot during a test session, `default` at any other time.
  const session = storage.getStore();
  if (session === undefined) return default_;
  return slotId in session.fixtures ? session.fixtures[slotId] : default_;
}

export function content(pointId, default_ = "") {
  // Text the scan placed at this injection point during a test session, `default` otherwise.
  const session = storage.getStore();
  if (session === undefined) return default_;
  return pointId in session.content ? session.content[pointId] : default_;
}

export function recordedCalls() {
  // The calls recorded so far in this request, for a bot that reports them in its own reply body.
  const session = storage.getStore();
  return session ? session.calls.map((c) => ({ ...c })) : [];
}

// -- small real actions, under caps -------------------------------------------------------------

const CAP = Symbol("promptproof.cap");

export function cap({ max = {}, only = {}, total = {}, calls = 1 } = {}) {
  // Limits under which a tool may be carried out for real during a test, mirroring the
  // Python harness's Cap. Frozen, and validated the same way: it must limit at least
  // one argument with max or only, ceilings are numbers of 0 or more, calls a whole
  // number of 1 or more, and an only-list is a non-empty array or Set (never a string,
  // which would allow every substring).
  max = { ...max };
  total = { ...total };
  const onlyLimits = {};
  if (Object.keys(max).length === 0 && Object.keys(only).length === 0) {
    throw new HarnessError("a cap must limit at least one argument with max or only");
  }
  if (typeof calls === "boolean" || typeof calls !== "number" || !Number.isInteger(calls) || calls < 1) {
    throw new HarnessError("calls in a cap must be a whole number, 1 or more");
  }
  for (const [name, ceiling] of Object.entries({ ...max, ...total })) {
    if (
      typeof ceiling === "boolean" ||
      typeof ceiling !== "number" ||
      !Number.isFinite(ceiling) ||
      ceiling < 0
    ) {
      throw new HarnessError(`the cap on '${name}' must be a number, 0 or more`);
    }
  }
  for (const [name, allowed] of Object.entries(only)) {
    const isList = allowed instanceof Set || Array.isArray(allowed);
    const size = isList ? (allowed instanceof Set ? allowed.size : allowed.length) : 0;
    if (!isList || size === 0) {
      throw new HarnessError(`only on '${name}' must be a non-empty array or Set of allowed values`);
    }
    onlyLimits[name] = allowed instanceof Set ? new Set(allowed) : Object.freeze([...allowed]);
  }
  const made = {
    max: Object.freeze(max), // argument -> highest value for one call
    only: Object.freeze(onlyLimits), // argument -> the values allowed
    total: Object.freeze(total), // argument -> highest sum over one run
    calls, // real calls per run
    names() {
      return new Set([...Object.keys(max), ...Object.keys(onlyLimits), ...Object.keys(total)]);
    },
  };
  made[CAP] = true;
  return Object.freeze(made);
}

function number_(value) {
  // The value as a finite number, or null. Booleans, numeric strings, BigInts, boxed
  // numbers and objects with valueOf are not numbers here (Python: True is not 1).
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  return value;
}

function liveSwitch() {
  // The owner's switch on this deployment: nothing runs for real unless it names the tool.
  return new Set(
    (process.env[LIVE_ENV] || "")
      .split(",")
      .map((t) => t.trim())
      .filter((t) => t !== "")
  );
}

// run id -> Map<tool, [real calls so far, {argument: sum so far}]>. In this process
// only, shared with the test suite so it can be cleaned between tests.
export const _ledger = new Map();
export const _runFirstSeen = new Map();

function mayRun(session, tool, limits, callArguments) {
  // Whether this call is carried out for real, and why not. Reserves its share of the
  // run's limits: the reservation happens here, synchronously before the real function
  // is called, so concurrent calls cannot both pass a limit. Order and reason texts
  // match the Python harness's _may_run exactly.
  const valueOf = (name) => (Object.hasOwn(callArguments, name) ? callArguments[name] : undefined);
  if (limits === null || !session.live.has(tool)) return [false, ""]; // an ordinary test session: record only
  if (!liveSwitch().has(tool)) {
    return [false, `this deployment does not allow ${tool} to run for real (${LIVE_ENV})`];
  }
  for (const [name, ceiling] of Object.entries(limits.max)) {
    const value = number_(valueOf(name));
    if (value === null) return [false, `${name} is not a number, so its cap cannot be checked`];
    if (!(0 <= value && value <= ceiling)) {
      return [false, `${name} ${pyG(value)} is outside the cap of 0 to ${pyG(ceiling)}`];
    }
  }
  for (const [name, allowed] of Object.entries(limits.only)) {
    const value = valueOf(name);
    const listed = allowed instanceof Set ? allowed.has(value) : allowed.includes(value); // strict, no coercion
    if (!listed) return [false, `${name} is not one of the values allowed for a live test`];
  }
  const sums = {};
  for (const name of Object.keys(limits.total)) {
    const value = number_(valueOf(name));
    if (value === null || value < 0) {
      return [false, `${name} is not a number of 0 or more, so the run's total cannot be checked`];
    }
    sums[name] = value;
  }
  const now = performance.now(); // monotonic, like Python's time.monotonic()
  if (!_ledger.has(session.runId)) {
    for (const [old, seen] of _runFirstSeen) {
      if (now - seen > RUN_MEMORY_SECONDS * 1000) {
        _ledger.delete(old);
        _runFirstSeen.delete(old);
      }
    }
    if (_ledger.size >= MAX_RUNS_REMEMBERED) {
      // Forgetting a recent run would hand it a fresh allowance. Refuse the new one instead.
      return [false, "too many test runs in the last day for this process to keep count of; nothing more runs for real"];
    }
    _ledger.set(session.runId, new Map());
    _runFirstSeen.set(session.runId, now);
  }
  const run = _ledger.get(session.runId);
  const [calls, totals] = run.get(tool) ?? [0, {}];
  if (calls + 1 > limits.calls) {
    return [false, `the run's limit of ${limits.calls} real call(s) to ${tool} is used up`];
  }
  for (const [name, value] of Object.entries(sums)) {
    if ((totals[name] ?? 0) + value > limits.total[name]) {
      return [false, `this would take the run's total ${name} over the cap of ${pyG(limits.total[name])}`];
    }
  }
  const spent = { ...totals };
  for (const [name, value] of Object.entries(sums)) spent[name] = (totals[name] ?? 0) + value;
  run.set(tool, [calls + 1, spent]);
  return [true, ""];
}

function paramNames(fn) {
  // Best effort: read the parameter names off the function's source, the way Python's
  // inspect.signature does. Anything unusual (rest, destructuring, native code, a bound
  // or minified-away shape we cannot trust) returns null and calls are recorded with
  // generated names arg0, arg1, ... Default values are fine: the name before "=" is
  // kept, and JavaScript itself has already filled the value in.
  let source;
  try {
    source = Function.prototype.toString.call(fn);
  } catch {
    return null;
  }
  if (source.includes("[native code]")) return [];
  const head = source.match(/^\s*(?:async\s+)?(?:function\s*(?:[\w$]+\s*)?|(?:[\w$]+\s*))?\(/);
  if (!head) return null;
  let text = source.slice(head[0].length); // just after the opening "("
  const params = [];
  let current = "";
  let depth = 0;
  let closed = false;
  for (const ch of text) {
    if (ch === "(" || ch === "[" || ch === "{") depth += 1;
    else if (ch === ")" || ch === "]" || ch === "}") {
      if (depth === 0) {
        closed = true;
        break;
      }
      depth -= 1;
    } else if (ch === "," && depth === 0) {
      params.push(current.trim());
      current = "";
      continue;
    }
    current += ch;
  }
  if (!closed) return null;
  params.push(current.trim());
  if (params.length === 1 && params[0] === "") return []; // zero parameters
  const names = [];
  for (const raw of params) {
    if (raw === "") return null; // stray trailing comma or something odd
    const name = raw.split("=")[0].trim(); // keep the name of a parameter with a default
    if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(name)) return null; // ...rest, destructuring: generated names
    names.push(name);
  }
  return names;
}

function text(value) {
  // Python _text: strings stay, everything else becomes its Python-json form.
  if (typeof value === "string") return value;
  return pyDumps(value, { sortKeys: true });
}

function errorName(error) {
  // Python records type(error).__name__, so the class's own name comes first; an
  // explicitly set error.name is the fallback.
  if (error !== null && typeof error === "object") {
    const className = error.constructor?.name;
    if (typeof className === "string" && className !== "") return className;
    if (typeof error.name === "string" && error.name !== "") return error.name;
  }
  return "Error";
}

export function action(tool, fn, options = {}) {
  // Mark a function as a risky tool. In a test session it is recorded, not run, and
  // returns `options.result` (or `options.result(arguments)` if that is a function).
  // Outside one it runs as written.
  //
  // With `options.live` a cap made with cap(), the tool may be carried out for real in
  // a test session, inside those limits and only where the owner has switched that on;
  // the cap's argument names must be parameters of the function.
  const resultOption = options && options.result !== undefined ? options.result : DEFAULT_RESULT;
  const live = options && options.live !== undefined && options.live !== null ? options.live : null;
  if (live !== null && live[CAP] !== true) {
    throw new HarnessError(`${tool}: live must be a cap made with cap()`);
  }
  const names = paramNames(fn);
  if (live !== null) {
    if (names === null) {
      throw new HarnessError(
        `${tool}: the parameter names of the function cannot be read, so its cap cannot be checked`
      );
    }
    const known = new Set(names);
    const unknown = [...live.names()].filter((name) => !known.has(name)).sort(pyCmp);
    if (unknown.length > 0) {
      throw new HarnessError(`${tool}: the cap names ${JSON.stringify(unknown)}, which are not arguments of the function`);
    }
  }
  const isAsync = fn && fn.constructor && fn.constructor.name === "AsyncFunction";

  function namedArguments(args) {
    // The arguments of the call by name — Python's signature.bind — or with generated
    // names when the source's parameter names could not be read, or when the call
    // passed more than it names: arguments the function would reject can never be
    // checked against a cap, so they are never carried out for real.
    if (names && args.length <= names.length) {
      const byName = {};
      for (let i = 0; i < args.length; i++) byName[names[i]] = args[i];
      delete byName.self; // a method call: the bound instance is not an argument
      delete byName.cls;
      return { arguments: byName, bound: true };
    }
    const generated = {};
    for (let i = 0; i < args.length; i++) generated[`arg${i}`] = args[i];
    return { arguments: generated, bound: false };
  }

  function record(session, callArguments, outcome, note, mode) {
    const recorded = {};
    for (const key of Object.keys(callArguments)) recorded[key] = text(callArguments[key]);
    const call = {
      id: `call-${session.calls.length + 1}`,
      tool,
      arguments: recorded,
      accepted: true,
      result: (note ? `[${note}] ` : "") + text(outcome),
    };
    if (mode) call.live = mode; // "ran" or "capped"; absent for an ordinary recorded call
    session.add(call);
  }

  function standIn(session, callArguments, whyNot) {
    const outcome = typeof resultOption === "function" ? resultOption(callArguments) : resultOption;
    record(session, callArguments, outcome, whyNot ? `not run: ${whyNot}` : "", whyNot ? "capped" : "");
    return outcome;
  }

  function decide(session, args) {
    const named = namedArguments(args);
    if (live === null || !named.bound) return [named.arguments, false, ""];
    return [named.arguments, ...mayRun(session, tool, live, named.arguments)];
  }

  async function runInSessionAsync(session, thisArg, args) {
    const [callArguments, real, whyNot] = decide(session, args); // reserves synchronously
    if (!real) return standIn(session, callArguments, whyNot);
    try {
      const outcome = await fn.apply(thisArg, args);
      record(session, callArguments, outcome, "ran for real within the caps", "ran");
      return outcome;
    } catch (error) {
      record(session, callArguments, `raised ${errorName(error)}`, "ran for real within the caps", "ran");
      throw error;
    }
  }

  function runInSession(session, thisArg, args) {
    const [callArguments, real, whyNot] = decide(session, args);
    if (!real) return standIn(session, callArguments, whyNot);
    try {
      const outcome = fn.apply(thisArg, args);
      record(session, callArguments, outcome, "ran for real within the caps", "ran");
      return outcome;
    } catch (error) {
      record(session, callArguments, `raised ${errorName(error)}`, "ran for real within the caps", "ran");
      throw error;
    }
  }

  if (isAsync) {
    return async function (...args) {
      const session = storage.getStore();
      if (session === undefined) return fn.apply(this, args);
      return runInSessionAsync(session, this, args);
    };
  }
  return function (...args) {
    const session = storage.getStore();
    if (session === undefined) return fn.apply(this, args);
    return runInSession(session, this, args);
  };
}

// -- wrapping the web app ----------------------------------------------------------------------

function challengeBytes() {
  const value = (process.env[CHALLENGE_ENV] || "").trim();
  return value ? Buffer.from(value, "utf8") : null;
}

function challengeResponse(writeHead, end) {
  const challenge = challengeBytes();
  writeHead(200, { "content-type": "text/plain" });
  end(Buffer.concat([challenge, Buffer.from("\n")]));
}

function refuse(writeHead, end) {
  // It says it is a test message but is not a valid session here. Never run it as an ordinary one.
  writeHead(403, { "content-type": "text/plain" });
  end(REFUSED);
}

function pathOf(url) {
  // The path without the query, as the Python adapters see it.
  const q = url.indexOf("?");
  return q < 0 ? url : url.slice(0, q);
}

function tokensFromRawHeaders(rawHeaders) {
  const wanted = SESSION_HEADER.toLowerCase();
  const tokens = [];
  for (let i = 0; i < rawHeaders.length; i += 2) {
    if (rawHeaders[i].toLowerCase() === wanted) tokens.push(rawHeaders[i + 1]);
  }
  return tokens;
}

function attachCallsHeader(res, session) {
  // The record is signed the moment the response headers are sent, so calls made after
  // that (a streaming reply that keeps working) are blocked but not reported.
  let sent = false;
  const add = () => {
    if (sent || res.headersSent || res.writableEnded) return;
    sent = true;
    const value = session.headerValue();
    const existing = res.getHeader(CALLS_HEADER);
    // append, never replace: a reply that carries its own made-up record keeps it, and
    // the two values together fail the scanner's signature check, as they should
    if (existing === undefined) res.setHeader(CALLS_HEADER, value);
    else res.setHeader(CALLS_HEADER, [].concat(existing, value));
  };
  for (const name of ["writeHead", "write", "end"]) {
    const original = res[name].bind(res);
    res[name] = (...args) => {
      add();
      return original(...args);
    };
  }
}

function bindEmitter(emitter) {
  // The session lives in an AsyncLocalStorage, which follows promises, awaits and
  // timers — but not Node's raw event emitters: a listener registered on the request
  // fires later in the socket's own context, where there is no session, and a wrapped
  // tool called there would run for real. Binding each listener into the context it
  // was registered in (inside the session) is what makes `req.on("data"/"end")` and
  // `res.on("finish")` see the session, the way Python's context variable follows the
  // whole request. Registering through this wrapper and removing through it match.
  const boundListeners = new WeakMap();
  const bind = (listener) => {
    if (typeof listener !== "function") return listener;
    let bound = boundListeners.get(listener);
    if (bound === undefined) {
      bound = AsyncResource.bind(listener);
      boundListeners.set(listener, bound);
    }
    return bound;
  };
  for (const name of ["on", "addListener", "once", "prependListener", "prependOnceListener"]) {
    const original = emitter[name].bind(emitter);
    emitter[name] = (event, listener, options) => original(event, bind(listener), options);
  }
  for (const name of ["off", "removeListener"]) {
    const original = emitter[name].bind(emitter);
    emitter[name] = (event, listener, options) => original(event, boundListeners.get(listener) ?? listener, options);
  }
}

export function wrapNode(handler) {
  // Wrap a plain (req, res) Node http handler. Without PROMPTPROOF_HARNESS_KEY set,
  // requests pass straight through.
  envKey(); // a key that is set but too short is a mistake worth stopping on
  return function (req, res) {
    const path = pathOf(req.url || "/");
    if (challengeBytes() !== null && req.method === "GET" && path === CHALLENGE_PATH) {
      challengeResponse((status, headers) => res.writeHead(status, headers), (body) => res.end(body));
      return;
    }
    const tokens = tokensFromRawHeaders(req.rawHeaders || []);
    if (tokens.length === 0) return handler(req, res); // an ordinary request
    const session = tokens.length === 1 ? openSession(tokens[0]) : null;
    if (session === null) {
      refuse((status, headers) => res.writeHead(status, headers), (body) => res.end(body));
      return;
    }
    if (path === READY_PATH) {
      req.resume(); // some clients wait for their (empty) body to be taken in
      res.writeHead(200, { "content-type": "text/plain", [CALLS_HEADER]: session.headerValue() });
      res.end(READY);
      return;
    }
    attachCallsHeader(res, session);
    bindEmitter(req);
    bindEmitter(res);
    return storage.run(session, () => handler(req, res));
  };
}

export function express() {
  // Express-style middleware: (req, res, next). Install it as early as possible.
  envKey();
  return function (req, res, next) {
    const path = pathOf(req.url || "/");
    if (challengeBytes() !== null && req.method === "GET" && path === CHALLENGE_PATH) {
      challengeResponse((status, headers) => res.writeHead(status, headers), (body) => res.end(body));
      return;
    }
    const tokens = tokensFromRawHeaders(req.rawHeaders || []);
    if (tokens.length === 0) return next(); // an ordinary request
    const session = tokens.length === 1 ? openSession(tokens[0]) : null;
    if (session === null) {
      refuse((status, headers) => res.writeHead(status, headers), (body) => res.end(body));
      return;
    }
    if (path === READY_PATH) {
      req.resume();
      res.writeHead(200, { "content-type": "text/plain", [CALLS_HEADER]: session.headerValue() });
      res.end(READY);
      return;
    }
    attachCallsHeader(res, session);
    bindEmitter(req);
    bindEmitter(res);
    return storage.run(session, () => next());
  };
}

export function wrapFetch(handler) {
  // Wrap a (Request) => Response | Promise<Response> handler: Next.js route handlers,
  // Hono, Cloudflare Workers style. The Request and Response are the standard fetch kinds.
  envKey();
  return async function (request) {
    const path = new URL(request.url).pathname;
    const challenge = challengeBytes();
    if (challenge !== null && request.method === "GET" && path === CHALLENGE_PATH) {
      return new Response(Buffer.concat([challenge, Buffer.from("\n")]), {
        status: 200,
        headers: { "content-type": "text/plain" },
      });
    }
    // Headers.get() joins repeated headers with ", ", so a doubled session header is
    // one string that cannot verify — refused, exactly as the Python adapters refuse it.
    const token = request.headers.get(SESSION_HEADER);
    if (token === null) return handler(request); // an ordinary request
    const session = openSession(token);
    if (session === null) {
      return new Response(REFUSED, { status: 403, headers: { "content-type": "text/plain" } });
    }
    if (path === READY_PATH) {
      return new Response(READY, {
        status: 200,
        headers: { "content-type": "text/plain", [CALLS_HEADER]: session.headerValue() },
      });
    }
    const response = await storage.run(session, () => handler(request));
    const headers = new Headers(response.headers);
    headers.append(CALLS_HEADER, session.headerValue()); // append: a lying reply keeps its own fake record
    return new Response(response.status === 204 || response.status === 304 ? null : response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  };
}
