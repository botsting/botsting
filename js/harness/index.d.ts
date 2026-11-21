// Types for promptproof-harness, hand-written. Every runtime export is declared here.

export const KEY_ENV: string;
export const CHALLENGE_ENV: string;
export const LIVE_ENV: string;
export const CHALLENGE_PATH: string;
export const READY_PATH: string;
export const SESSION_HEADER: string;
export const CALLS_HEADER: string;
export const MIN_KEY_LENGTH: number;
export const MAX_TOKEN_BYTES: number;
export const MAX_CALLS: number;
export const MAX_RECORD_BYTES: number;
export const MAX_LIFETIME_SECONDS: number;
/** How many runs of live actions one process keeps count of; a 65th run within a day
 *  is refused rather than an old run forgotten. */
export const MAX_RUNS_REMEMBERED: number;
/** How long one process remembers a run's live-action counts. */
export const RUN_MEMORY_SECONDS: number;

export class HarnessError extends Error {}

/** One Promptproof test session, created from a signed token. Rarely needed directly:
 *  the adapters make one per request. `run(fn)` runs `fn` inside the session, the way
 *  a wrapped request handler runs. */
export class Session {
  constructor(
    sid: string,
    fixtures: Readonly<Record<string, string>>,
    content: Readonly<Record<string, string>>,
    key: string,
    nonce?: string,
    live?: ReadonlySet<string>,
    runId?: string
  );
  sid: string;
  fixtures: Record<string, string>;
  content: Record<string, string>;
  key: string;
  nonce: string;
  /** Tools the scan asks to have carried out for real ("live" in the token). */
  live: ReadonlySet<string>;
  /** The run their totals are counted under ("run" in the token). */
  runId: string;
  calls: CallRecord[];
  dropped: number;
  size: number;
  /** Record a call, or count it as dropped past MAX_CALLS / MAX_RECORD_BYTES. */
  add(call: CallRecord): void;
  /** The signed Promptproof-Tool-Calls header value for this session and message. */
  headerValue(): string;
  /** Run `fn` with this session as the active one. */
  run<T>(fn: () => T): T;
}

/** One recorded tool call, as it travels in the signed record. */
export interface CallRecord {
  id: string;
  tool: string;
  arguments: Record<string, string>;
  accepted: boolean;
  result: string;
  /** "ran" when the call was carried out for real inside its caps, "capped" when a
   *  live call was refused by a limit. Absent for an ordinary recorded call. */
  live?: "ran" | "capped";
}

/** Refuse a key shorter than MIN_KEY_LENGTH; returns it unchanged otherwise. */
export function checkKey(key: string): string;

/** A fresh, strong key for PROMPTPROOF_HARNESS_KEY (base64url, 32 random bytes). */
export function newKey(): string;

export interface SessionTokenOptions {
  /** How long the token stays valid; at most MAX_LIFETIME_SECONDS. Default 300. */
  lifetimeSeconds?: number;
  /** Seconds since the epoch to sign for instead of now. */
  now?: number | null;
  /** New for every message: the harness signs it into that message's tool-call record. */
  nonce?: string;
  /** Tool names the scan asks to have carried out for real. When not empty, `run`
   *  must name the run their totals are counted under. Written into the token only
   *  when not empty, exactly as the Python harness writes them. */
  live?: Iterable<string>;
  /** The run the live actions' totals are counted under. */
  run?: string;
}

/** What the scanner puts in the Promptproof-Session header of each message. */
export function makeSessionToken(
  key: string,
  sessionId: string,
  fixtures: Readonly<Record<string, string>>,
  content?: Readonly<Record<string, string>>,
  options?: SessionTokenOptions
): string;

/** What the scanner does with the Promptproof-Tool-Calls header. Throws HarnessError if
 *  it was not made by a harness holding the key for this very session and message, or
 *  if calls were dropped. */
export function readCallsHeader(
  key: string,
  sessionId: string,
  value: string | null | undefined,
  nonce?: string
): CallRecord[];

/** The HMAC the wire format shares with the Python harness: domain + json.dumps(parts)
 *  with Python's exact bytes, base64url, no padding. */
export function mac(key: string, domain: string | Buffer, parts: readonly string[]): string;

/** A session for a validly signed, unexpired token; null for anything else. */
export function openSession(token: string | null | undefined, now?: number | null): Session | null;

/** True while handling a request from a Promptproof scan. */
export function active(): boolean;

/** The fake secret for this slot during a test session, `default` at any other time. */
export function planted(slotId: string, defaultValue?: string): string;

/** Text the scan placed at this injection point during a test session, `default` otherwise. */
export function content(pointId: string, defaultValue?: string): string;

/** The calls recorded so far in this request, for a bot that reports them in its own reply body. */
export function recordedCalls(): CallRecord[];

/** Limits under which a tool may be carried out for real during a test session. Make
 *  one with cap(); frozen, and its names must be parameters of the wrapped function.
 *
 *  The per-call limits (`max`, `only`) are exact. The per-run limits (`total`, `calls`)
 *  are counted in this process's memory: a deployment with N worker processes can carry
 *  out up to N times those limits in one run, and a restart forgets the count. */
export interface Cap {
  /** argument -> highest value for one call */
  readonly max: Readonly<Record<string, number>>;
  /** argument -> the values allowed (strict equality: "1" is not 1) */
  readonly only: Readonly<Record<string, ReadonlySet<unknown> | readonly unknown[]>>;
  /** argument -> highest sum over one run */
  readonly total: Readonly<Record<string, number>>;
  /** real calls per run; a whole number, 1 or more */
  readonly calls: number;
  /** Every argument name the cap mentions. */
  names(): Set<string>;
}

/** Limits under which a tool marked `live` may be carried out for real during a test
 *  session. Must limit at least one argument with `max` or `only`; ceilings are
 *  numbers of 0 or more; `calls` a whole number of 1 or more (default 1); an
 *  `only`-list is a non-empty array or Set, never a string. Throws HarnessError
 *  otherwise. */
export function cap(limits?: {
  max?: Record<string, number>;
  only?: Record<string, readonly unknown[] | ReadonlySet<unknown>>;
  total?: Record<string, number>;
  calls?: number;
}): Cap;

export interface ActionOptions {
  /** What a wrapped tool returns during a test session instead of running. Default
   *  `{ status: "ok" }`. A function is called as `result(arguments)` with the recorded
   *  arguments and its return value is used. */
  result?: unknown;
  /** A cap under which the tool may be carried out for real during a test session:
   *  only where PROMPTPROOF_LIVE_ACTIONS names it on the deployment, only when the
   *  scan's session asks for it, and only inside every limit. A call outside the
   *  limits is still recorded, with the limit it broke. */
  live?: Cap;
}

/** Mark a function as a risky tool. In a test session it is recorded, not run, and
 *  returns `options.result` (or its value for the recorded arguments). Outside one it
 *  runs as written. Wrapping an async function returns an async function.
 *
 *  With `options.live` the tool may be carried out for real inside its caps; a real
 *  call is recorded with live: "ran" and the result prefix "[ran for real within the
 *  caps] ", a refused one with live: "capped" and "[not run: <reason>] ".
 *
 *  The parameter names are read from the function's source so calls are recorded with
 *  real argument names; when they cannot be read, names arg0, arg1, ... are used, and
 *  a cap cannot be attached to such a function. */
export function action<T extends (...args: never[]) => unknown>(
  tool: string,
  fn: T,
  options?: ActionOptions
): T;

/** Internal: this process's ledger of real calls (run id -> tool -> [calls, sums]) and
 *  when each run was first seen. Shared with the test suite so it can be cleared;
 *  not part of the wire format. */
export const _ledger: Map<string, Map<string, [number, Record<string, number>]>>;
export const _runFirstSeen: Map<string, number>;

// -- adapters ---------------------------------------------------------------------------------

export interface NodeRequest {
  url: string | undefined;
  method: string | undefined;
  rawHeaders: string[];
  resume?(): void;
}

export interface NodeResponse {
  writeHead(status: number, headers?: Record<string, unknown>): NodeResponse;
  write(chunk?: unknown, ...rest: unknown[]): boolean;
  end(chunk?: unknown, ...rest: unknown[]): void;
  getHeader(name: string): unknown;
  setHeader(name: string, value: unknown): void;
  headersSent: boolean;
  writableEnded: boolean;
}

/** Wrap a plain `(req, res)` Node http handler. Without PROMPTPROOF_HARNESS_KEY set,
 *  requests pass straight through. */
export function wrapNode(
  handler: (req: NodeRequest & Record<string, unknown>, res: NodeResponse & Record<string, unknown>) => void
): (req: NodeRequest & Record<string, unknown>, res: NodeResponse & Record<string, unknown>) => void;

/** Express-style middleware `(req, res, next)`. Install it as early as possible:
 *  `app.use(pp.express())`. */
export function express(): (
  req: NodeRequest & Record<string, unknown>,
  res: NodeResponse & Record<string, unknown>,
  next: (err?: unknown) => void
) => void;

/** Wrap a `(Request) => Response | Promise<Response>` handler: Next.js route handlers,
 *  Hono, Cloudflare Workers style. */
export function wrapFetch(
  handler: (request: Request) => Response | Promise<Response>
): (request: Request) => Promise<Response>;
