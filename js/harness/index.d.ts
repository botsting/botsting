// Types for promptproof-harness, hand-written. Every runtime export is declared here.

export const KEY_ENV: string;
export const CHALLENGE_ENV: string;
export const CHALLENGE_PATH: string;
export const READY_PATH: string;
export const SESSION_HEADER: string;
export const CALLS_HEADER: string;
export const MIN_KEY_LENGTH: number;
export const MAX_TOKEN_BYTES: number;
export const MAX_CALLS: number;
export const MAX_RECORD_BYTES: number;
export const MAX_LIFETIME_SECONDS: number;

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
    nonce?: string
  );
  sid: string;
  fixtures: Record<string, string>;
  content: Record<string, string>;
  key: string;
  nonce: string;
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

export interface ActionOptions {
  /** What a wrapped tool returns during a test session instead of running. Default
   *  `{ status: "ok" }`. A function is called as `result(arguments)` with the recorded
   *  arguments and its return value is used. */
  result?: unknown;
}

/** Mark a function as a risky tool. In a test session it is recorded, not run, and
 *  returns `options.result` (or its value for the recorded arguments). Outside one it
 *  runs as written. Wrapping an async function returns an async function.
 *
 *  The parameter names are read from the function's source so calls are recorded with
 *  real argument names; when they cannot be read, names arg0, arg1, ... are used. */
export function action<T extends (...args: never[]) => unknown>(
  tool: string,
  fn: T,
  options?: ActionOptions
): T;

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
