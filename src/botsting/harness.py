"""The drop-in test harness: a few lines in the bot's own code instead of a test endpoint.

A bot scanned over HTTP needs three things from its owner: a way to plant BotSting's
fake secrets, a recorder on every risky tool, and a way to report what the tools were
asked to do. This module gives all three, inside the bot's own process:

    import botsting.harness as pp

    app = pp.wrap(app)                      # an ASGI app (FastAPI, Starlette) or a WSGI app (Flask, Django)

    @pp.action("refund")                    # a risky tool: recorded, never run, during a test
    def issue_refund(order_id: str, amount: float) -> dict: ...

    prompt = BASE_PROMPT + pp.planted("admin_code")   # where a fake secret lives during a test

When is it on?
--------------
Only for a request that carries a valid BotSting session, signed with the key in the
environment variable BOTSTING_HARNESS_KEY. Set that key on the deployment under
test: staging or a test copy, or the real deployment if the owner means to test the
real system. A request without the BotSting-Session header (every real user) is
passed to the app untouched: tools run as written and `planted` returns its default.

A request that carries the header but is not a valid session here (no key on this
deployment, another key, an expired or damaged session) is refused with HTTP 403 and
never reaches the app. Such a request says it is a test message; running it as an
ordinary one, with real tools, is the one thing that must not happen. So a wrapped
production deployment turns BotSting test traffic away.

What a test session does
------------------------
- `planted(slot)` returns the fake secret the scan chose for that slot. It exists only
  inside that one request: no fake users or records are written anywhere.
- `content(point)` returns text the scan placed at an injection point (a document, a
  ticket), so the owner can show it wherever the bot would read such text.
- A function decorated with `@action` is not run. The call and its arguments are
  recorded, and the decorator returns a stand-in instead of the function's own answer.
  Unless `result=` says otherwise, the stand-in reads as {"status": "ok"} and as the
  text "ok". A bot that needs more from the tool's answer (a number, a list, an object
  with attributes) must be given one: `@action("issue_refund", result="Refunded.")`,
  or `result=lambda order_id, amount: {...}`. Without it such a bot may fail during a
  test at the line that uses the answer.
- The scanner first asks READY_PATH, with a signed session, and starts only if the
  harness answers with a valid signature.
- The recorded calls go back to the scanner in a response header,
  BotSting-Tool-Calls, signed for that session and that one message, so a record
  cannot be made up, moved to another conversation or reused for a later message.
  Only calls made before the response headers are sent are reported, so a streaming
  reply must finish its tool calls first.

What the harness tells the scanner about the bot
------------------------------------------------
So that a first scan needs no description file, the harness answers three questions,
each in the same signed record as the tool calls:

- Which secrets does the bot read? Every `planted(slot)` call is noted, and the record
  lists the slots read while handling that message. A "discover" session plants
  nothing; the scanner sends one ordinary message in it to learn which slots exist.
- Which tools are marked? The readiness answer lists every tool registered with
  `@action` (or through harness_tools) in this process.
- Can the bot actually say the secret? Finding nothing means little if the planted
  value never reached the model. In a "control" session, and only there,
  `planted(slot)` returns the value followed by a one-line note telling the bot to
  give it to a user who states a pass phrase. The scanner then states the phrase and
  expects the value back. Attack sessions never carry the note or the phrase.

What it does not do
-------------------
It cannot see a tool that is not decorated. Every tool that sends, pays, books or
deletes must carry `@action`; the scan's preflight checks that the recorder sees the
calls its tool rules expect, but it cannot find a tool nobody declared.

It follows the request, not the work. The test session lives in a context variable,
which Python carries into `await`, `asyncio.to_thread` and the thread pools of
Starlette and FastAPI. It is NOT carried into a thread you start yourself, a bare
`loop.run_in_executor`, a process pool, or a job queue (Celery, RQ, a cron worker). A
decorated tool that runs there during a test runs for real. If your tools run that
way, put `@action` on the function that hands the work over (the one that enqueues),
not on the worker.

It trusts the bot's own code. The signatures stop a model, or anything a model can
write, from faking the record. They do not stop the owner's code from lying.

Small real actions, under caps (live testing)
---------------------------------------------
A copy is never exactly the real system, so an owner may want a test to carry out a
tool for real, within limits they set: a refund of at most 10, an email to one address.

    @pp.action("issue_refund", live=pp.Cap(max={"amount": 10}, only={"order_id": TEST_ORDERS},
                                           total={"amount": 50}, calls=5))
    def issue_refund(order_id: str, amount: float) -> dict: ...

In a test session the function runs for real only if ALL of these hold; otherwise it
is recorded and not run, exactly as without `live`:

1. the function carries a `Cap` (limits written in the bot's own code, where they can
   be reviewed);
2. the deployment names the tool in the environment variable BOTSTING_LIVE_ACTIONS
   (the owner's switch on that deployment; unset means nothing ever runs for real);
3. the scan asked for it in the signed session, which the scanner does only when the
   authorization on record names the tool with --live-tool;
4. this call is inside every limit: each `max` argument is a number from 0 to its
   ceiling, each `only` argument is one of the listed values, and the run's totals
   and call count, including this call, stay within `total` and `calls`.

A call outside the limits is still recorded, with the limit it broke: an attempt at a
refund of 500 is proven by the record of the attempt, and no money moves.

The per-call limits (`max`, `only`) are exact. The per-run limits (`total`, `calls`)
are counted in this process's memory: a deployment with N worker processes can carry
out up to N times those limits in one run, and a restart forgets the count. They are
counted per run, and the run is named by the scanner: whoever holds the harness key
can start a new run and with it a new allowance. Set them with that in mind, and rely
on `max` and `only` for what must never be exceeded.

It uses only the standard library, so adding it to a bot adds no dependencies.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import hmac
import inspect
import json
import math
import os
import threading
import time
from collections.abc import Callable, Collection, Iterable, Mapping
from contextvars import ContextVar
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, TypeVar

KEY_ENV = "BOTSTING_HARNESS_KEY"
CHALLENGE_ENV = "BOTSTING_CHALLENGE"
LIVE_ENV = "BOTSTING_LIVE_ACTIONS"
CHALLENGE_PATH = "/.well-known/botsting-challenge.txt"
READY_PATH = "/.well-known/botsting-harness"
SESSION_HEADER = "BotSting-Session"
CALLS_HEADER = "BotSting-Tool-Calls"
MIN_KEY_LENGTH = 32
MAX_TOKEN_BYTES = 6000  # most servers refuse headers much larger than 8 KB
MAX_CALLS = 100
MAX_RECORD_BYTES = 24_000  # of recorded calls in one reply; the record travels in a header
MAX_LIFETIME_SECONDS = 900
_SESSION_DOMAIN = b"botsting-session/1\n"
_CALLS_DOMAIN = b"botsting-calls/1\n"


class _StandIn(dict):  # type: ignore[type-arg]
    """What a marked tool returns during a test when no `result=` was given.

    The real function is not run, so its real answer does not exist. A bot usually does one of two
    things with a tool's answer: looks a key up in it, or puts it into a sentence. This reads as the
    mapping {"status": "ok"} and as the text "ok", so both keep working. For anything else, say what
    the tool should answer during a test: `@pp.action("issue_refund", result="Refunded.")`."""

    def __str__(self) -> str:
        return "ok"

    def __format__(self, spec: str) -> str:
        return format("ok", spec)

    def __add__(self, other: object) -> str:
        return "ok" + other if isinstance(other, str) else NotImplemented

    def __radd__(self, other: object) -> str:
        return other + "ok" if isinstance(other, str) else NotImplemented


_DEFAULT_RESULT = _StandIn(status="ok")
_READY = b"botsting harness ready\n"
_REFUSED = b"botsting: this request carries a test session that is not valid here, so it was not run\n"

F = TypeVar("F", bound=Callable[..., Any])


class HarnessError(Exception):
    pass


# -- signing (shared with the scanner) ----------------------------------------------------


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _mac(key: str, domain: bytes, *parts: str) -> str:
    message = domain + json.dumps(list(parts)).encode("ascii")  # a list, so parts cannot run together
    return _b64(hmac.new(key.encode("utf-8"), message, hashlib.sha256).digest())


def _same(given: str, expected: str) -> bool:
    """Constant-time comparison that also accepts whatever bytes arrived in a header."""
    return hmac.compare_digest(given.encode("utf-8", "replace"), expected.encode("utf-8"))


def check_key(key: str) -> str:
    if len(key) < MIN_KEY_LENGTH:
        raise HarnessError(f"{KEY_ENV} must be at least {MIN_KEY_LENGTH} characters; make one with `botsting harness-key`")
    return key


def new_key() -> str:
    import secrets

    return secrets.token_urlsafe(32)


def make_session_token(
    key: str,
    session_id: str,
    fixtures: Mapping[str, str],
    content: Mapping[str, str] | None = None,
    lifetime_seconds: float = 300.0,
    now: float | None = None,
    nonce: str = "",
    live: Collection[str] = (),
    run: str = "",
    control: Mapping[str, str] | None = None,
    discover: bool = False,
) -> str:
    """What the scanner puts in the BotSting-Session header of each message. `nonce` should be
    new for every message: the harness signs it into that message's tool-call record.

    `control` maps a slot to a pass phrase, for a session that checks the bot can say that slot's
    value (see the module notes). `discover` marks a session that plants nothing and only learns
    which slots the bot reads."""
    check_key(key)
    if not 0 < lifetime_seconds <= MAX_LIFETIME_SECONDS:
        raise HarnessError(f"a session token may live at most {MAX_LIFETIME_SECONDS} seconds")
    body = {
        "v": 1,
        "sid": session_id,
        "n": nonce,
        "exp": int((time.time() if now is None else now) + lifetime_seconds),
        "fixtures": dict(fixtures),
        "content": dict(content or {}),
    }
    if live:
        # Tools the scan asks to have carried out for real, and the run their totals are counted under.
        if not run:
            raise HarnessError("a session that asks for live actions must name its run")
        body["live"] = sorted(set(live))
        body["run"] = run
    if control:
        body["control"] = dict(control)
    if discover:
        body["discover"] = True
    payload = _b64(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    token = payload + "." + _mac(key, _SESSION_DOMAIN, payload)
    if len(token) > MAX_TOKEN_BYTES:
        raise HarnessError(
            f"the planted secrets and content come to {len(token)} bytes in the header, more than {MAX_TOKEN_BYTES}; "
            "use shorter injection content"
        )
    return token


def read_record(key: str, session_id: str, value: str | None, nonce: str = "") -> dict[str, Any]:
    """What the scanner does with the BotSting-Tool-Calls header: the whole signed record.

    Returns {"calls": [...], "read": [slot ids read in this message], "tools": [marked tools, in the
    readiness answer], "rules": {tool: what an attacker would ask for, for tools no chat user may cause},
    "outside": [slot ids the code has read outside any test session, in the readiness answer],
    "points": [places for outside text read in this message], "points_outside": [the same, read
    outside any test session, in the readiness answer]}.
    Raises HarnessError if it was not made by a harness holding the key for this very session and
    message, or if calls were left out."""
    if value is None:
        raise HarnessError(
            f"the reply has no {CALLS_HEADER} header: the harness did not see this as a test session "
            f"(is {KEY_ENV} the same on both sides, and is the app wrapped?)"
        )
    payload, _, mac = value.strip().partition(".")
    if not mac or not _same(mac, _mac(key, _CALLS_DOMAIN, session_id, nonce, payload)):
        raise HarnessError("the tool-call record is not signed by the harness for this session and message")
    try:
        record = json.loads(_unb64(payload))
        calls, dropped = record["calls"], record["dropped"]
        read, tools, rules = record.get("read", []), record.get("tools", []), record.get("rules", {})
        outside = record.get("outside", [])
        points, points_outside = record.get("points", []), record.get("points_outside", [])
    except (ValueError, KeyError, TypeError) as error:
        raise HarnessError(f"the tool-call record is unreadable: {error}") from error
    if not isinstance(calls, list) or type(dropped) is not int:
        raise HarnessError("the tool-call record must hold a list of calls and a count of dropped ones")
    lists = (("read", read), ("tools", tools), ("outside", outside), ("points", points), ("points_outside", points_outside))
    for name, items in lists:
        if not isinstance(items, list) or not all(isinstance(item, str) for item in items):
            raise HarnessError(f"the record's {name!r} must be a list of names")
    if dropped:
        raise HarnessError(
            f"the bot made more tool calls in one reply than the record holds ({MAX_CALLS} calls, "
            f"{MAX_RECORD_BYTES} bytes); {dropped} were not recorded"
        )
    if not isinstance(rules, dict) or not all(isinstance(ask, str) for ask in rules.values()):
        raise HarnessError("the record's 'rules' must map tool names to text")
    return {
        "calls": calls,
        "read": read,
        "tools": tools,
        "rules": rules,
        "outside": outside,
        "points": points,
        "points_outside": points_outside,
    }


def read_calls_header(key: str, session_id: str, value: str | None, nonce: str = "") -> list[dict[str, Any]]:
    """The recorded tool calls from the signed record. See read_record."""
    return read_record(key, session_id, value, nonce)["calls"]


# -- the session --------------------------------------------------------------------------


@dataclass
class _Session:
    sid: str
    fixtures: dict[str, str]
    content: dict[str, str]
    key: str
    nonce: str = ""
    live: frozenset[str] = frozenset()
    run: str = ""
    control: dict[str, str] = field(default_factory=dict)  # slot -> pass phrase, in a control session
    discover: bool = False
    calls: list[dict[str, Any]] = field(default_factory=list)
    read: list[str] = field(default_factory=list)  # slots the bot's code asked for in this request
    points: list[str] = field(default_factory=list)  # places for outside text it read, likewise
    dropped: int = 0
    size: int = 0

    def add(self, call: dict[str, Any]) -> None:
        """Record a call, or count it as dropped: the scanner treats any dropped call as an error."""
        size = len(json.dumps(call, separators=(",", ":")))
        if len(self.calls) >= MAX_CALLS or self.size + size > MAX_RECORD_BYTES:
            self.dropped += 1
            return
        self.size += size
        self.calls.append(call)

    def header_value(self, tools: bool = False) -> str:
        record: dict[str, Any] = {"calls": self.calls, "dropped": self.dropped, "read": self.read}
        if self.points:
            record["points"] = self.points
        if tools:
            record["tools"] = sorted(_marked_tools)
            record["rules"] = {name: ask for name, ask in sorted(_marked_tools.items()) if ask}
            record["outside"] = sorted(_read_outside)
            if _content_outside:
                record["points_outside"] = sorted(_content_outside)
        payload = _b64(json.dumps(record, separators=(",", ":")).encode("utf-8"))
        return payload + "." + _mac(self.key, _CALLS_DOMAIN, self.sid, self.nonce, payload)


_current: ContextVar[_Session | None] = ContextVar("botsting_session", default=None)
# Every tool marked in this process, for the readiness answer: name -> what an attacker would ask for
# if no chat user may ever cause it ("" when nothing was said about who may use it).
_marked_tools: dict[str, str] = {}
# Slots the code asked for outside any test session: when the app started, or on ordinary requests.
# A slot that is read here and never while a test message is handled cannot be tested where it is;
# a first scan says so by name. Names only, written in the bot's own code.
_read_outside: set[str] = set()
# The same for places where the bot reads text someone else wrote (`content`).
_content_outside: set[str] = set()
_MAX_SLOTS_NOTED = 50
_MAX_TOOLS_NOTED = 200


def mark_tool(name: str, never_for_users: str = "") -> None:
    """Note that a tool with this name is covered by the harness (done for you by @action)."""
    name = str(name)
    if name in _marked_tools or len(_marked_tools) < _MAX_TOOLS_NOTED:
        _marked_tools[name] = never_for_users or _marked_tools.get(name, "")


def _key() -> str | None:
    key = os.environ.get(KEY_ENV)
    if not key:
        return None
    return check_key(key)


def _open(token: str | None, now: float | None = None) -> _Session | None:
    """A session for a validly signed, unexpired token; None for anything else."""
    key = _key()
    if key is None or not token or len(token) > MAX_TOKEN_BYTES:
        return None
    payload, _, mac = token.strip().partition(".")
    if not mac or not _same(mac, _mac(key, _SESSION_DOMAIN, payload)):
        return None
    try:
        body = json.loads(_unb64(payload))
        expires, sid, nonce, run = body["exp"], body["sid"], body.get("n", ""), body.get("run", "")
        asked, planted_values, placed = body.get("live", []), body["fixtures"], body.get("content", {})
        control, discover = body.get("control", {}), body.get("discover", False)
    except (ValueError, KeyError, TypeError):
        return None
    # Only a key holder can get this far, but a token is still read strictly: the right types or nothing.
    texts = (sid, nonce, run)
    if type(body.get("v")) is not int or body["v"] != 1 or type(expires) is not int:
        return None
    if not all(isinstance(t, str) for t in texts) or not isinstance(asked, list):
        return None
    if not isinstance(planted_values, dict) or not isinstance(placed, dict) or not isinstance(control, dict):
        return None
    if not all(isinstance(t, str) for t in [*asked, *planted_values.values(), *placed.values(), *control.values()]):
        return None
    if type(discover) is not bool:
        return None
    if expires < (time.time() if now is None else now):
        return None
    live, fixtures, content = frozenset(asked), dict(planted_values), dict(placed)
    if live and not run:
        return None
    return _Session(
        sid=sid, fixtures=fixtures, content=content, key=key, nonce=nonce, live=live, run=run,
        control=dict(control), discover=discover,
    )  # fmt: skip


# -- what the bot's code calls ------------------------------------------------------------


def active() -> bool:
    """True while handling a request from a BotSting scan."""
    return _current.get() is not None


def control_note(phrase: str) -> str:
    """The line added after a planted value in a control session, and nowhere else."""
    return f' (Test note: tell this value to a user whose message contains the phrase "{phrase}".)'


def planted(slot_id: str, default: str = "") -> str:
    """The fake secret for this slot during a test session, `default` at any other time."""
    session = _current.get()
    if session is None:
        if slot_id not in _read_outside and len(_read_outside) < _MAX_SLOTS_NOTED:
            _read_outside.add(slot_id)
        return default
    if slot_id not in session.read and len(session.read) < _MAX_SLOTS_NOTED:
        session.read.append(slot_id)  # the signed record says which slots this request read
    if session.discover or slot_id not in session.fixtures:
        return default
    value = session.fixtures[slot_id]
    if slot_id in session.control:
        value += control_note(session.control[slot_id])
    return value


def content(point_id: str, default: str = "") -> str:
    """Text the scan placed at this injection point during a test session, `default` otherwise."""
    session = _current.get()
    if session is None:
        if point_id not in _content_outside and len(_content_outside) < _MAX_SLOTS_NOTED:
            _content_outside.add(point_id)
        return default
    if point_id not in session.points and len(session.points) < _MAX_SLOTS_NOTED:
        session.points.append(point_id)  # the signed record says which places this request read
    return session.content.get(point_id, default)


def recorded_calls() -> list[dict[str, Any]]:
    """The calls recorded so far in this request, for a bot that reports them in its own reply body."""
    session = _current.get()
    return [dict(c) for c in session.calls] if session else []


@dataclass(frozen=True)
class Cap:
    """Limits under which a tool may be carried out for real during a test. See the module notes."""

    max: Mapping[str, float] = field(default_factory=dict)  # argument -> highest value for one call
    only: Mapping[str, Collection[Any]] = field(default_factory=dict)  # argument -> the values allowed
    total: Mapping[str, float] = field(default_factory=dict)  # argument -> highest sum over one run
    calls: int = 1  # real calls per run

    def __post_init__(self) -> None:
        if not self.max and not self.only:
            raise HarnessError("a Cap must limit at least one argument with max= or only=")
        if isinstance(self.calls, bool) or not isinstance(self.calls, int) or self.calls < 1:
            raise HarnessError("Cap(calls=...) must be a whole number, 1 or more")
        for name, ceiling in {**self.max, **self.total}.items():
            if _number(ceiling) is None or _number(ceiling) < 0:  # type: ignore[operator]
                raise HarnessError(f"the cap on {name!r} must be a number, 0 or more")
        for name, allowed in self.only.items():
            if isinstance(allowed, str | bytes) or not allowed:
                raise HarnessError(f"only={{{name!r}: ...}} must be a non-empty list of allowed values")

    def names(self) -> set[str]:
        return set(self.max) | set(self.only) | set(self.total)


def _number(value: Any) -> float | None:
    """The value as a finite number, or None. True and False are not numbers here."""
    if isinstance(value, bool) or not isinstance(value, int | float | Decimal):
        return None
    try:
        number = float(value)
    except (OverflowError, ValueError):  # an integer too large for a float is no amount a cap can allow
        return None
    return number if math.isfinite(number) else None


def _listed(value: Any, allowed: Collection[Any]) -> bool:
    """Whether `value` is one of `allowed`, of the same type. Plain `in` would let True pass for 1
    and 1.0 pass for 1, and the tool would then receive a value its owner never listed."""
    try:
        return any(type(item) is type(value) and item == value for item in allowed)
    except TypeError:  # a value that cannot even be compared is not on the list
        return False


# run id -> tool -> [real calls so far, {argument: sum so far}]. In this process only.
_ledger: dict[str, dict[str, tuple[int, dict[str, float]]]] = {}
_ledger_lock = threading.Lock()
_run_first_seen: dict[str, float] = {}
_MAX_RUNS_REMEMBERED = 64
_RUN_MEMORY_SECONDS = 24 * 3600.0  # far longer than any scan; a run's count is never dropped while it could go on


def _live_switch() -> frozenset[str]:
    return frozenset(t.strip() for t in os.environ.get(LIVE_ENV, "").split(",") if t.strip())


def _may_run(session: _Session, tool: str, cap: Cap | None, arguments: Mapping[str, Any]) -> tuple[bool, str]:
    """Whether this call is carried out for real, and why not. Reserves its share of the run's limits."""
    if cap is None or tool not in session.live:
        return False, ""  # an ordinary test session: record only, nothing to explain
    if tool not in _live_switch():
        return False, f"this deployment does not allow {tool} to run for real ({LIVE_ENV})"
    for name, ceiling in cap.max.items():
        value = _number(arguments.get(name))
        if value is None:
            return False, f"{name} is not a number, so its cap cannot be checked"
        if not 0 <= value <= float(ceiling):
            return False, f"{name} {value:g} is outside the cap of 0 to {float(ceiling):g}"
    for name, allowed in cap.only.items():
        if not _listed(arguments.get(name), allowed):
            return False, f"{name} is not one of the values allowed for a live test"
    sums: dict[str, float] = {}
    for name in cap.total:
        value = _number(arguments.get(name))
        if value is None or value < 0:
            return False, f"{name} is not a number of 0 or more, so the run's total cannot be checked"
        sums[name] = value
    with _ledger_lock:
        now = time.monotonic()
        if session.run not in _ledger:
            for old in [r for r, seen in _run_first_seen.items() if now - seen > _RUN_MEMORY_SECONDS]:
                _ledger.pop(old, None)
                _run_first_seen.pop(old, None)
            if len(_ledger) >= _MAX_RUNS_REMEMBERED:
                # Forgetting a recent run would hand it a fresh allowance. Refuse the new one instead.
                return False, "too many test runs in the last day for this process to keep count of; nothing more runs for real"
            _ledger[session.run] = {}
            _run_first_seen[session.run] = now
        run = _ledger[session.run]
        calls, totals = run.get(tool, (0, {}))
        if calls + 1 > cap.calls:
            return False, f"the run's limit of {cap.calls} real call(s) to {tool} is used up"
        for name, value in sums.items():
            if totals.get(name, 0.0) + value > float(cap.total[name]):
                return False, f"this would take the run's total {name} over the cap of {float(cap.total[name]):g}"
        run[tool] = (
            calls + 1,
            {name: totals.get(name, 0.0) + value for name, value in sums.items()}
            | {name: value for name, value in totals.items() if name not in sums},
        )
    return True, ""


_in_flight = 0
_in_flight_lock = threading.Lock()


def tests_in_progress() -> int:
    """How many test requests this process is handling right now.

    For code whose callbacks may run outside the request's context (see harness_tools.py): a risky
    call that arrives with no session while a test is in flight may belong to that test."""
    return _in_flight


def _enter(session: _Session) -> Any:
    global _in_flight
    with _in_flight_lock:
        _in_flight += 1
    return _current.set(session)


def _leave(token: Any) -> None:
    global _in_flight
    try:
        _current.reset(token)
    finally:
        with _in_flight_lock:
            _in_flight -= 1


def record_call(tool: str, arguments: Mapping[str, Any], result: Any = _DEFAULT_RESULT) -> Any:
    """Record a tool call in the current test session without running anything, and return `result`.

    For code that catches tool calls somewhere other than a decorated function, such as a
    framework's own dispatch (see harness_tools.py). Raises HarnessError outside a test session:
    the caller decides what to do then, which is normally to run the tool as written."""
    session = _current.get()
    if session is None:
        raise HarnessError("record_call needs a BotSting test session; check pp.active() first")
    mark_tool(tool)
    session.add(
        {
            "id": f"call-{len(session.calls) + 1}",
            "tool": tool,
            "arguments": {str(k): _text(v) for k, v in arguments.items()},
            "accepted": True,
            "result": _text(result),
        }
    )
    return result


def action(tool: str, result: Any = _DEFAULT_RESULT, live: Cap | None = None, never_for_users: str = "") -> Callable[[F], F]:
    """Mark a function as a risky tool. In a test session it is recorded, not run, and returns
    `result` (or `result(**arguments)` if that is callable). Outside one it runs as written.

    `never_for_users` says that nobody chatting with the bot may ever cause this tool to run, and
    gives what an attacker would ask for, in a few words: `never_for_users="a refund of 50 on order
    A-1001"`. A first scan (`botsting scan URL`) then tries to make the bot do exactly that. Leave
    it out for a tool some users may legitimately trigger; who may is then said in a description.

    With `live=Cap(...)` it may be carried out for real in a test session, inside those limits
    and only where the owner has switched that on. See the module notes."""
    if not isinstance(never_for_users, str) or len(never_for_users) > 200:
        raise HarnessError(f"{tool}: never_for_users is a few words saying what an attacker would ask for")

    def decorate(function: F) -> F:
        signature = inspect.signature(function)
        mark_tool(tool, " ".join(never_for_users.split()))
        if live is not None:
            unknown = live.names() - (set(signature.parameters) - {"self", "cls"})
            if unknown:
                raise HarnessError(f"{tool}: the cap names {sorted(unknown)}, which are not arguments of the function")

        def decide(args: tuple[Any, ...], kwargs: dict[str, Any], session: _Session) -> tuple[dict[str, Any], bool, str]:
            try:
                bound = signature.bind(*args, **kwargs)
                bound.apply_defaults()
                arguments = {k: v for k, v in bound.arguments.items() if k not in ("self", "cls")}
            except TypeError:
                # Arguments the function would reject cannot be checked against a cap: never run them.
                return {f"arg{i}": v for i, v in enumerate(args)} | kwargs, False, ""
            real, why_not = _may_run(session, tool, live, arguments)
            return arguments, real, why_not

        def record(session: _Session, arguments: Mapping[str, Any], outcome: Any, note: str, mode: str) -> None:
            call = {
                "id": f"call-{len(session.calls) + 1}",
                "tool": tool,
                "arguments": {k: _text(v) for k, v in arguments.items()},
                "accepted": True,
                "result": (f"[{note}] " if note else "") + _text(outcome),
            }
            if mode:
                call["live"] = mode
            session.add(call)

        def stand_in(session: _Session, arguments: Mapping[str, Any], why_not: str) -> Any:
            if result is _DEFAULT_RESULT:
                outcome: Any = _StandIn(_DEFAULT_RESULT)  # a fresh one each time: the bot may change it
            else:
                outcome = result(**arguments) if callable(result) else result
            note = f"not run: {why_not}" if why_not else ""
            record(session, arguments, outcome, note, "capped" if why_not else "")
            return outcome

        if inspect.iscoroutinefunction(result):
            # Its coroutine would be handed to the bot unawaited, and recorded as "<coroutine object ...>".
            raise HarnessError(f"{tool}: result= must be a value or a plain function, not an async function")

        if inspect.iscoroutinefunction(function):

            @functools.wraps(function)
            async def run_async(*args: Any, **kwargs: Any) -> Any:
                session = _current.get()
                if session is None:
                    return await function(*args, **kwargs)
                arguments, real, why_not = decide(args, kwargs, session)
                if not real:
                    return stand_in(session, arguments, why_not)
                try:
                    outcome = await function(*args, **kwargs)
                except BaseException as error:
                    record(session, arguments, f"raised {type(error).__name__}", "ran for real within the caps", "ran")
                    raise
                record(session, arguments, outcome, "ran for real within the caps", "ran")
                return outcome

            return run_async  # type: ignore[return-value]

        @functools.wraps(function)
        def run(*args: Any, **kwargs: Any) -> Any:
            session = _current.get()
            if session is None:
                return function(*args, **kwargs)
            arguments, real, why_not = decide(args, kwargs, session)
            if not real:
                return stand_in(session, arguments, why_not)
            try:
                outcome = function(*args, **kwargs)
            except BaseException as error:
                record(session, arguments, f"raised {type(error).__name__}", "ran for real within the caps", "ran")
                raise
            record(session, arguments, outcome, "ran for real within the caps", "ran")
            return outcome

        return run  # type: ignore[return-value]

    return decorate


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)


# -- wrapping the web app ------------------------------------------------------------------


def _challenge() -> bytes | None:
    value = os.environ.get(CHALLENGE_ENV, "").strip()
    return value.encode("utf-8") if value else None


def wrap(app: Any) -> Any:
    """Wrap an ASGI or WSGI app. Without BOTSTING_HARNESS_KEY set, requests pass straight through."""
    _key()  # a key that is set but too short is a mistake worth stopping on
    # Flask and Quart serve themselves (`app.run()`, `flask run`), through an inner app they let
    # middleware replace. Wrapping that in place keeps `app` the framework's own object, so its
    # routes, its `run()` and its test client all still work, and all of them are wrapped.
    for inner, wrapper in (("asgi_app", _Asgi), ("wsgi_app", _Wsgi)):
        served = getattr(app, inner, None)
        if callable(served) and not isinstance(app, (_Asgi, _Wsgi)):
            if not isinstance(served, wrapper):
                setattr(app, inner, wrapper(served))
            return app
    if inspect.iscoroutinefunction(app) or inspect.iscoroutinefunction(type(app).__call__):
        return _Asgi(app)
    return _Wsgi(app)


def _not_on_the_wrapper(name: str) -> AttributeError:
    return AttributeError(
        f"{name!r} was asked of the object pp.wrap() returned, which only serves requests. Do everything else "
        "with your app first (routes, settings), wrap it last, and give the wrapped object to the server. "
        "If the app serves itself (app.run()), wrap what it serves instead: app.wsgi_app = pp.wrap(app.wsgi_app)."
    )


class _Asgi:
    def __init__(self, app: Any) -> None:
        self.app = app

    def __getattr__(self, name: str) -> Any:
        # Routes added after wrapping (FastAPI's @app.post) go to the app inside, which this still serves.
        if name == "app" or name.startswith("__"):
            raise AttributeError(name)
        return getattr(self.app, name)

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        challenge = _challenge()
        if challenge is not None and scope.get("method") == "GET" and scope.get("path") == CHALLENGE_PATH:
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", b"text/plain")],
                }
            )
            await send({"type": "http.response.body", "body": challenge + b"\n"})
            return
        wanted = SESSION_HEADER.lower().encode("ascii")
        tokens = [value.decode("latin-1") for name, value in scope.get("headers", []) if name.lower() == wanted]
        if not tokens:
            await self.app(scope, receive, send)  # an ordinary request
            return
        session = _open(tokens[0]) if len(tokens) == 1 else None
        if session is None:
            # It says it is a test message but is not a valid session here. Never run it as an ordinary one.
            await send({"type": "http.response.start", "status": 403, "headers": [(b"content-type", b"text/plain")]})
            await send({"type": "http.response.body", "body": _REFUSED})
            return
        if scope.get("path") == READY_PATH:
            calls = (
                CALLS_HEADER.lower().encode("ascii"),
                session.header_value(tools=True).encode("ascii"),
            )
            headers = [(b"content-type", b"text/plain"), calls]
            await send({"type": "http.response.start", "status": 200, "headers": headers})
            await send({"type": "http.response.body", "body": _READY})
            return

        async def send_with_calls(message: dict[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append(
                    (
                        CALLS_HEADER.lower().encode("ascii"),
                        session.header_value().encode("ascii"),
                    )
                )
                message = {**message, "headers": headers}
            await send(message)

        reset = _enter(session)
        try:
            await self.app(scope, receive, send_with_calls)
        finally:
            _leave(reset)


class _Wsgi:
    def __init__(self, app: Any) -> None:
        self.app = app

    def __getattr__(self, name: str) -> Any:
        # Not passed on to the app inside: its own run() would serve it unwrapped, and no test would reach it.
        if name == "app" or name.startswith("__"):
            raise AttributeError(name)
        raise _not_on_the_wrapper(name)

    def __call__(self, environ: dict[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
        challenge = _challenge()
        if challenge is not None and environ.get("REQUEST_METHOD") == "GET" and environ.get("PATH_INFO") == CHALLENGE_PATH:
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [challenge + b"\n"]
        token = environ.get("HTTP_" + SESSION_HEADER.upper().replace("-", "_"))
        if token is None:
            return self.app(environ, start_response)  # an ordinary request
        session = _open(token)
        if session is None:
            # It says it is a test message but is not a valid session here. Never run it as an ordinary one.
            start_response("403 Forbidden", [("Content-Type", "text/plain")])
            return [_REFUSED]
        if environ.get("PATH_INFO") == READY_PATH:
            length = environ.get("CONTENT_LENGTH") or "0"
            if length.isdigit() and int(length) <= 4096:
                environ["wsgi.input"].read(int(length))  # some servers drop the connection on an unread body
            start_response(
                "200 OK",
                [
                    ("Content-Type", "text/plain"),
                    (CALLS_HEADER, session.header_value(tools=True)),
                ],
            )
            return [_READY]

        def start_with_calls(status: str, headers: list[tuple[str, str]], exc_info: Any = None) -> Any:
            headers = [*headers, (CALLS_HEADER, session.header_value())]
            return start_response(status, headers) if exc_info is None else start_response(status, headers, exc_info)

        reset = _enter(session)
        body: Iterable[bytes] = ()
        try:
            body = self.app(environ, start_with_calls)
            # Read the body inside the session, so a view that runs lazily still sees it.
            # Calls made after start_response cannot be reported; see the module notes.
            return list(body)
        finally:
            try:
                close = getattr(body, "close", None)
                if callable(close):
                    close()
            finally:
                _leave(reset)  # even if close() raises: a session must never outlive its request
