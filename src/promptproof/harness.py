"""The drop-in test harness: a few lines in the bot's own code instead of a test endpoint.

A bot scanned over HTTP needs three things from its owner: a way to plant Promptproof's
fake secrets, a recorder on every risky tool, and a way to report what the tools were
asked to do. This module gives all three, inside the bot's own process:

    import promptproof.harness as pp

    app = pp.wrap(app)                      # an ASGI app (FastAPI, Starlette) or a WSGI app (Flask, Django)

    @pp.action("refund")                    # a risky tool: recorded, never run, during a test
    def issue_refund(order_id: str, amount: float) -> dict: ...

    prompt = BASE_PROMPT + pp.planted("admin_code")   # where a fake secret lives during a test

When is it on?
--------------
Only for a request that carries a valid Promptproof session, signed with the key in the
environment variable PROMPTPROOF_HARNESS_KEY. Set that key on the staging or test
deployment only. With no key, or for any request without a valid signature (every
real user), everything here does nothing: tools run as written and `planted` returns
its default.

What a test session does
------------------------
- `planted(slot)` returns the fake secret the scan chose for that slot. It exists only
  inside that one request: no fake users or records are written anywhere.
- `content(point)` returns text the scan placed at an injection point (a document, a
  ticket), so the owner can show it wherever the bot would read such text.
- A function decorated with `@action` is not run. The call and its arguments are
  recorded, and the decorator returns the stand-in result instead.
- The scanner first asks READY_PATH, with a signed session, and starts only if the
  harness answers with a valid signature. Without a valid session that path is passed
  to the app like any other, so it tells nobody else that the harness is there.
- The recorded calls go back to the scanner in a signed response header,
  Promptproof-Tool-Calls. Only calls made before the response headers are sent are
  reported, so a streaming reply must finish its tool calls first.

What it does not do
-------------------
It cannot see a tool that is not decorated. Every tool that sends, pays, books or
deletes must carry `@action`; the scan's preflight checks that the recorder sees the
calls its tool rules expect, but it cannot find a tool nobody declared.

It uses only the standard library, so adding it to a bot adds no dependencies.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import hmac
import inspect
import json
import os
import time
from collections.abc import Callable, Iterable, Mapping
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, TypeVar

KEY_ENV = "PROMPTPROOF_HARNESS_KEY"
CHALLENGE_ENV = "PROMPTPROOF_CHALLENGE"
CHALLENGE_PATH = "/.well-known/promptproof-challenge.txt"
READY_PATH = "/.well-known/promptproof-harness"
SESSION_HEADER = "Promptproof-Session"
CALLS_HEADER = "Promptproof-Tool-Calls"
MIN_KEY_LENGTH = 32
MAX_TOKEN_BYTES = 6000  # most servers refuse headers much larger than 8 KB
MAX_CALLS = 100
MAX_LIFETIME_SECONDS = 900
_SESSION_DOMAIN = b"promptproof-session/1\n"
_CALLS_DOMAIN = b"promptproof-calls/1\n"
_DEFAULT_RESULT = {"status": "ok"}
_READY = b"promptproof harness ready\n"

F = TypeVar("F", bound=Callable[..., Any])


class HarnessError(Exception):
    pass


# -- signing (shared with the scanner) ----------------------------------------------------


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _mac(key: str, domain: bytes, *parts: str) -> str:
    message = domain + "\n".join(parts).encode("utf-8")
    return _b64(hmac.new(key.encode("utf-8"), message, hashlib.sha256).digest())


def check_key(key: str) -> str:
    if len(key) < MIN_KEY_LENGTH:
        raise HarnessError(
            f"{KEY_ENV} must be at least {MIN_KEY_LENGTH} characters; make one with `promptproof harness-key`"
        )
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
) -> str:
    """What the scanner puts in the Promptproof-Session header of each message."""
    check_key(key)
    if not 0 < lifetime_seconds <= MAX_LIFETIME_SECONDS:
        raise HarnessError(
            f"a session token may live at most {MAX_LIFETIME_SECONDS} seconds"
        )
    body = {
        "v": 1,
        "sid": session_id,
        "exp": int((time.time() if now is None else now) + lifetime_seconds),
        "fixtures": dict(fixtures),
        "content": dict(content or {}),
    }
    payload = _b64(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    token = payload + "." + _mac(key, _SESSION_DOMAIN, payload)
    if len(token) > MAX_TOKEN_BYTES:
        raise HarnessError(
            f"the planted secrets and content come to {len(token)} bytes in the header, more than {MAX_TOKEN_BYTES}; "
            "use shorter injection content"
        )
    return token


def read_calls_header(
    key: str, session_id: str, value: str | None
) -> list[dict[str, Any]]:
    """What the scanner does with the Promptproof-Tool-Calls header. Raises HarnessError if it was not
    made by a harness holding the key for this very session, or if calls were left out."""
    if value is None:
        raise HarnessError(
            f"the reply has no {CALLS_HEADER} header: the harness did not see this as a test session "
            f"(is {KEY_ENV} the same on both sides, and is the app wrapped?)"
        )
    payload, _, mac = value.strip().partition(".")
    if not mac or not hmac.compare_digest(
        mac, _mac(key, _CALLS_DOMAIN, session_id, payload)
    ):
        raise HarnessError(
            "the tool-call record is not signed by the harness for this session"
        )
    try:
        record = json.loads(_unb64(payload))
        calls, dropped = record["calls"], int(record["dropped"])
    except (ValueError, KeyError, TypeError) as error:
        raise HarnessError(f"the tool-call record is unreadable: {error}") from error
    if not isinstance(calls, list):
        raise HarnessError("the tool-call record must hold a list of calls")
    if dropped:
        raise HarnessError(
            f"the bot made more than {MAX_CALLS} tool calls in one reply; {dropped} were not recorded"
        )
    return calls


# -- the session --------------------------------------------------------------------------


@dataclass
class _Session:
    sid: str
    fixtures: dict[str, str]
    content: dict[str, str]
    key: str
    calls: list[dict[str, Any]] = field(default_factory=list)
    dropped: int = 0

    def header_value(self) -> str:
        record = {"calls": self.calls, "dropped": self.dropped}
        payload = _b64(json.dumps(record, separators=(",", ":")).encode("utf-8"))
        return payload + "." + _mac(self.key, _CALLS_DOMAIN, self.sid, payload)


_current: ContextVar[_Session | None] = ContextVar("promptproof_session", default=None)


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
    if not mac or not hmac.compare_digest(mac, _mac(key, _SESSION_DOMAIN, payload)):
        return None
    try:
        body = json.loads(_unb64(payload))
        expires = int(body["exp"])
        sid = str(body["sid"])
        fixtures = {str(k): str(v) for k, v in dict(body["fixtures"]).items()}
        content = {str(k): str(v) for k, v in dict(body.get("content", {})).items()}
    except (ValueError, KeyError, TypeError):
        return None
    if body.get("v") != 1 or expires < (time.time() if now is None else now):
        return None
    return _Session(sid=sid, fixtures=fixtures, content=content, key=key)


# -- what the bot's code calls ------------------------------------------------------------


def active() -> bool:
    """True while handling a request from a Promptproof scan."""
    return _current.get() is not None


def planted(slot_id: str, default: str = "") -> str:
    """The fake secret for this slot during a test session, `default` at any other time."""
    session = _current.get()
    if session is None:
        return default
    return session.fixtures.get(slot_id, default)


def content(point_id: str, default: str = "") -> str:
    """Text the scan placed at this injection point during a test session, `default` otherwise."""
    session = _current.get()
    if session is None:
        return default
    return session.content.get(point_id, default)


def recorded_calls() -> list[dict[str, Any]]:
    """The calls recorded so far in this request, for a bot that reports them in its own reply body."""
    session = _current.get()
    return [dict(c) for c in session.calls] if session else []


def action(tool: str, result: Any = _DEFAULT_RESULT) -> Callable[[F], F]:
    """Mark a function as a risky tool. In a test session it is recorded, not run, and returns
    `result` (or `result(**arguments)` if that is callable). Outside one it runs as written."""

    def decorate(function: F) -> F:
        signature = inspect.signature(function)

        def record(
            args: tuple[Any, ...], kwargs: dict[str, Any], session: _Session
        ) -> Any:
            try:
                bound = signature.bind(*args, **kwargs)
                bound.apply_defaults()
                arguments = {
                    k: v for k, v in bound.arguments.items() if k not in ("self", "cls")
                }
            except TypeError:
                arguments = {f"arg{i}": v for i, v in enumerate(args)} | kwargs
            stand_in = result(**arguments) if callable(result) else result
            if len(session.calls) >= MAX_CALLS:
                session.dropped += 1
            else:
                session.calls.append(
                    {
                        "id": f"call-{len(session.calls) + 1}",
                        "tool": tool,
                        "arguments": {k: _text(v) for k, v in arguments.items()},
                        "accepted": True,
                        "result": _text(stand_in),
                    }
                )
            return stand_in

        if inspect.iscoroutinefunction(function):

            @functools.wraps(function)
            async def run_async(*args: Any, **kwargs: Any) -> Any:
                session = _current.get()
                if session is None:
                    return await function(*args, **kwargs)
                return record(args, kwargs, session)

            return run_async  # type: ignore[return-value]

        @functools.wraps(function)
        def run(*args: Any, **kwargs: Any) -> Any:
            session = _current.get()
            if session is None:
                return function(*args, **kwargs)
            return record(args, kwargs, session)

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
    """Wrap an ASGI or WSGI app. Without PROMPTPROOF_HARNESS_KEY set, requests pass straight through."""
    _key()  # a key that is set but too short is a mistake worth stopping on
    if inspect.iscoroutinefunction(app) or inspect.iscoroutinefunction(
        type(app).__call__
    ):
        return _Asgi(app)
    return _Wsgi(app)


class _Asgi:
    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        challenge = _challenge()
        if (
            challenge is not None
            and scope.get("method") == "GET"
            and scope.get("path") == CHALLENGE_PATH
        ):
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", b"text/plain")],
                }
            )
            await send({"type": "http.response.body", "body": challenge + b"\n"})
            return
        token = None
        wanted = SESSION_HEADER.lower().encode("ascii")
        for name, value in scope.get("headers", []):
            if name.lower() == wanted:
                token = value.decode("latin-1")
        session = _open(token)
        if session is None:
            await self.app(scope, receive, send)
            return
        if scope.get("path") == READY_PATH:
            calls = (
                CALLS_HEADER.lower().encode("ascii"),
                session.header_value().encode("ascii"),
            )
            headers = [(b"content-type", b"text/plain"), calls]
            await send(
                {"type": "http.response.start", "status": 200, "headers": headers}
            )
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

        reset = _current.set(session)
        try:
            await self.app(scope, receive, send_with_calls)
        finally:
            _current.reset(reset)


class _Wsgi:
    def __init__(self, app: Any) -> None:
        self.app = app

    def __call__(
        self, environ: dict[str, Any], start_response: Callable[..., Any]
    ) -> Iterable[bytes]:
        challenge = _challenge()
        if (
            challenge is not None
            and environ.get("REQUEST_METHOD") == "GET"
            and environ.get("PATH_INFO") == CHALLENGE_PATH
        ):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [challenge + b"\n"]
        session = _open(environ.get("HTTP_" + SESSION_HEADER.upper().replace("-", "_")))
        if session is None:
            return self.app(environ, start_response)
        if environ.get("PATH_INFO") == READY_PATH:
            length = environ.get("CONTENT_LENGTH") or "0"
            if length.isdigit() and int(length) <= 4096:
                environ["wsgi.input"].read(int(length))  # some servers drop the connection on an unread body
            start_response(
                "200 OK",
                [
                    ("Content-Type", "text/plain"),
                    (CALLS_HEADER, session.header_value()),
                ],
            )
            return [_READY]

        def start_with_calls(
            status: str, headers: list[tuple[str, str]], exc_info: Any = None
        ) -> Any:
            headers = [*headers, (CALLS_HEADER, session.header_value())]
            return (
                start_response(status, headers)
                if exc_info is None
                else start_response(status, headers, exc_info)
            )

        reset = _current.set(session)
        body: Iterable[bytes] = ()
        try:
            body = self.app(environ, start_with_calls)
            # Read the body inside the session, so a view that runs lazily still sees it.
            # Calls made after start_response cannot be reported; see the module notes.
            return list(body)
        finally:
            close = getattr(body, "close", None)
            if callable(close):
                close()
            _current.reset(reset)
