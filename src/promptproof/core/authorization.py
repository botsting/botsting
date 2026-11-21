"""Authorization to scan a target that is not running inside this process.

Promptproof sends hostile messages. Pointed at someone else's bot, it is an attack
tool, so nothing is sent to a target across a network unless all of these hold:

1. **Someone is named as authorizing it.** A person, for one exact origin
   (scheme, host and port), for a stated scope and environment, until a stated date
   no more than MAX_DAYS away. The authorization names every tool the scan may
   exercise, and, if it restricts the agent or tenant, the target must name the same.
2. **Control of that origin has been shown.** The origin serves a fresh random token
   at `/.well-known/promptproof-challenge.txt`, as plain text over HTTPS, without
   redirects. Only someone who controls what the site serves can put it there.
3. **The proof is still in place when the scan runs.** It is fetched again, ignoring
   anything remembered, at the start of every scan and replay, and again whenever
   RECHECK_SECONDS have passed. The expiry and the rest of the record are checked
   before every operation on the target. A proof that has been taken down, or an
   authorization that has expired, stops the scan, which still reports what it found.

A target on this machine ("loopback") needs the record in point 1 but no proof of
control: there is no domain to prove. It still needs a named person, a scope and
an expiry, because a local server can forward to anything.

A target that runs inside this Python process ("in-process", like the practice
bots) needs nothing here: its code is right in front of the person running it. Such
a target may still call a language model served on this machine (Ollama); it may
not call a model anywhere else.

What this does not do
---------------------
This shows control of what an origin *serves*. It does not show that the person who
placed the token owns every system behind it, or that the bot's data and tools are
theirs to test; the named authorizer and the scope text are how a person takes
responsibility for that. Where a target says it runs and what tools it has are the
target adapter's declarations: this module checks them, it does not watch the
network. In open-source code anyone can delete this check; it is on by default.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import tempfile
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass, fields, replace
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import httpx

CHALLENGE_PATH = "/.well-known/promptproof-challenge.txt"
TOKEN_PREFIX = "promptproof-challenge="
MAX_DAYS = 90
RECHECK_SECONDS = 600.0
_MIN_TOKEN_LENGTH = 32
_MAX_PROOF_BYTES = 4096
_FETCH_SECONDS = 10.0  # for the whole fetch, connection to last byte
_USER_AGENT = "promptproof-authorization-check"

Reach = Literal["in-process", "loopback", "network"]
Environment = Literal["staging", "test", "production"]
REACHES: tuple[str, ...] = ("in-process", "loopback", "network")
ENVIRONMENTS: tuple[str, ...] = ("staging", "test", "production")

# Tests replace this with an httpx.MockTransport. Nothing else should.
_transport: httpx.AsyncBaseTransport | None = None


class AuthorizationError(PermissionError):
    """There is no valid authorization to send anything to this target."""


@dataclass(frozen=True)
class Authorization:
    origin: str  # normalized: scheme://host[:port], lowercase, punycode, default ports dropped
    authorized_by: str  # the person taking responsibility, as they gave their name
    scope: str  # what may be tested, in their words
    environment: str  # one of ENVIRONMENTS
    created_at: str  # ISO 8601 with a time zone
    expires_at: str  # ISO 8601 with a time zone
    token: str  # random; published by the origin to show control
    verified_at: str = ""  # when the proof was last seen in place; empty until then
    # Narrower scope. Control of a site is not permission to fire every tool behind it,
    # or to test every bot and customer account it serves.
    allowed_tools: tuple[str, ...] = ()  # every tool the target declares must be named here
    agent_id: str = ""  # if set, the target must name this agent
    tenant: str = ""  # if set, the target must name this tenant or account

    @property
    def needs_proof(self) -> bool:
        return not is_loopback_origin(self.origin)

    def expired(self, now: datetime) -> bool:
        return now >= _aware(self.expires_at, "expires_at")

    def challenge_url(self) -> str:
        return self.origin + CHALLENGE_PATH

    def challenge_line(self) -> str:
        return TOKEN_PREFIX + self.token


def _aware(value: object, name: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise AuthorizationError(f"{name} must be a date and time, got {value!r}")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise AuthorizationError(f"{name} is not a date and time: {value!r}") from exc
    if parsed.tzinfo is None:
        raise AuthorizationError(f"{name} must include a time zone, got {value!r}")
    return parsed


def normalize_origin(url: str) -> str:
    """scheme://host[:port] for a URL, or ValueError if it has no usable origin.

    Exact matching on this string is the whole point, so it is strict and canonical:
    no user info (not even an empty one), no path beyond "/", no query or fragment,
    only http or https, no port 0, international names in punycode, IPv6 compressed.
    """
    raw = url.strip()
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise ValueError(f"an origin must start with http:// or https://, got {url!r}")
    if "@" in parts.netloc:
        raise ValueError("an origin must not contain a user name or password")
    if parts.path not in ("", "/") or parts.query or parts.fragment or raw.endswith(("?", "#")):
        raise ValueError("give only the origin, such as https://staging.example.com, with no path, query or fragment")
    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise ValueError(f"no host in {url!r}")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"bad port in {url!r}") from exc
    if port == 0:
        raise ValueError("port 0 is not a usable port")
    try:
        host = ip_address(host).compressed
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError(f"the host name in {url!r} is not a valid domain name") from exc
    default = {"http": 80, "https": 443}[parts.scheme]
    shown_host = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{shown_host}" + (f":{port}" if port is not None and port != default else "")


def is_loopback_origin(origin: str) -> bool:
    host = (urlsplit(origin).hostname or "").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def validate(authorization: Authorization) -> Authorization:
    """Check a record however it was obtained: made here, or read back from a file someone could edit.

    Raises AuthorizationError naming the first problem.
    """
    a = authorization
    for item in fields(Authorization):
        value = getattr(a, item.name)
        if item.name == "allowed_tools":
            if not isinstance(value, tuple) or not all(isinstance(t, str) and t.strip() for t in value):
                raise AuthorizationError("allowed_tools must be a list of tool names")
        elif not isinstance(value, str):
            raise AuthorizationError(f"{item.name} must be text, got {value!r}")
    try:
        canonical = normalize_origin(a.origin)
    except ValueError as exc:
        raise AuthorizationError(f"origin is not usable: {exc}") from exc
    if canonical != a.origin:
        raise AuthorizationError(f"origin {a.origin!r} is not written the canonical way ({canonical!r})")
    if not a.authorized_by.strip():
        raise AuthorizationError("the record does not name the person who authorized the test")
    if not a.scope.strip():
        raise AuthorizationError("the record does not say what may be tested")
    if a.environment not in ENVIRONMENTS:
        raise AuthorizationError(f"environment must be one of {', '.join(ENVIRONMENTS)}, got {a.environment!r}")
    if a.needs_proof and not a.origin.startswith("https://"):
        raise AuthorizationError("a target across a network must be reached over https://")
    if len(a.token) < _MIN_TOKEN_LENGTH:
        raise AuthorizationError("the token is too short to be one this tool generated")
    created = _aware(a.created_at, "created_at")
    expires = _aware(a.expires_at, "expires_at")
    if not created < expires:
        raise AuthorizationError("the record expires before it was created")
    if expires - created > timedelta(days=MAX_DAYS):
        raise AuthorizationError(f"an authorization lasts at most {MAX_DAYS} days")
    if a.verified_at:
        _aware(a.verified_at, "verified_at")
    return a


def new_authorization(
    origin: str,
    authorized_by: str,
    scope: str,
    environment: str,
    days: int,
    now: datetime | None = None,
    allowed_tools: Iterable[str] = (),
    agent_id: str = "",
    tenant: str = "",
) -> Authorization:
    now = now or datetime.now(UTC)
    normalized = normalize_origin(origin)
    if not 1 <= days <= MAX_DAYS:
        raise ValueError(f"an authorization lasts between 1 and {MAX_DAYS} days")
    if environment not in ENVIRONMENTS:
        raise ValueError(f"environment must be one of {', '.join(ENVIRONMENTS)}")
    if not authorized_by.strip():
        raise ValueError("name the person who authorizes this scan")
    if not scope.strip():
        raise ValueError("state what may be tested, for example 'the support bot on this staging site'")
    if not is_loopback_origin(normalized) and not normalized.startswith("https://"):
        raise ValueError("a target across a network must be reached over https:// so its proof of control can be trusted")
    record = Authorization(
        origin=normalized,
        authorized_by=" ".join(authorized_by.split()),
        scope=" ".join(scope.split()),
        environment=environment,
        created_at=now.isoformat(timespec="seconds"),
        expires_at=(now + timedelta(days=days)).isoformat(timespec="seconds"),
        token=secrets.token_urlsafe(32),
        allowed_tools=tuple(dict.fromkeys(t.strip() for t in allowed_tools if t.strip())),
        agent_id=agent_id.strip(),
        tenant=tenant.strip(),
    )
    try:
        return validate(record)
    except AuthorizationError as exc:
        raise ValueError(str(exc)) from exc


# -- proof of control --------------------------------------------------------------------


@dataclass(frozen=True)
class ProofResult:
    ok: bool
    detail: str


async def check_proof_async(
    authorization: Authorization, transport: httpx.AsyncBaseTransport | None = None
) -> ProofResult:
    """Fetch the challenge file from the origin and look for this authorization's token.

    HTTPS only; no redirects (a redirect could point at a host someone else controls);
    asks caches not to answer; accepts only plain text; reads at most a small number of
    bytes; gives up after _FETCH_SECONDS for the whole fetch. Never raises, except that
    a caller's cancellation is passed on.
    """
    if not authorization.needs_proof:
        return ProofResult(True, "a loopback origin needs no proof of control")
    url = authorization.challenge_url()
    if not url.startswith("https://"):
        return ProofResult(False, "proof of control is only accepted over https://")

    async def fetch() -> ProofResult:
        async with httpx.AsyncClient(
            transport=transport if transport is not None else _transport,
            timeout=_FETCH_SECONDS,
            follow_redirects=False,
            headers={"User-Agent": _USER_AGENT, "Cache-Control": "no-cache", "Pragma": "no-cache"},
        ) as client:
            async with client.stream("GET", url) as response:
                if response.is_redirect:
                    return ProofResult(False, f"{url} answered with a redirect; redirects are not followed")
                if response.status_code != 200:
                    return ProofResult(False, f"{url} answered HTTP {response.status_code}")
                kind = response.headers.get("content-type", "").split(";")[0].strip().lower()
                if kind != "text/plain":
                    return ProofResult(False, f"{url} must be served as text/plain, not {kind or 'no content type'}")
                body = b""
                async for chunk in response.aiter_bytes():
                    body += chunk
                    if len(body) > _MAX_PROOF_BYTES:
                        return ProofResult(False, f"{url} is larger than {_MAX_PROOF_BYTES} bytes")
        lines = {line.strip() for line in body.decode("utf-8", "replace").splitlines()}
        if authorization.challenge_line() in lines:
            return ProofResult(True, f"token found at {url}")
        return ProofResult(False, f"{url} does not contain this authorization's token")

    try:
        return await asyncio.wait_for(fetch(), timeout=_FETCH_SECONDS)
    except TimeoutError:
        return ProofResult(False, f"no complete answer from {url} within {_FETCH_SECONDS:g} seconds")
    except httpx.HTTPError as exc:
        return ProofResult(False, f"could not fetch {url}: {type(exc).__name__}")


def check_proof(authorization: Authorization, transport: httpx.AsyncBaseTransport | None = None) -> ProofResult:
    """check_proof_async, for callers outside an event loop (the `authorize --verify` command)."""
    return asyncio.run(check_proof_async(authorization, transport))


# -- the store ---------------------------------------------------------------------------


DEFAULT_STORE = Path("promptproof.authorizations.json")


class AuthorizationStore:
    """Authorizations kept in one JSON file next to where scans are run.

    The file holds names and scope text that people typed. It stays on this machine;
    nothing here sends it anywhere. Every record is validated when it is read back,
    because the file can be edited by hand.
    """

    def __init__(self, path: Path = DEFAULT_STORE) -> None:
        self.path = Path(path)

    def load(self) -> list[Authorization]:
        if not self.path.exists():
            return []
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            items = data["authorizations"]
            if not isinstance(items, list):
                raise TypeError("'authorizations' must be a list")
            records = []
            for item in items:
                tools = item.get("allowed_tools", [])
                if not isinstance(tools, list):
                    raise TypeError("allowed_tools must be a list")
                records.append(Authorization(**{**item, "allowed_tools": tuple(tools)}))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise AuthorizationError(f"could not read {self.path}: {exc}") from exc
        for record in records:
            try:
                validate(record)
            except AuthorizationError as exc:
                raise AuthorizationError(f"{self.path} holds an unusable authorization for {record.origin!r}: {exc}") from exc
        return records

    def save(self, authorizations: Iterable[Authorization]) -> None:
        payload = json.dumps({"authorizations": [asdict(a) for a in authorizations]}, indent=2)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Written to a temporary file and renamed, so a crash cannot leave half a file.
        handle, temporary = tempfile.mkstemp(dir=self.path.parent, prefix=".promptproof-auth-", suffix=".json")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as file:
                file.write(payload)
            os.replace(temporary, self.path)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise

    def add(self, authorization: Authorization) -> None:
        validate(authorization)
        # One live authorization per origin: a new one replaces the old.
        kept = [a for a in self.load() if a.origin != authorization.origin]
        self.save([*kept, authorization])

    def find(self, origin: str) -> Authorization | None:
        normalized = normalize_origin(origin)
        return next((a for a in self.load() if a.origin == normalized), None)

    def mark_verified(self, origin: str, when: datetime) -> Authorization:
        found = self.find(origin)
        if found is None:
            raise AuthorizationError(f"no authorization for {origin}; create one with `promptproof authorize`")
        updated = replace(found, verified_at=when.isoformat(timespec="seconds"))
        self.add(updated)
        return updated


def authorization_summary(target: object) -> dict[str, str]:
    """What a report records about the permission a scan ran under. Never includes the token."""
    reach = getattr(target, "reach", "")
    authorization = getattr(target, "authorization", None)
    if reach == "in-process" or not isinstance(authorization, Authorization):
        return {"reach": str(reach)} if reach else {}
    return {
        "reach": str(reach),
        "origin": authorization.origin,
        "authorized_by": authorization.authorized_by,
        "scope": authorization.scope,
        "environment": authorization.environment,
        "expires_at": authorization.expires_at,
        "proof": "token served by the origin, checked during the scan" if authorization.needs_proof else "none needed on this machine",
        "verified_at": authorization.verified_at or "not needed",
        "allowed_tools": ", ".join(authorization.allowed_tools) or "none",
        "agent_id": authorization.agent_id or "any",
        "tenant": authorization.tenant or "any",
    }


# -- the gate ------------------------------------------------------------------------------

# (origin, token) -> monotonic time the proof was last seen in place during this process.
_seen: dict[tuple[str, str], float] = {}


def forget_checks() -> None:
    """Drop every remembered proof check, so the next check fetches again. For tests."""
    _seen.clear()


def _require_in_scope(target: object, authorization: Authorization) -> None:
    """The target must not reach beyond what the authorization names."""
    rules = getattr(target, "tool_rules", None)
    points = getattr(target, "injection_points", None)
    tools = {rule.tool for rule in (rules() if callable(rules) else ())}
    tools |= {tool for point in (points() if callable(points) else ()) for tool in point.forbidden_tools}
    unnamed = sorted(tools - set(authorization.allowed_tools))
    if unnamed:
        raise AuthorizationError(
            f"the authorization for {authorization.origin} does not name the tool(s) {', '.join(unnamed)}; "
            "re-authorize with --tool for each tool that may be exercised"
        )
    for field_name, flag in (("agent_id", "--agent"), ("tenant", "--tenant")):
        declared = str(getattr(target, field_name, "") or "")
        allowed = getattr(authorization, field_name)
        if allowed and not declared:
            raise AuthorizationError(
                f"the authorization is limited to {field_name} {allowed!r}, but this target does not say which "
                f"{field_name} it is, so the limit cannot be checked"
            )
        if declared and declared != allowed:
            raise AuthorizationError(
                f"this target's {field_name} is {declared!r} but the authorization covers {allowed or 'nothing'!r}; "
                f"re-authorize with {flag} {declared}"
            )


def require_authorized(target: object, now: datetime | None = None) -> Authorization | None:
    """Everything about permission that can be checked without the network. Raises AuthorizationError.

    Returns the authorization whose proof of control still has to be confirmed (a
    network target), or None when no proof is needed. Called before every operation
    on a target, so it must stay cheap.
    """
    reach = getattr(target, "reach", None)
    if reach not in REACHES:
        raise AuthorizationError(
            "this target does not declare where it runs (in-process, loopback or network); refusing to send it anything"
        )
    if reach == "in-process":
        return None
    origin = getattr(target, "origin", None)
    authorization = getattr(target, "authorization", None)
    if not isinstance(origin, str) or not origin:
        raise AuthorizationError("this target reaches beyond this process but does not say which origin it talks to")
    try:
        normalized = normalize_origin(origin)
    except ValueError as exc:
        raise AuthorizationError(f"this target's origin is not usable: {exc}") from exc
    if reach == "loopback" and not is_loopback_origin(normalized):
        raise AuthorizationError(f"this target says it is on this machine but its origin {normalized} is not")
    if reach == "network" and is_loopback_origin(normalized):
        raise AuthorizationError(f"this target says it is across a network but its origin {normalized} is on this machine")
    if not isinstance(authorization, Authorization):
        raise AuthorizationError(
            f"no authorization to test {normalized}. Create one with `promptproof authorize {normalized} ...`, "
            "publish its token, and verify it"
        )
    validate(authorization)
    if authorization.origin != normalized:
        raise AuthorizationError(
            f"the authorization is for {authorization.origin}, not {normalized}; each origin needs its own"
        )
    if authorization.expired(now or datetime.now(UTC)):
        raise AuthorizationError(f"the authorization for {normalized} expired at {authorization.expires_at}")
    _require_in_scope(target, authorization)
    if not authorization.needs_proof:
        return None
    if not authorization.verified_at:
        raise AuthorizationError(
            f"the authorization for {normalized} has not been verified; run `promptproof authorize --verify {normalized}`"
        )
    return authorization


async def confirm_proof(authorization: Authorization, fresh: bool = False) -> None:
    """Make sure the origin still serves the token. Raises AuthorizationError if it does not.

    `fresh` ignores anything remembered: used at the start of every scan and replay.
    Otherwise the proof is fetched again once RECHECK_SECONDS have passed.
    """
    key = (authorization.origin, authorization.token)
    last = _seen.get(key)
    if not fresh and last is not None and time.monotonic() - last < RECHECK_SECONDS:
        return
    _seen.pop(key, None)
    result = await check_proof_async(authorization)
    if not result.ok:
        raise AuthorizationError(f"proof of control for {authorization.origin} is no longer in place: {result.detail}")
    _seen[key] = time.monotonic()
