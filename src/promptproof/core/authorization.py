"""Authorization to scan a target that is not running inside this process.

Promptproof sends hostile messages. Pointed at someone else's bot, it is an attack
tool, so nothing is sent to a target across a network unless all of these hold:

1. **Someone is named as authorizing it.** A person, for one exact origin
   (scheme, host and port), for a stated scope and environment, until a stated date
   no more than MAX_DAYS away.
2. **Control of that origin has been shown.** The origin serves a fresh random token
   at `/.well-known/promptproof-challenge.txt`, over HTTPS, without redirects. Only
   someone who controls what the site serves can put it there.
3. **The proof is still in place when the scan runs.** It is checked again when a
   scan or replay starts, and again if the scan runs longer than RECHECK_SECONDS. A
   proof that has been taken down stops the scan.

A target on this machine ("loopback") needs the record in point 1 but no proof of
control: there is no domain to prove. It still needs a named person, a scope and
an expiry, because a local server can forward to anything.

A target that runs inside this Python process ("in-process", like the practice
bots) needs nothing here: its code is right in front of the person running it.

What this does not do
---------------------
This shows control of what an origin *serves*. It does not show that the person who
placed the token owns every system behind it, or that the bot's data and tools are
theirs to test; the named authorizer and the scope text are how a person takes
responsibility for that. In open-source code anyone can delete this check; it is on
by default and, for the hosted service, enforced on our side.
"""

from __future__ import annotations

import json
import os
import secrets
import tempfile
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass, replace
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
_MAX_PROOF_BYTES = 4096
_FETCH_TIMEOUT_SECONDS = 10.0
_USER_AGENT = "promptproof-authorization-check"

Reach = Literal["in-process", "loopback", "network"]
Environment = Literal["staging", "test", "production"]
REACHES: tuple[str, ...] = ("in-process", "loopback", "network")
ENVIRONMENTS: tuple[str, ...] = ("staging", "test", "production")

# Tests replace this with an httpx.MockTransport. Nothing else should.
_transport: httpx.BaseTransport | None = None


class AuthorizationError(PermissionError):
    """There is no valid authorization to send anything to this target."""


@dataclass(frozen=True)
class Authorization:
    origin: str  # normalized: scheme://host[:port], lowercase, default ports dropped
    authorized_by: str  # the person taking responsibility, as they gave their name
    scope: str  # what may be tested, in their words
    environment: str  # one of ENVIRONMENTS
    created_at: str  # ISO 8601, UTC
    expires_at: str  # ISO 8601, UTC
    token: str  # random; published by the origin to show control
    verified_at: str = ""  # when the proof was last seen in place; empty until then

    @property
    def needs_proof(self) -> bool:
        return not is_loopback_origin(self.origin)

    def expired(self, now: datetime) -> bool:
        return now >= datetime.fromisoformat(self.expires_at)

    def challenge_url(self) -> str:
        return self.origin + CHALLENGE_PATH

    def challenge_line(self) -> str:
        return TOKEN_PREFIX + self.token


def normalize_origin(url: str) -> str:
    """scheme://host[:port] for a URL, or ValueError if it has no usable origin.

    Exact matching on this string is the whole point, so it is strict: no user info,
    no path beyond "/", no query or fragment, only http or https.
    """
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https"):
        raise ValueError(f"an origin must start with http:// or https://, got {url!r}")
    if parts.username or parts.password:
        raise ValueError("an origin must not contain a user name or password")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError("give only the origin, such as https://staging.example.com, with no path, query or fragment")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError(f"no host in {url!r}")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"bad port in {url!r}") from exc
    default = {"http": 80, "https": 443}[parts.scheme]
    shown_host = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{shown_host}" + (f":{port}" if port and port != default else "")


def is_loopback_origin(origin: str) -> bool:
    host = (urlsplit(origin).hostname or "").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def new_authorization(
    origin: str,
    authorized_by: str,
    scope: str,
    environment: str,
    days: int,
    now: datetime | None = None,
) -> Authorization:
    now = now or datetime.now(UTC)
    normalized = normalize_origin(origin)
    if not authorized_by.strip():
        raise ValueError("name the person who authorizes this scan")
    if not scope.strip():
        raise ValueError("state what may be tested, for example 'the support bot on this staging site'")
    if environment not in ENVIRONMENTS:
        raise ValueError(f"environment must be one of {', '.join(ENVIRONMENTS)}")
    if not 1 <= days <= MAX_DAYS:
        raise ValueError(f"an authorization lasts between 1 and {MAX_DAYS} days")
    if not is_loopback_origin(normalized) and not normalized.startswith("https://"):
        raise ValueError("a target across a network must be reached over https:// so its proof of control can be trusted")
    return Authorization(
        origin=normalized,
        authorized_by=" ".join(authorized_by.split()),
        scope=" ".join(scope.split()),
        environment=environment,
        created_at=now.isoformat(timespec="seconds"),
        expires_at=(now + timedelta(days=days)).isoformat(timespec="seconds"),
        token=secrets.token_urlsafe(32),
    )


# -- proof of control --------------------------------------------------------------------


@dataclass(frozen=True)
class ProofResult:
    ok: bool
    detail: str


def check_proof(authorization: Authorization, transport: httpx.BaseTransport | None = None) -> ProofResult:
    """Fetch the challenge file from the origin and look for this authorization's token.

    HTTPS only, no redirects (a redirect could point at a host someone else controls),
    a short timeout and a small size limit. Never raises.
    """
    if not authorization.needs_proof:
        return ProofResult(True, "a loopback origin needs no proof of control")
    url = authorization.challenge_url()
    if not url.startswith("https://"):
        return ProofResult(False, "proof of control is only accepted over https://")
    try:
        with httpx.Client(
            transport=transport if transport is not None else _transport,
            timeout=_FETCH_TIMEOUT_SECONDS,
            follow_redirects=False,
            headers={"User-Agent": _USER_AGENT},
        ) as client:
            with client.stream("GET", url) as response:
                if response.is_redirect:
                    return ProofResult(False, f"{url} answered with a redirect; redirects are not followed")
                if response.status_code != 200:
                    return ProofResult(False, f"{url} answered HTTP {response.status_code}")
                body = b""
                for chunk in response.iter_bytes():
                    body += chunk
                    if len(body) > _MAX_PROOF_BYTES:
                        return ProofResult(False, f"{url} is larger than {_MAX_PROOF_BYTES} bytes")
    except httpx.HTTPError as exc:
        return ProofResult(False, f"could not fetch {url}: {type(exc).__name__}")
    lines = {line.strip() for line in body.decode("utf-8", "replace").splitlines()}
    if authorization.challenge_line() in lines:
        return ProofResult(True, f"token found at {url}")
    return ProofResult(False, f"{url} does not contain this authorization's token")


# -- the store ---------------------------------------------------------------------------


DEFAULT_STORE = Path("promptproof.authorizations.json")


class AuthorizationStore:
    """Authorizations kept in one JSON file next to where scans are run.

    The file holds names and scope text that people typed. It stays on this machine;
    nothing here sends it anywhere.
    """

    def __init__(self, path: Path = DEFAULT_STORE) -> None:
        self.path = Path(path)

    def load(self) -> list[Authorization]:
        if not self.path.exists():
            return []
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return [Authorization(**item) for item in data["authorizations"]]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise AuthorizationError(f"could not read {self.path}: {exc}") from exc

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


# -- the gate ------------------------------------------------------------------------------

# (origin, token) -> monotonic time the proof was last seen in place during this process.
_seen: dict[tuple[str, str], float] = {}


def forget_checks() -> None:
    """Drop every remembered proof check, so the next gate check fetches again. For tests."""
    _seen.clear()


def require_authorized(target: object, now: datetime | None = None) -> None:
    """Refuse to send anything to `target` unless it is permitted. Called at every entry point.

    A target says where it runs through `reach`. A target that does not say is refused:
    not saying where messages go is not the same as keeping them on this machine.
    """
    reach = getattr(target, "reach", None)
    if reach not in REACHES:
        raise AuthorizationError(
            "this target does not declare where it runs (in-process, loopback or network); refusing to send it anything"
        )
    if reach == "in-process":
        return
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
    if not isinstance(authorization, Authorization):
        raise AuthorizationError(
            f"no authorization to test {normalized}. Create one with `promptproof authorize {normalized} ...`, "
            "publish its token, and verify it"
        )
    if authorization.origin != normalized:
        raise AuthorizationError(
            f"the authorization is for {authorization.origin}, not {normalized}; each origin needs its own"
        )
    now = now or datetime.now(UTC)
    if authorization.expired(now):
        raise AuthorizationError(f"the authorization for {normalized} expired at {authorization.expires_at}")
    if not authorization.needs_proof:
        return
    if not authorization.verified_at:
        raise AuthorizationError(
            f"the authorization for {normalized} has not been verified; run `promptproof authorize --verify {normalized}`"
        )
    key = (authorization.origin, authorization.token)
    last = _seen.get(key)
    if last is not None and time.monotonic() - last < RECHECK_SECONDS:
        return
    result = check_proof(authorization)
    if not result.ok:
        _seen.pop(key, None)
        raise AuthorizationError(f"proof of control for {normalized} is no longer in place: {result.detail}")
    _seen[key] = time.monotonic()
