"""Authorization gate for non-local targets (Milestone 4, PLAN.md).

Ownership of a host or token alone is not enough to authorize a security scan. Before
anything is sent to a non-local target, the runner requires an explicit, unexpired
`Authorization` naming:

- who authorized the scan (`authorized_by`),
- the exact resource and scope (`target_spec`, `agent_id`, `tenant`, `allowed_tools`),
- an expiry timestamp in UTC (`expires_at`), and
- `ProofOfControl` binding a configuration challenge nonce to the exact resource (plus
  a domain record where applicable, so neither a domain record alone nor a token alone
  is accepted).

Built-in local practice targets (`locality == "local"`, such as `toy:*` and `hardened:*`)
skip the ownership challenge only; tool-containment (`require_contained_tools`) and all
scan limits still apply to them.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from promptproof.targets.base import Target, tool_rules

ProofMethod = Literal[
    "http_config_and_dns",
    "telegram_token_and_config",
    "email_admin_and_dns",
    "platform_admin",
]

_VALID_METHODS: frozenset[str] = frozenset(
    ("http_config_and_dns", "telegram_token_and_config", "email_admin_and_dns", "platform_admin")
)
_METHODS_REQUIRING_DNS: frozenset[str] = frozenset(("http_config_and_dns", "email_admin_and_dns"))
_REMOTE_PREFIXES: tuple[str, ...] = (
    "http://",
    "https://",
    "ws://",
    "wss://",
    "http:",
    "https:",
    "telegram:",
    "email:",
    "whatsapp:",
    "sms:",
    "slack:",
    "discord:",
    "voice:",
    "platform:",
    "remote:",
)


class AuthorizationError(ValueError):
    """The scan is not authorized to run against this target."""


@dataclass(frozen=True)
class ProofOfControl:
    """Evidence that the authorizer controls the exact application resource, not just a domain or token."""

    method: ProofMethod
    challenge_nonce: str
    resource_binding: str
    verified_at: str  # ISO 8601 UTC timestamp
    domain_record: str = ""


@dataclass(frozen=True)
class Authorization:
    """Explicit, scoped, expiring authorization record for scanning one non-local target."""

    target_spec: str
    authorized_by: str
    agent_id: str
    tenant: str
    allowed_tools: tuple[str, ...]
    expires_at: str  # ISO 8601 UTC timestamp
    proof: ProofOfControl

    def summary(self) -> dict[str, str]:
        """Non-sensitive fields safe to record in reports (never includes secret tokens)."""
        return {
            "authorized_by": self.authorized_by,
            "agent_id": self.agent_id,
            "tenant": self.tenant,
            "allowed_tools": ", ".join(self.allowed_tools) if self.allowed_tools else "none",
            "expires_at": self.expires_at,
            "proof_method": self.proof.method,
            "resource_binding": self.proof.resource_binding,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Authorization":
        if not isinstance(data, dict):
            raise AuthorizationError("authorization file must contain a JSON object")
        proof_raw = data.get("proof")
        if not isinstance(proof_raw, dict):
            raise AuthorizationError("authorization is missing a 'proof' object")
        tools_raw = data.get("allowed_tools", ())
        if not isinstance(tools_raw, list) or not all(isinstance(t, str) for t in tools_raw):
            raise AuthorizationError("authorization 'allowed_tools' must be a list of tool names")
        try:
            proof = ProofOfControl(
                method=proof_raw["method"],
                challenge_nonce=str(proof_raw["challenge_nonce"]),
                resource_binding=str(proof_raw["resource_binding"]),
                verified_at=str(proof_raw["verified_at"]),
                domain_record=str(proof_raw.get("domain_record", "")),
            )
            return cls(
                target_spec=str(data["target_spec"]),
                authorized_by=str(data["authorized_by"]),
                agent_id=str(data["agent_id"]),
                tenant=str(data["tenant"]),
                allowed_tools=tuple(tools_raw),
                expires_at=str(data["expires_at"]),
                proof=proof,
            )
        except KeyError as exc:
            raise AuthorizationError(f"authorization is missing required field {exc.args[0]!r}") from exc


def load_authorization(path: str | Path) -> Authorization:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise AuthorizationError(f"could not read authorization file {path}: {exc}") from exc
    return Authorization.from_dict(raw)


def is_remote_target(target: Target) -> bool:
    """True when the target is non-local and therefore requires explicit authorization."""
    declared = getattr(target, "locality", None)
    if declared == "remote":
        return True
    if declared == "local":
        return False
    spec = getattr(target, "spec", "").strip().lower()
    if spec.startswith(_REMOTE_PREFIXES):
        return True
    return False


def _parse_utc(value: str, field_name: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise AuthorizationError(f"authorization {field_name} must be a non-empty ISO 8601 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuthorizationError(f"authorization {field_name} is not a valid ISO 8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise AuthorizationError(f"authorization {field_name} must include a timezone offset (UTC)")
    return parsed.astimezone(UTC)


def require_authorization(
    target: Target,
    authorization: Authorization | None,
    *,
    now: datetime | None = None,
    challenge_verifier: Callable[[Target, Authorization], bool] | None = None,
) -> None:
    """Refuse to start a scan against a non-local target unless valid, unexpired authorization is present."""
    if not is_remote_target(target):
        return
    if authorization is None:
        raise AuthorizationError(
            f"target {target.spec!r} is non-local and requires an explicit authorization record "
            "(--auth <file>) with proof of control, named authorizer, scope, and expiry"
        )
    if authorization.target_spec != target.spec:
        raise AuthorizationError(
            f"authorization target_spec {authorization.target_spec!r} does not match target {target.spec!r}"
        )
    if not authorization.authorized_by.strip():
        raise AuthorizationError("authorization must name the person authorizing the scan (authorized_by)")
    if not authorization.agent_id.strip():
        raise AuthorizationError("authorization must specify the exact agent_id in scope")
    if not authorization.tenant.strip():
        raise AuthorizationError("authorization must specify the exact tenant/environment in scope")

    current = (now or datetime.now(UTC)).astimezone(UTC)
    expires = _parse_utc(authorization.expires_at, "expires_at")
    if expires <= current:
        raise AuthorizationError(
            f"authorization expired at {authorization.expires_at} (current time {current.isoformat(timespec='seconds')})"
        )

    proof = authorization.proof
    if proof.method not in _VALID_METHODS:
        raise AuthorizationError(
            f"unsupported proof method {proof.method!r}; expected one of {sorted(_VALID_METHODS)}"
        )
    if len(proof.challenge_nonce.strip()) < 8:
        raise AuthorizationError("proof.challenge_nonce must be a non-trivial challenge placed in target config")
    if not proof.resource_binding.strip():
        raise AuthorizationError("proof.resource_binding must identify the exact resource under control")
    verified_at = _parse_utc(proof.verified_at, "proof.verified_at")
    if verified_at > current:
        raise AuthorizationError("proof.verified_at cannot be in the future")
    if proof.method in _METHODS_REQUIRING_DNS and not proof.domain_record.strip():
        raise AuthorizationError(
            f"proof method {proof.method!r} requires both a configuration challenge and a domain_record"
        )

    # Every tool declared by the target must be explicitly listed in the authorization's scope.
    declared_tools = {rule.tool for rule in tool_rules(target)}
    missing_tools = sorted(declared_tools - set(authorization.allowed_tools))
    if missing_tools:
        raise AuthorizationError(
            f"authorization allowed_tools does not cover target tool(s): {', '.join(missing_tools)}"
        )

    # Optional live challenge verification hook (for adapters that can check the staging nonce live).
    verifier = challenge_verifier or getattr(target, "verify_authorization_challenge", None)
    if callable(verifier):
        ok = verifier(target, authorization) if challenge_verifier is not None else verifier(authorization)
        if not ok:
            raise AuthorizationError(
                "live proof-of-control challenge failed: target configuration did not confirm challenge_nonce"
            )
