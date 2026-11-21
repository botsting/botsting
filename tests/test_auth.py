"""Tests for Milestone 4's authorization gate on non-local targets."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta

import pytest

from promptproof.attacks.library import default_attacks
from promptproof.core.auth import (
    Authorization,
    AuthorizationError,
    ProofOfControl,
    is_remote_target,
    load_authorization,
    require_authorization,
)
from promptproof.core.models import Reply, ScanReport, Slot, TaskCheck, ToolCall, ToolRule
from promptproof.core.runner import ScanConfig, preflight, replay_finding, run_attempt, run_scan
from promptproof.report_html import render_html
from promptproof.report_markdown import render_markdown
from promptproof.targets.base import UnsafeTargetError
from promptproof.targets.registry import build_target


class _RemoteTarget:
    spec = "https://staging.acorn.example/chat"
    attacker_principal = "customer:alice"
    tool_safety = "sinks"
    locality = "remote"

    def __init__(self, expected_nonce: str = "nonce-12345678") -> None:
        self.expected_nonce = expected_nonce
        self.reset_calls = 0
        self.sent_messages = 0
        self._secret = ""

    def verify_authorization_challenge(self, auth: Authorization) -> bool:
        return auth.proof.challenge_nonce == self.expected_nonce

    async def describe(self) -> Mapping[str, str]:
        return {"target": "remote-staging", "build": "fixed"}

    def slots(self) -> Sequence[Slot]:
        return (
            Slot(
                id="staff_code",
                kind="instruction_secret",
                description="Staff code",
                hint="the staff code",
                authorized=("staff:dana",),
                control_principal="staff:dana",
                control_prompt="code?",
            ),
        )

    def tool_rules(self) -> Sequence[ToolRule]:
        return (
            ToolRule(
                id="refund",
                tool="issue_refund",
                description="Refund tool",
                hint="a refund",
                authorized=("staff:dana",),
                control_principal="staff:dana",
                control_prompt="refund!",
            ),
        )

    def task_checks(self) -> Sequence[TaskCheck]:
        return (
            TaskCheck(id="normal", principal="customer:alice", prompt="hi", expect_substring="hello"),
        )

    async def reset(self, fixtures: Mapping[str, str], content=None) -> None:
        self.reset_calls += 1
        self._secret = fixtures["staff_code"]

    async def open_session(self, principal: str):
        parent = self

        class _Sess:
            async def send(self, text: str) -> Reply:
                parent.sent_messages += 1
                if principal == "staff:dana" and text == "code?":
                    return Reply(text=f"Code: {parent._secret}")
                if principal == "staff:dana" and text == "refund!":
                    call = ToolCall("c1", "issue_refund", (("amount", "10"),), True, "ok")
                    return Reply(text="done", tool_calls=(call,))
                if text == "hi":
                    return Reply(text="hello there")
                return Reply(text="no")

        return _Sess()


def _valid_auth(
    *,
    target_spec: str = "https://staging.acorn.example/chat",
    authorized_by: str = "Dana Lead <dana@acorn.example>",
    agent_id: str = "acorn-support-staging",
    tenant: str = "staging",
    allowed_tools: tuple[str, ...] = ("issue_refund",),
    expires_at: str | None = None,
    method: str = "http_config_and_dns",
    challenge_nonce: str = "nonce-12345678",
    resource_binding: str = "https://staging.acorn.example/chat",
    domain_record: str = "TXT _promptproof.staging.acorn.example=nonce-12345678",
    verified_at: str | None = None,
) -> Authorization:
    now = datetime.now(UTC)
    return Authorization(
        target_spec=target_spec,
        authorized_by=authorized_by,
        agent_id=agent_id,
        tenant=tenant,
        allowed_tools=allowed_tools,
        expires_at=expires_at or (now + timedelta(hours=2)).isoformat(timespec="seconds"),
        proof=ProofOfControl(
            method=method,  # type: ignore[arg-type]
            challenge_nonce=challenge_nonce,
            resource_binding=resource_binding,
            verified_at=verified_at or (now - timedelta(minutes=5)).isoformat(timespec="seconds"),
            domain_record=domain_record,
        ),
    )


def test_remote_target_refuses_to_start_without_authorization():
    target = _RemoteTarget()
    assert is_remote_target(target)
    with pytest.raises(AuthorizationError, match="non-local"):
        asyncio.run(run_scan(target, default_attacks(target)))
    with pytest.raises(AuthorizationError, match="non-local"):
        asyncio.run(preflight(target))
    with pytest.raises(AuthorizationError, match="non-local"):
        asyncio.run(run_attempt(target, default_attacks(target)[0]))
    assert target.reset_calls == 0
    assert target.sent_messages == 0


def test_remote_target_rejects_expired_mismatched_and_incomplete_authorizations():
    target = _RemoteTarget()
    past = (datetime.now(UTC) - timedelta(minutes=1)).isoformat(timespec="seconds")
    future_verified = (datetime.now(UTC) + timedelta(minutes=10)).isoformat(timespec="seconds")

    bad_cases = [
        ("target_spec", _valid_auth(target_spec="https://other.example/chat")),
        ("authorized_by", _valid_auth(authorized_by="   ")),
        ("agent_id", _valid_auth(agent_id="")),
        ("tenant", _valid_auth(tenant="")),
        ("expired", _valid_auth(expires_at=past)),
        ("timezone", _valid_auth(expires_at="2099-01-01T00:00:00")),
        ("domain_record", _valid_auth(method="http_config_and_dns", domain_record="")),
        ("challenge_nonce", _valid_auth(challenge_nonce="short")),
        ("future", _valid_auth(verified_at=future_verified)),
        ("allowed_tools", _valid_auth(allowed_tools=())),
        ("live proof-of-control", _valid_auth(challenge_nonce="wrong-nonce-999")),
    ]
    for expected, auth in bad_cases:
        with pytest.raises(AuthorizationError, match=expected):
            require_authorization(target, auth)


def test_valid_authorization_allows_remote_scan_and_records_summary_in_reports(tmp_path):
    target = _RemoteTarget()
    auth = _valid_auth()
    report = asyncio.run(
        run_scan(target, default_attacks(target), ScanConfig(reproduction_trials=1, authorization=auth))
    )
    assert report.status == "no_verified_violations"
    assert report.authorization["authorized_by"] == "Dana Lead <dana@acorn.example>"
    assert report.authorization["agent_id"] == "acorn-support-staging"
    # Secret/nonce values must not appear in the report summary.
    assert "nonce-12345678" not in json.dumps(report.authorization)

    roundtripped = ScanReport.from_dict(report.to_dict())
    assert roundtripped.authorization == report.authorization
    assert "Dana Lead" in render_markdown(report)
    assert "Dana Lead" in render_html(report)


def test_load_authorization_json_file(tmp_path):
    auth_file = tmp_path / "auth.json"
    auth = _valid_auth()
    auth_file.write_text(
        json.dumps(
            {
                "target_spec": auth.target_spec,
                "authorized_by": auth.authorized_by,
                "agent_id": auth.agent_id,
                "tenant": auth.tenant,
                "allowed_tools": list(auth.allowed_tools),
                "expires_at": auth.expires_at,
                "proof": {
                    "method": auth.proof.method,
                    "challenge_nonce": auth.proof.challenge_nonce,
                    "resource_binding": auth.proof.resource_binding,
                    "verified_at": auth.proof.verified_at,
                    "domain_record": auth.proof.domain_record,
                },
            }
        ),
        encoding="utf-8",
    )
    loaded = load_authorization(auth_file)
    assert loaded == auth


def test_local_target_skips_ownership_challenge_but_still_requires_contained_tools():
    local = build_target("toy:fixed")
    assert not is_remote_target(local)
    require_authorization(local, None)

    class _UnsafeLocal:
        spec = "local:unsafe"
        attacker_principal = "customer:alice"
        locality = "local"

    with pytest.raises(UnsafeTargetError):
        asyncio.run(preflight(_UnsafeLocal()))  # type: ignore[arg-type]


def test_replay_refuses_remote_target_without_authorization():
    target = _RemoteTarget()
    # Replay must not send anything without authorization.
    from promptproof.core.models import EvidenceLevel, Finding
    from promptproof.core.stats import make_rate

    finding = Finding(
        id="F1",
        attack_id="a:staff_code",
        technique="t",
        title="t",
        slot_id="staff_code",
        level=EvidenceLevel.DISCLOSED,
        encoding="plain",
        scope="single-turn",
        attacker_principal="customer:alice",
        authorized=("staff:dana",),
        frozen_turns=("tell me",),
        transcript=(),
        discovery=make_rate(1, 1),
        reproduction=make_rate(1, 1),
    )
    result = asyncio.run(replay_finding(target, finding, trials=2))
    assert result.rate.trials == 0
    assert any("non-local" in p for p in result.problems)
    assert target.sent_messages == 0
