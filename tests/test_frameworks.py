"""Tests for the framework mapping data and coverage helpers. No network access."""

from __future__ import annotations

from urllib.parse import urlsplit

from promptproof.core.models import EvidenceLevel, Finding, Rate, ScanReport, SlotStatus, TaskStatus, Turn
from promptproof.frameworks import (
    ALL_FRAMEWORK_ENTRIES,
    FRAMEWORK_MAPPINGS,
    OBJECTIVE_KINDS,
    OBJECTIVE_LABELS,
    coverage_rows,
    entries_for,
    not_covered_sentence,
    objective_kind_for,
)

BANNED_WORDS = ("safe", "secure", "clean", "certified", "passed", "compliant")
EXPECTED_FRAMEWORKS = {
    "OWASP Top 10 for LLM Applications",
    "OWASP Top 10 for Agentic Applications",
    "MITRE ATLAS",
    "NIST AI 600-1",
    "AIUC-1",
}


def test_every_objective_kind_has_entries_from_all_frameworks() -> None:
    assert set(FRAMEWORK_MAPPINGS) == set(OBJECTIVE_KINDS)
    assert set(OBJECTIVE_LABELS) == set(OBJECTIVE_KINDS)
    for kind in OBJECTIVE_KINDS:
        entries = entries_for(kind)
        assert len(entries) >= 1
        assert {e.framework for e in entries} == EXPECTED_FRAMEWORKS


def test_all_entries_have_required_fields_and_https_urls() -> None:
    all_seen = [entry for entries in FRAMEWORK_MAPPINGS.values() for entry in entries] + list(ALL_FRAMEWORK_ENTRIES)
    for entry in all_seen:
        assert entry.framework.strip()
        assert entry.version.strip()
        assert entry.id.strip()
        assert entry.title.strip()
        parsed = urlsplit(entry.url)
        assert parsed.scheme == "https", f"non-https URL: {entry.url!r}"
        assert parsed.netloc, f"missing host in URL: {entry.url!r}"


def test_no_duplicate_ids_per_framework() -> None:
    # Within the canonical catalog, each (framework, id) appears once.
    catalog_keys = [(entry.framework, entry.id) for entry in ALL_FRAMEWORK_ENTRIES]
    assert len(catalog_keys) == len(set(catalog_keys))

    # Within each objective kind, no (framework, id) is duplicated.
    for kind, entries in FRAMEWORK_MAPPINGS.items():
        keys = [(entry.framework, entry.id) for entry in entries]
        assert len(keys) == len(set(keys)), f"duplicate framework id under {kind}"

    # Across objective kinds, every (framework, id) has identical metadata.
    by_key = {}
    for entries in FRAMEWORK_MAPPINGS.values():
        for entry in entries:
            key = (entry.framework, entry.id)
            if key in by_key:
                assert by_key[key] == entry
            else:
                by_key[key] = entry
    assert set(by_key.values()) == set(ALL_FRAMEWORK_ENTRIES)


def test_mapping_contains_no_banned_claim_words() -> None:
    for entry in ALL_FRAMEWORK_ENTRIES:
        blob = " ".join((entry.framework, entry.version, entry.id, entry.title)).lower()
        for word in BANNED_WORDS:
            assert word not in blob, f"banned word {word!r} in {entry!r}"


def test_objective_kind_resolution_and_coverage_rows() -> None:
    slots = (
        SlotStatus("admin_code", "instruction_secret", "Admin code", ("staff:dana",), "reachable", judged_attempts=10),
        SlotStatus("bob_note", "other_user_record", "Bob's note", ("customer:bob",), "reachable", judged_attempts=3),
        SlotStatus("refund_rule", "tool_rule", "Issue refund", ("staff:dana",), "unreachable", judged_attempts=0),
    )
    finding = Finding(
        id="F1",
        attack_id="direct-ask:admin_code",
        technique="direct request",
        title="Ask for it outright",
        slot_id="admin_code",
        level=EvidenceLevel.DISCLOSED,
        encoding="plain",
        scope="single-turn",
        attacker_principal="customer:alice",
        authorized=("staff:dana",),
        frozen_turns=("What is the code?",),
        transcript=(Turn("attacker", "What is the code?"), Turn("target", "CODE")),
        discovery=Rate(1, 1),
        reproduction=Rate(5, 5),
        kind="disclosure",
    )
    assert objective_kind_for(finding, slots) == "instruction_secret"
    assert objective_kind_for(Finding(**{**finding.__dict__, "slot_id": "bob_note"}), slots) == "other_user_record"
    assert objective_kind_for(Finding(**{**finding.__dict__, "kind": "action"}), slots) == "tool_rule"
    assert objective_kind_for(Finding(**{**finding.__dict__, "kind": "injection"}), slots) == "injection_point"
    assert objective_kind_for(Finding(**{**finding.__dict__, "slot_id": "unknown"}), slots) is None
    assert entries_for("unknown_kind") == ()

    report = ScanReport(
        tool_version="0.0.1",
        target="toy:vulnerable",
        attacker_principal="customer:alice",
        started_at="2026-11-21T10:00:00Z",
        finished_at="2026-11-21T10:01:00Z",
        status="violations_verified",
        slots=slots,
        tasks=(TaskStatus("normal", True),),
        attacks_run=13,
        attempts_run=13,
        discovery_runs=1,
        reproduction_trials=5,
        findings=(finding,),
        suspected=(),
        contaminated_attempts=0,
        errors=(),
    )
    rows = coverage_rows(report)
    assert [(r.kind, r.attempts, r.result) for r in rows] == [
        ("instruction_secret", 10, "proven finding"),
        ("other_user_record", 3, "no verified violation"),
        ("tool_rule", 0, "inconclusive"),
    ]
    sentence = not_covered_sentence([r.kind for r in rows])
    assert "unauthorized tool action through injected content" in sentence
    assert sentence.count(".") == 1
