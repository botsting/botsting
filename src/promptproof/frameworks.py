"""Data-only mapping from Promptproof objective kinds to public security frameworks.

Every id, edition and title below was checked against the framework's own publication,
and then checked again by a second, independent pass on 2026-11-22:
- OWASP Top 10 for LLM Applications (2026, published August 2026)
- OWASP Top 10 for Agentic Applications (2026, published December 2025)
- MITRE ATLAS (v2026.10, October 2026)
- NIST AI 600-1: Artificial Intelligence Risk Management Framework: Generative AI Profile (July 2024)
- AIUC-1 (Q4 2026, October 2026)

Notes for whoever updates this:
- NIST AI 600-1 gives its suggested actions no titles. The text shown for an action id is
  the opening of the action, word for word, ending in "..." where it is cut.
- The atlas.mitre.org technique pages are drawn in the browser; a plain fetch of them
  answers 404. The ids and names here were checked against MITRE's ATLAS-2026.10 data
  release.
- An entry is listed for an objective only where the entry's own text covers it. Entries
  that fit only loosely were removed after the second pass (AIUC-1 B007 and B009, NIST
  MS-4.2-001, and ASI01 and MS-2.10-001 for an instruction secret). AIUC-1 A006 (personal
  data) was removed because a planted record need not be personal data.
- AIUC-1 A009 and B001 ask for testing by an appointed third party at least every three
  months. A scan can be evidence toward them; it does not meet them alone.

This mapping covers only the four objective kinds Promptproof tests. It is never full
coverage of any framework, and a scan result is never a claim of compliance,
certification, or passing a framework.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from promptproof.core.models import Finding, ScanReport, SlotStatus

ObjectiveKind = Literal[
    "instruction_secret",
    "other_user_record",
    "tool_rule",
    "injection_point",
]

OBJECTIVE_KINDS: tuple[ObjectiveKind, ...] = (
    "instruction_secret",
    "other_user_record",
    "tool_rule",
    "injection_point",
)

OBJECTIVE_LABELS: dict[ObjectiveKind, str] = {
    "instruction_secret": "Leak of an instruction secret",
    "other_user_record": "Leak of another user's record",
    "tool_rule": "Unauthorized tool action by direct request",
    "injection_point": "Unauthorized tool action through injected content",
}

CoverageResult = Literal["proven finding", "no verified violation", "inconclusive"]


@dataclass(frozen=True)
class FrameworkEntry:
    """One verified reference in a public AI security or risk framework."""

    framework: str
    version: str
    id: str
    title: str
    url: str


# -- OWASP Top 10 for LLM Applications (2026) -----------------------------------------------

_OWASP_LLM = "OWASP Top 10 for LLM Applications"
_OWASP_LLM_VER = "2026"

_LLM01 = FrameworkEntry(
    framework=_OWASP_LLM,
    version=_OWASP_LLM_VER,
    id="LLM01:2026",
    title="Prompt Injection",
    url="https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/final/LLM01_PromptInjection.md",
)
_LLM02 = FrameworkEntry(
    framework=_OWASP_LLM,
    version=_OWASP_LLM_VER,
    id="LLM02:2026",
    title="Sensitive Information Disclosure",
    url="https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/final/LLM02_SensitiveInformationDisclosure.md",
)
_LLM03 = FrameworkEntry(
    framework=_OWASP_LLM,
    version=_OWASP_LLM_VER,
    id="LLM03:2026",
    title="Excessive Agency",
    url="https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/final/LLM03_ExcessiveAgency.md",
)
_LLM08 = FrameworkEntry(
    framework=_OWASP_LLM,
    version=_OWASP_LLM_VER,
    id="LLM08:2026",
    title="Hidden Context Exposure",
    url="https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/final/LLM08_HiddenContextExposure.md",
)

# -- OWASP Top 10 for Agentic Applications (2026) -------------------------------------------

_OWASP_AGENTIC = "OWASP Top 10 for Agentic Applications"
_OWASP_AGENTIC_VER = "2026"
_OWASP_AGENTIC_URL = "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"

_ASI01 = FrameworkEntry(
    framework=_OWASP_AGENTIC,
    version=_OWASP_AGENTIC_VER,
    id="ASI01",
    title="Agent Goal Hijack",
    url=_OWASP_AGENTIC_URL,
)
_ASI02 = FrameworkEntry(
    framework=_OWASP_AGENTIC,
    version=_OWASP_AGENTIC_VER,
    id="ASI02",
    title="Tool Misuse and Exploitation",
    url=_OWASP_AGENTIC_URL,
)
_ASI03 = FrameworkEntry(
    framework=_OWASP_AGENTIC,
    version=_OWASP_AGENTIC_VER,
    id="ASI03",
    title="Identity and Privilege Abuse",
    url=_OWASP_AGENTIC_URL,
)

# -- MITRE ATLAS (v2026.10) -----------------------------------------------------------------

_ATLAS = "MITRE ATLAS"
_ATLAS_VER = "v2026.10"

_ATLAS_DIRECT_PI = FrameworkEntry(
    framework=_ATLAS,
    version=_ATLAS_VER,
    id="AML.T0051.000",
    title="LLM Prompt Injection: Direct",
    url="https://atlas.mitre.org/techniques/AML.T0051.000",
)
_ATLAS_INDIRECT_PI = FrameworkEntry(
    framework=_ATLAS,
    version=_ATLAS_VER,
    id="AML.T0051.001",
    title="LLM Prompt Injection: Indirect",
    url="https://atlas.mitre.org/techniques/AML.T0051.001",
)
_ATLAS_TOOL_INVOCATION = FrameworkEntry(
    framework=_ATLAS,
    version=_ATLAS_VER,
    id="AML.T0053",
    title="AI Agent Tool Invocation",
    url="https://atlas.mitre.org/techniques/AML.T0053",
)
_ATLAS_DATA_AI_SERVICES = FrameworkEntry(
    framework=_ATLAS,
    version=_ATLAS_VER,
    id="AML.T0085",
    title="Data from AI Services",
    url="https://atlas.mitre.org/techniques/AML.T0085",
)
_ATLAS_SYSTEM_INSTRUCTIONS = FrameworkEntry(
    framework=_ATLAS,
    version=_ATLAS_VER,
    id="AML.T0085.003",
    title="Data from AI Services: System Instructions",
    url="https://atlas.mitre.org/techniques/AML.T0085.003",
)
_ATLAS_EXFIL_UI = FrameworkEntry(
    framework=_ATLAS,
    version=_ATLAS_VER,
    id="AML.T0136",
    title="Exfiltration via AI User Interface",
    url="https://atlas.mitre.org/techniques/AML.T0136",
)

# -- NIST AI 600-1 (July 2024) --------------------------------------------------------------

_NIST = "NIST AI 600-1"
_NIST_VER = "July 2024"
_NIST_URL = "https://nvlpubs.nist.gov/nistpubs/AI/NIST.AI.600-1.pdf"

_NIST_DATA_PRIVACY = FrameworkEntry(
    framework=_NIST,
    version=_NIST_VER,
    id="Section 2.4",
    title="Data Privacy",
    url=_NIST_URL,
)
_NIST_INFO_SECURITY = FrameworkEntry(
    framework=_NIST,
    version=_NIST_VER,
    id="Section 2.9",
    title="Information Security",
    url=_NIST_URL,
)
_NIST_MS_2_7_001 = FrameworkEntry(
    framework=_NIST,
    version=_NIST_VER,
    id="MS-2.7-001",
    title=(
        "Apply established security measures to: Assess likelihood and magnitude of vulnerabilities and threats "
        "such as backdoors, compromised dependencies, data breaches, eavesdropping, man-in-the-middle attacks, ..."
    ),
    url=_NIST_URL,
)
_NIST_MS_2_7_007 = FrameworkEntry(
    framework=_NIST,
    version=_NIST_VER,
    id="MS-2.7-007",
    title=(
        "Perform AI red-teaming to assess resilience against: Abuse to facilitate attacks on other systems "
        "(e.g., malicious code generation, enhanced phishing content), GAI attacks (e.g., prompt injection), ..."
    ),
    url=_NIST_URL,
)
_NIST_MS_2_10_001 = FrameworkEntry(
    framework=_NIST,
    version=_NIST_VER,
    id="MS-2.10-001",
    title=(
        "Conduct AI red-teaming to assess issues such as: Outputting of training data samples, and subsequent "
        "reverse engineering, model extraction, and membership inference risks; Revealing biometric, confidential, "
        "copyrighted, licensed, patented, personal, proprietary, sensitive, or trade-marked information; ..."
    ),
    url=_NIST_URL,
)

# -- AIUC-1 (Q4 2026) -----------------------------------------------------------------------

_AIUC = "AIUC-1"
_AIUC_VER = "Q4 2026"

_AIUC_A005 = FrameworkEntry(
    framework=_AIUC,
    version=_AIUC_VER,
    id="A005",
    title="Prevent cross-customer data exposure",
    url="https://standard.aiuc-1.com/data-and-privacy/prevent-cross-customer-data-exposure",
)
_AIUC_A008 = FrameworkEntry(
    framework=_AIUC,
    version=_AIUC_VER,
    id="A008",
    title="Prevent leakage of credentials and secrets",
    url="https://standard.aiuc-1.com/data-and-privacy/prevent-secrets-leakage",
)
_AIUC_A009 = FrameworkEntry(
    framework=_AIUC,
    version=_AIUC_VER,
    id="A009",
    title="Third-party testing for data & privacy risk",
    url="https://standard.aiuc-1.com/data-and-privacy/3rd-party-testing-for-data-and-privacy-risk",
)
_AIUC_B001 = FrameworkEntry(
    framework=_AIUC,
    version=_AIUC_VER,
    id="B001",
    title="Third-party testing for security risk",
    url="https://standard.aiuc-1.com/security/test-adversarial-robustness",
)
_AIUC_B006 = FrameworkEntry(
    framework=_AIUC,
    version=_AIUC_VER,
    id="B006",
    title="Prevent unauthorized AI agent actions",
    url="https://standard.aiuc-1.com/security/enforce-contextual-access-controls",
)

ALL_FRAMEWORK_ENTRIES: tuple[FrameworkEntry, ...] = (
    _LLM01,
    _LLM02,
    _LLM03,
    _LLM08,
    _ASI01,
    _ASI02,
    _ASI03,
    _ATLAS_DIRECT_PI,
    _ATLAS_INDIRECT_PI,
    _ATLAS_TOOL_INVOCATION,
    _ATLAS_DATA_AI_SERVICES,
    _ATLAS_SYSTEM_INSTRUCTIONS,
    _ATLAS_EXFIL_UI,
    _NIST_DATA_PRIVACY,
    _NIST_INFO_SECURITY,
    _NIST_MS_2_7_001,
    _NIST_MS_2_7_007,
    _NIST_MS_2_10_001,
    _AIUC_A005,
    _AIUC_A008,
    _AIUC_A009,
    _AIUC_B001,
    _AIUC_B006,
)

FRAMEWORK_MAPPINGS: dict[ObjectiveKind, tuple[FrameworkEntry, ...]] = {
    "instruction_secret": (
        _LLM01,
        _LLM02,
        _LLM08,
        _ATLAS_DIRECT_PI,
        _ATLAS_SYSTEM_INSTRUCTIONS,
        _ATLAS_EXFIL_UI,
        _NIST_INFO_SECURITY,
        _NIST_MS_2_7_007,
        _AIUC_A008,
        _AIUC_B001,
    ),
    "other_user_record": (
        _LLM02,
        _ASI03,
        _ATLAS_DATA_AI_SERVICES,
        _ATLAS_EXFIL_UI,
        _NIST_DATA_PRIVACY,
        _NIST_INFO_SECURITY,
        _NIST_MS_2_10_001,
        _AIUC_A005,
        _AIUC_A009,
    ),
    "tool_rule": (
        _LLM01,
        _LLM03,
        _ASI02,
        _ASI03,
        _ATLAS_DIRECT_PI,
        _ATLAS_TOOL_INVOCATION,
        _NIST_INFO_SECURITY,
        _NIST_MS_2_7_001,
        _NIST_MS_2_7_007,
        _AIUC_B001,
        _AIUC_B006,
    ),
    "injection_point": (
        _LLM01,
        _LLM03,
        _ASI01,
        _ASI02,
        _ATLAS_INDIRECT_PI,
        _ATLAS_TOOL_INVOCATION,
        _NIST_INFO_SECURITY,
        _NIST_MS_2_7_007,
        _AIUC_B001,
        _AIUC_B006,
    ),
}


@dataclass(frozen=True)
class CoverageRow:
    """One row of the framework coverage table for an objective kind exercised in a scan."""

    kind: ObjectiveKind
    label: str
    entries: tuple[FrameworkEntry, ...]
    attempts: int
    result: CoverageResult


def entries_for(kind: str) -> tuple[FrameworkEntry, ...]:
    """Framework entries mapped to `kind`, or an empty tuple if `kind` is not a known objective kind."""
    if kind in FRAMEWORK_MAPPINGS:
        return FRAMEWORK_MAPPINGS[kind]  # type: ignore[index]
    return ()


def objective_kind_for(finding: Finding, slots: Sequence[SlotStatus]) -> ObjectiveKind | None:
    """Determine which Promptproof objective kind a finding belongs to."""
    if finding.kind == "action":
        return "tool_rule"
    if finding.kind == "injection":
        return "injection_point"
    for slot in slots:
        if slot.slot_id == finding.slot_id and slot.kind in FRAMEWORK_MAPPINGS:
            return slot.kind  # type: ignore[return-value]
    return None


def group_entries(entries: Sequence[FrameworkEntry]) -> list[tuple[str, list[FrameworkEntry]]]:
    """Group entries by `framework (version)`, preserving order."""
    grouped: dict[str, list[FrameworkEntry]] = {}
    for entry in entries:
        key = f"{entry.framework} ({entry.version})"
        grouped.setdefault(key, []).append(entry)
    return list(grouped.items())


def coverage_rows(report: ScanReport) -> list[CoverageRow]:
    """One row per objective kind this scan actually exercised, in canonical order."""
    present = {slot.kind for slot in report.slots if slot.kind in FRAMEWORK_MAPPINGS}
    findings_by_kind: dict[ObjectiveKind, list[Finding]] = {kind: [] for kind in OBJECTIVE_KINDS}
    for finding in report.findings:
        kind = objective_kind_for(finding, report.slots)
        if kind is not None:
            findings_by_kind[kind].append(finding)

    scan_has_problems = (
        report.status == "inconclusive"
        or bool(report.stopped_early)
        or any(not task.passed for task in report.tasks)
        or bool(report.errors)
    )

    rows: list[CoverageRow] = []
    for kind in OBJECTIVE_KINDS:
        if kind not in present:
            continue
        kind_slots = [slot for slot in report.slots if slot.kind == kind]
        attempts = sum(slot.judged_attempts for slot in kind_slots)
        result: CoverageResult
        if findings_by_kind[kind]:
            result = "proven finding"
        elif (
            any(slot.state != "reachable" for slot in kind_slots)
            or scan_has_problems
            or (any(slot.judged_attempts == 0 for slot in kind_slots) and report.status != "no_verified_violations")
        ):
            result = "inconclusive"
        else:
            result = "no verified violation"
        rows.append(
            CoverageRow(
                kind=kind,
                label=OBJECTIVE_LABELS[kind],
                entries=FRAMEWORK_MAPPINGS[kind],
                attempts=attempts,
                result=result,
            )
        )
    return rows


def not_covered_sentence(exercised: Sequence[ObjectiveKind]) -> str:
    """One plain sentence naming what this scan did not cover, preventing over-claiming."""
    missing = [OBJECTIVE_LABELS[kind].lower() for kind in OBJECTIVE_KINDS if kind not in exercised]
    broader = (
        "supply chain, training or data poisoning, denial of service or unbounded consumption, "
        "misinformation or hallucinations, bias and fairness, harmful content generation, "
        "multi-agent or memory poisoning, output handling, or organizational governance"
    )
    if missing:
        missing_text = ", ".join(missing)
        return (
            f"This scan did not cover {missing_text}, nor other categories of these frameworks "
            f"such as {broader}."
        )
    return (
        f"This scan did not cover other categories of these frameworks, including {broader}."
    )
