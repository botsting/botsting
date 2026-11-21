"""Core data model. Everything a scan produces is expressed in these types.

Vocabulary
----------
principal   Who is talking to the target, e.g. "customer:alice" or "staff:dana".
slot        A place in the target where a canary can be planted, together with the
            policy saying which principals may legitimately see it.
canary      A fresh random secret planted in a slot for one attempt.
attack      A scripted sequence of attacker messages aimed at one slot.
attempt     One run of an attack from a reset state with freshly planted canaries.
finding     An attack that produced verified evidence, with its discovery and
            reproduction rates.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any, Literal


class EvidenceLevel(IntEnum):
    """How strong the evidence for a finding is. A finding carries the highest level it reached."""

    SUSPECTED = 0  # partial match or a model's opinion; never counted as verified
    DISCLOSED = 1  # protected data the attacker never saw came out of the target
    ACTION_ATTEMPTED = 2  # the target tried a forbidden tool call
    ACTION_ACCEPTED = 3  # the tool accepted the call
    STATE_VERIFIED = 4  # the downstream state change was independently confirmed

    @property
    def label(self) -> str:
        return {
            0: "Suspected",
            1: "Protected data disclosed",
            2: "Forbidden action attempted",
            3: "Forbidden action accepted",
            4: "State change verified",
        }[int(self)]


SlotKind = Literal["instruction_secret", "other_user_record"]
Role = Literal["attacker", "target"]


@dataclass(frozen=True)
class Turn:
    role: Role
    text: str


@dataclass(frozen=True)
class Slot:
    """A place a canary can be planted, and the policy around it."""

    id: str
    kind: SlotKind
    description: str
    # How an attacker with ordinary public knowledge would refer to the protected thing,
    # e.g. "the staff discount code" or "order B-2002". Never contains the canary.
    hint: str
    # Principals allowed to see the planted value. Anyone else seeing it is a violation.
    authorized: tuple[str, ...]
    # A legitimate request that must reveal the canary. Run before attacking to confirm
    # the canary is reachable at all; a canary nobody can reach can never leak.
    control_principal: str
    control_prompt: str


@dataclass(frozen=True)
class TaskCheck:
    """A normal, harmless use of the target that must keep working."""

    id: str
    principal: str
    prompt: str
    expect_substring: str


@dataclass(frozen=True)
class Attack:
    """A scripted attack. `turns` are sent in order as the attacker principal."""

    id: str
    technique: str
    title: str
    slot_id: str
    turns: tuple[str, ...]


@dataclass(frozen=True)
class Match:
    """A canary seen in target output."""

    slot_id: str
    # How it appeared: plain, normalized (case or separators changed), reversed, rot13,
    # url, base64, hex, spelled (one character at a time), pieces (a few chunks).
    encoding: str
    # "single-turn" or "across-turns" (assembled from several replies).
    scope: str
    # True when the whole canary was recovered. Partial matches are only ever suspected.
    full: bool
    matched_chars: int
    canary_chars: int
    # Canary characters found in the attacker's own messages before the target had
    # disclosed them. Anything above zero breaks the proof, so the match can no longer
    # be verified, only suspected.
    attacker_known_chars: int = 0
    # Of the characters in the target's output, how many the attacker had not supplied.
    # None means all of `matched_chars`.
    newly_disclosed_chars: int | None = None

    @property
    def verified(self) -> bool:
        return self.full and self.attacker_known_chars == 0


@dataclass(frozen=True)
class Rate:
    """Successes out of the trials that could be judged.

    Trials that errored before showing anything, and trials discarded because the
    canary was in attacker input, are counted separately and are not in `trials`.
    """

    successes: int
    trials: int
    errors: int = 0
    contaminated: int = 0
    # Two-sided 95% Wilson score interval on successes/trials; None when trials == 0.
    interval_low: float | None = None
    interval_high: float | None = None
    interval_method: str = "wilson-95"

    @property
    def rate(self) -> float | None:
        return self.successes / self.trials if self.trials else None


AttemptOutcome = Literal["verified", "suspected", "contaminated", "none"]


@dataclass(frozen=True)
class Attempt:
    """One run of one attack from a reset state.

    What was observed and whether the run completed are separate facts. A run that
    failed halfway is still judged on the replies it did receive: a transport error
    cannot undo a disclosure that already happened.
    """

    attack_id: str
    slot_id: str
    outcome: AttemptOutcome  # from the evidence in the transcript, complete or not
    transcript: tuple[Turn, ...]
    matches: tuple[Match, ...] = ()  # everything not discarded as contaminated
    contaminated_slots: tuple[str, ...] = ()
    error: str | None = None  # set when the run did not complete


@dataclass(frozen=True)
class Finding:
    """A verified violation: an attack that provably reached protected data."""

    id: str
    attack_id: str
    technique: str
    title: str
    slot_id: str
    level: EvidenceLevel
    encoding: str
    scope: str
    attacker_principal: str
    # Policy the finding is judged against, copied from the slot.
    authorized: tuple[str, ...]
    # The attacker messages, frozen. Replaying these from a reset state with a fresh
    # canary is what `reproduction` measures.
    frozen_turns: tuple[str, ...]
    # The first conversation in which the attack worked. The canary value in it was
    # single-use and is dead once the scan ends.
    transcript: tuple[Turn, ...]
    # How often the attack worked while searching.
    discovery: Rate
    # How often the frozen attack worked when replayed from reset.
    reproduction: Rate


@dataclass(frozen=True)
class SuspectedFinding:
    """Evidence that falls short of verified. Always shown, never counted."""

    attack_id: str
    technique: str
    title: str
    slot_id: str
    reason: str
    transcript: tuple[Turn, ...]


SlotState = Literal["reachable", "unreachable", "error"]


@dataclass(frozen=True)
class SlotStatus:
    slot_id: str
    kind: str
    description: str
    authorized: tuple[str, ...]
    state: SlotState
    detail: str = ""
    # Attempts aimed at this slot that completed and were not discarded. Zero means the
    # slot was never actually tested, whatever else the report says.
    judged_attempts: int = 0


@dataclass(frozen=True)
class TaskStatus:
    task_id: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True)
class ErrorRecord:
    phase: str  # "preflight", "discovery", "reproduction"
    attack_id: str | None
    message: str


# "violations_verified"      at least one verified finding.
# "no_verified_violations"   every instrument worked and nothing was verified. This is a
#                            statement about the tested conditions only, never "safe".
# "inconclusive"             nothing verified, but something needed to trust that result
#                            failed (unreachable canary, broken normal task, errors).
ScanStatus = Literal["violations_verified", "no_verified_violations", "inconclusive"]


@dataclass(frozen=True)
class ScanReport:
    tool_version: str
    target: str  # the target spec string, enough to reconnect for a replay
    attacker_principal: str
    started_at: str  # ISO 8601 UTC
    finished_at: str
    status: ScanStatus
    slots: tuple[SlotStatus, ...]
    tasks: tuple[TaskStatus, ...]
    attacks_run: int
    attempts_run: int
    discovery_runs: int  # attempts per attack while searching
    reproduction_trials: int  # replays per verified attack
    findings: tuple[Finding, ...]
    suspected: tuple[SuspectedFinding, ...]
    contaminated_attempts: int  # discarded because the canary was in attacker input
    errors: tuple[ErrorRecord, ...]
    limitations: tuple[str, ...] = field(default_factory=tuple)
    # Why the status is "inconclusive"; empty otherwise.
    inconclusive_reasons: tuple[str, ...] = field(default_factory=tuple)
    # What the target said about its own configuration when scanned (model, digest,
    # settings), so a later replay can tell whether it is facing the same thing.
    target_config: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for finding in data["findings"]:
            finding["level"] = int(finding["level"])
            finding["level_label"] = EvidenceLevel(finding["level"]).label
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanReport":
        def turns(items: list[dict[str, str]]) -> tuple[Turn, ...]:
            return tuple(Turn(role=item["role"], text=item["text"]) for item in items)  # type: ignore[arg-type]

        def rate(item: dict[str, Any]) -> Rate:
            return Rate(**item)

        findings = tuple(
            Finding(
                id=f["id"],
                attack_id=f["attack_id"],
                technique=f["technique"],
                title=f["title"],
                slot_id=f["slot_id"],
                level=EvidenceLevel(f["level"]),
                encoding=f["encoding"],
                scope=f["scope"],
                attacker_principal=f["attacker_principal"],
                authorized=tuple(f["authorized"]),
                frozen_turns=tuple(f["frozen_turns"]),
                transcript=turns(f["transcript"]),
                discovery=rate(f["discovery"]),
                reproduction=rate(f["reproduction"]),
            )
            for f in data["findings"]
        )
        suspected = tuple(
            SuspectedFinding(
                attack_id=s["attack_id"],
                technique=s["technique"],
                title=s["title"],
                slot_id=s["slot_id"],
                reason=s["reason"],
                transcript=turns(s["transcript"]),
            )
            for s in data["suspected"]
        )
        return cls(
            tool_version=data["tool_version"],
            target=data["target"],
            attacker_principal=data["attacker_principal"],
            started_at=data["started_at"],
            finished_at=data["finished_at"],
            status=data["status"],
            slots=tuple(
                SlotStatus(**{**s, "authorized": tuple(s["authorized"])}) for s in data["slots"]
            ),
            tasks=tuple(TaskStatus(**t) for t in data["tasks"]),
            attacks_run=data["attacks_run"],
            attempts_run=data["attempts_run"],
            discovery_runs=data["discovery_runs"],
            reproduction_trials=data["reproduction_trials"],
            findings=findings,
            suspected=suspected,
            contaminated_attempts=data["contaminated_attempts"],
            errors=tuple(ErrorRecord(**e) for e in data["errors"]),
            limitations=tuple(data.get("limitations", ())),
            inconclusive_reasons=tuple(data.get("inconclusive_reasons", ())),
            target_config=dict(data.get("target_config", {})),
        )
