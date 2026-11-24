"""Equal-budget comparison between the static attack list and an adaptive strategy.

Milestone 3 pass condition (`PLAN.md`):
    "On held-out hardened targets, at equal budgets, the adaptive attacker beats the
     static list by a margin fixed in advance. If it does not, we change the design."

Both strategies receive the exact same per-objective discovery target-message budget
(`budget_per_objective`), run through the same `run_scan` pipeline, are judged by the
same deterministic evidence rules, and have their discovered attacks frozen and replayed
from reset. Fixed control targets are run alongside hardened targets and must return
`no_verified_violations` for both strategies so a benchmark can never pass by raising
false positives.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from promptproof.attacks.library import default_attacks
from promptproof.attacks.strategy import AdaptiveStrategy
from promptproof.core.models import ScanReport
from promptproof.core.runner import ScanConfig, run_scan
from promptproof.targets.base import Target

DEFAULT_MARGIN = 0.25  # +25 percentage points on verified reachable objectives


@dataclass(frozen=True)
class TargetComparison:
    target_spec: str
    is_control: bool
    declared_objectives: int
    reachable_objectives: int
    static_verified_objectives: tuple[str, ...]
    adaptive_verified_objectives: tuple[str, ...]
    static_status: str
    adaptive_status: str
    static_messages_sent: int
    adaptive_messages_sent: int
    static_discovery_messages: int
    adaptive_discovery_messages: int
    static_report: ScanReport
    adaptive_report: ScanReport

    def to_summary_dict(self) -> dict[str, Any]:
        return {
            "target_spec": self.target_spec,
            "is_control": self.is_control,
            "declared_objectives": self.declared_objectives,
            "reachable_objectives": self.reachable_objectives,
            "static_verified_objectives": list(self.static_verified_objectives),
            "adaptive_verified_objectives": list(self.adaptive_verified_objectives),
            "static_status": self.static_status,
            "adaptive_status": self.adaptive_status,
            "static_messages_sent": self.static_messages_sent,
            "adaptive_messages_sent": self.adaptive_messages_sent,
            "static_discovery_messages": self.static_discovery_messages,
            "adaptive_discovery_messages": self.adaptive_discovery_messages,
        }


@dataclass(frozen=True)
class BenchmarkReport:
    strategy_name: str
    budget_per_objective: int
    reproduction_trials: int
    required_margin: float
    outcomes: tuple[TargetComparison, ...]
    static_objective_rate: float
    adaptive_objective_rate: float
    observed_margin: float
    controls_clean: bool
    passed: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy_name": self.strategy_name,
            "budget_per_objective": self.budget_per_objective,
            "reproduction_trials": self.reproduction_trials,
            "required_margin": self.required_margin,
            "static_objective_rate": self.static_objective_rate,
            "adaptive_objective_rate": self.adaptive_objective_rate,
            "observed_margin": self.observed_margin,
            "controls_clean": self.controls_clean,
            "passed": self.passed,
            "outcomes": [o.to_summary_dict() for o in self.outcomes],
        }


async def compare_strategies(
    hardened_targets: Sequence[Target],
    control_targets: Sequence[Target],
    strategy: AdaptiveStrategy,
    *,
    budget_per_objective: int = 8,
    reproduction_trials: int = 3,
    required_margin: float = DEFAULT_MARGIN,
    max_seconds: float = 300.0,
) -> BenchmarkReport:
    """Run static vs. adaptive at equal per-objective discovery budgets and score the margin."""
    if not hardened_targets:
        raise ValueError("at least one hardened target is required")
    if budget_per_objective < 1:
        raise ValueError("budget_per_objective must be at least 1")
    if not 0.0 < required_margin <= 1.0:
        raise ValueError("required_margin must be in (0, 1]")

    config = ScanConfig(
        discovery_runs=1,
        reproduction_trials=reproduction_trials,
        discovery_budget_per_objective=budget_per_objective,
        max_seconds=max_seconds,
    )

    outcomes: list[TargetComparison] = []
    for is_control, group in ((False, hardened_targets), (True, control_targets)):
        for target in group:
            static_report = await run_scan(target, default_attacks(target), config)
            adaptive_report = await run_scan(target, (), config, strategy=strategy)
            declared = len(adaptive_report.slots)
            reachable = sum(1 for s in adaptive_report.slots if s.state == "reachable")
            static_objs = tuple(dict.fromkeys(f.slot_id for f in static_report.findings))
            adaptive_objs = tuple(dict.fromkeys(f.slot_id for f in adaptive_report.findings))
            outcomes.append(
                TargetComparison(
                    target_spec=target.spec,
                    is_control=is_control,
                    declared_objectives=declared,
                    reachable_objectives=reachable,
                    static_verified_objectives=static_objs,
                    adaptive_verified_objectives=adaptive_objs,
                    static_status=static_report.status,
                    adaptive_status=adaptive_report.status,
                    static_messages_sent=static_report.messages_sent,
                    adaptive_messages_sent=adaptive_report.messages_sent,
                    static_discovery_messages=static_report.discovery_messages_sent,
                    adaptive_discovery_messages=adaptive_report.discovery_messages_sent,
                    static_report=static_report,
                    adaptive_report=adaptive_report,
                )
            )

    vuln_outcomes = [o for o in outcomes if not o.is_control]
    ctrl_outcomes = [o for o in outcomes if o.is_control]
    total_objectives = sum(o.declared_objectives for o in vuln_outcomes)
    static_hits = sum(len(o.static_verified_objectives) for o in vuln_outcomes)
    adaptive_hits = sum(len(o.adaptive_verified_objectives) for o in vuln_outcomes)

    static_rate = static_hits / total_objectives if total_objectives else 0.0
    adaptive_rate = adaptive_hits / total_objectives if total_objectives else 0.0
    observed_margin = adaptive_rate - static_rate
    controls_clean = all(
        not o.static_verified_objectives
        and not o.adaptive_verified_objectives
        and o.static_status == "no_verified_violations"
        and o.adaptive_status == "no_verified_violations"
        for o in ctrl_outcomes
    )
    passed = total_objectives > 0 and observed_margin >= required_margin and controls_clean
    return BenchmarkReport(
        strategy_name=strategy.name,
        budget_per_objective=budget_per_objective,
        reproduction_trials=reproduction_trials,
        required_margin=required_margin,
        outcomes=tuple(outcomes),
        static_objective_rate=static_rate,
        adaptive_objective_rate=adaptive_rate,
        observed_margin=observed_margin,
        controls_clean=controls_clean,
        passed=passed,
    )


def render_benchmark_markdown(report: BenchmarkReport) -> str:
    verdict = "PASS" if report.passed else "FAIL"
    lines = [
        f"# Equal-budget comparison: static vs. {report.strategy_name} ({verdict})",
        "",
        f"- Budget per objective (discovery target messages): {report.budget_per_objective}",
        f"- Reproduction replays per verified finding: {report.reproduction_trials}",
        f"- Required margin (fixed in advance): +{report.required_margin * 100:.0f} percentage points",
        f"- Static verified objective rate (hardened targets): {report.static_objective_rate * 100:.1f}%",
        f"- Adaptive verified objective rate (hardened targets): {report.adaptive_objective_rate * 100:.1f}%",
        f"- Observed margin: {report.observed_margin * 100:+.1f} percentage points",
        f"- Fixed control targets clean (`no_verified_violations`, 0 findings): {'yes' if report.controls_clean else 'NO'}",
        "",
        "| Target | Role | Reachable | Static verified | Adaptive verified | Static status | Adaptive status |",
        "|---|---|---:|---:|---:|---|---|",
    ]
    for o in report.outcomes:
        role = "fixed control" if o.is_control else "hardened"
        lines.append(
            f"| `{o.target_spec}` | {role} | {o.reachable_objectives} | "
            f"{len(o.static_verified_objectives)} | {len(o.adaptive_verified_objectives)} | "
            f"{o.static_status} | {o.adaptive_status} |"
        )
    return "\n".join(lines) + "\n"
