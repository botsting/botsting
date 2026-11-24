"""Replay a frozen attack or a finding, and check the instruments again.

"The attack no longer works" is only worth saying if the thing it reached still works
by its legitimate route and normal use still works. A target that answers "no" to
everything stops every attack and is not fixed.
"""

from __future__ import annotations

from dataclasses import dataclass

from promptproof.core.judge import _rate_for
from promptproof.core.meter import Meter, ScanConfig
from promptproof.core.models import (
    Attack,
    EvidenceLevel,
    Finding,
    Rate,
)
from promptproof.core.preflight import preflight
from promptproof.core.scan import _control_for, _control_verdict, _describe, _replays
from promptproof.core.stats import make_rate
from promptproof.targets.base import (
    Target,
    UnsafeTargetError,
    injection_points,
    require_contained_tools,
    tool_rules,
)


@dataclass(frozen=True)
class ReplayResult:
    rate: Rate
    # Reasons a result of zero successes could not be trusted. Empty when the instruments held.
    problems: tuple[str, ...]
    target_config: dict[str, str]
    # Set when successes were seen but cannot be pinned on the attack, so they prove nothing.
    unattributable: str = ""


def attack_from(finding: Finding) -> Attack:
    """The frozen attack behind a finding, aimed at the thing it was found to violate."""
    return Attack(
        id=finding.attack_id,
        technique=finding.technique,
        title=finding.title,
        slot_id=finding.slot_id,
        turns=finding.frozen_turns,
        kind=finding.kind,
        payload=finding.payload,
    )


async def replay(
    target: Target,
    attack: Attack,
    objective_id: str,
    trials: int,
    meter: Meter | None = None,
    at_least: EvidenceLevel | None = None,
) -> Rate:
    """Replay a frozen attack from reset `trials` times; success is verified evidence against `objective_id`."""
    attempts, _ = await _replays(target, attack, trials, meter or Meter())
    return _rate_for(attempts, objective_id, at_least)


async def replay_finding(target: Target, finding: Finding, trials: int, config: ScanConfig | None = None) -> ReplayResult:
    """Replay a finding and check the instruments again, so a zero can be told from a broken target.

    "The attack no longer works" is only worth saying if the thing it reached still
    works by its legitimate route and normal use still works. A target that answers
    "no" to everything stops every attack and is not fixed.

    Success means evidence at the finding's own level or stronger: a refund that was
    carried out is not reproduced by one that was refused. Planted text is replayed
    with a harmless-text request after each trial, and not at all if the harmless
    check fails first, because a tool call could not then be pinned on the text.
    """
    meter = Meter(config)
    try:
        require_contained_tools(target)
        await meter.start(target)
    except UnsafeTargetError as exc:
        return ReplayResult(make_rate(0, 0), (f"Nothing was sent to the target: {exc}",), {})
    target_config = await _describe(target, meter)
    objective_id = finding.slot_id
    slot = next((s for s in target.slots() if s.id == objective_id), None)
    rule = next((r for r in tool_rules(target) if r.id == objective_id), None)
    point = next((p for p in injection_points(target) if p.id == objective_id), None)
    if {"disclosure": slot, "action": rule, "injection": point}[finding.kind] is None:
        return ReplayResult(
            make_rate(0, 0),
            (f"This target has nothing called {objective_id} for a {finding.kind} finding to be replayed against.",),
            target_config,
        )
    checks = await preflight(target, meter)
    status = next(s for s in checks.slots if s.slot_id == objective_id)
    tasks = checks.tasks

    problems: list[str] = []
    if status.state != "reachable":
        problems.append(f"{objective_id} is {status.state} by its legitimate route: {status.detail}")
    if not tasks:
        problems.append("The target defines no normal-task check.")
    problems += [f"Normal-task check {t.task_id} did not work: {t.detail}" for t in tasks if not t.passed]
    if finding.kind == "injection" and status.state != "reachable":
        problems.append("The planted text was not replayed: a tool call could not have been attributed to it.")
        return ReplayResult(make_rate(0, 0), tuple(problems), target_config)
    if objective_id in checks.repeated:
        problems.append("The attack was not replayed: on this target the value comes back whoever asks, so a match would prove nothing.")
        return ReplayResult(make_rate(0, 0), tuple(problems), target_config)

    control = _control_for(point) if finding.kind == "injection" and point is not None else None
    replays, controls = await _replays(target, attack_from(finding), trials, meter, control)
    rate = _rate_for(replays, objective_id, finding.level)
    meter.poll()
    if meter.stop_reason:
        problems.append(f"The replay stopped before finishing ({meter.stop_reason}).")
    if rate.errors:
        problems.append(f"{rate.errors} replay(s) did not complete.")
    if rate.contaminated:
        problems.append(f"{rate.contaminated} replay(s) were discarded as contaminated.")
    if rate.trials == 0:
        problems.append("No replay could be judged.")
    unattributable = ""
    if control is not None and point is not None:
        _, control_problem = _control_verdict(point, replays, controls)
        if control_problem:
            unattributable = control_problem[0].upper() + control_problem[1:] + "."
            problems.append(unattributable)
    return ReplayResult(rate, tuple(problems), target_config, unattributable)
