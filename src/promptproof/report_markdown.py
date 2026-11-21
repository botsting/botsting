"""Render a ScanReport as the human-readable markdown report.

Wording rules (PLAN.md, "What a report may say"):

- A report with no verified findings states exactly
  "No verified violations observed under these tested conditions." — never
  that the target is safe, secure, clean or certified, and never that it
  passed. Those words must not appear anywhere in Promptproof-authored text.
- Lead with the result, then what was tested, then slots, task checks,
  findings, suspected items, contaminated attempts, errors, limitations.
- Empty sections say so in one line, so "none" is distinguishable from
  "not checked".
- Transcript text comes from attackers and from a model and is rendered
  verbatim in fenced blocks whose fence is longer than any backtick run
  inside the text.
"""

from __future__ import annotations

import re
from decimal import ROUND_HALF_UP, Decimal

from promptproof.core.models import Finding, Rate, ScanReport, Turn

HEADLINE_NO_VERIFIED_VIOLATIONS = "No verified violations observed under these tested conditions."

_EMPTY_SECTION = "None recorded."


def render_markdown(report: ScanReport, report_path: str | None = None) -> str:
    """Render the report. `report_path` is the JSON file's path, used in replay commands."""
    lines: list[str] = []
    lines.extend(_headline(report))
    lines.append("")
    lines.append("## What was tested")
    lines.extend(_what_was_tested(report))
    lines.append("")
    lines.append("## Canary slots")
    lines.extend(_slots(report))
    lines.append("")
    lines.append("## Normal-task checks")
    lines.extend(_tasks(report))
    lines.append("")
    lines.append("## Verified findings")
    lines.extend(_findings(report, report_path))
    lines.append("")
    lines.append("## Suspected findings")
    lines.extend(_suspected(report))
    lines.append("")
    lines.append("## Contaminated attempts")
    lines.extend(_contaminated(report))
    lines.append("")
    lines.append("## Errors")
    lines.extend(_errors(report))
    lines.append("")
    lines.append("## Limitations")
    lines.extend(_limitations(report))
    text = "\n".join(lines)
    return text if text.endswith("\n") else text + "\n"


def _headline(report: ScanReport) -> list[str]:
    if report.status == "violations_verified":
        count = len(report.findings)
        plural = "" if count == 1 else "s"
        return [f"{count} verified violation{plural} found."]
    if report.status == "no_verified_violations":
        return [HEADLINE_NO_VERIFIED_VIOLATIONS]
    lines = ["The scan could not reach a conclusion.", ""]
    lines.extend(f"- {reason}" for reason in _inconclusive_reasons(report))
    return lines


def _inconclusive_reasons(report: ScanReport) -> list[str]:
    reasons: list[str] = []
    for slot in report.slots:
        detail = f" ({_code(slot.detail)})" if slot.detail else ""
        if slot.state == "unreachable":
            reasons.append(
                f"Canary slot '{slot.slot_id}' was unreachable{detail}, so nothing "
                "was proven about it."
            )
        elif slot.state == "error":
            reasons.append(f"Canary slot '{slot.slot_id}' could not be checked{detail}.")
    for task in report.tasks:
        if not task.passed:
            detail = f" ({_code(task.detail)})" if task.detail else ""
            reasons.append(
                f"Normal-task check '{task.task_id}' did not work{detail}, so the "
                "target may be broken rather than hardened."
            )
    if report.errors:
        count = len(report.errors)
        plural = "" if count == 1 else "s"
        verb = "was" if count == 1 else "were"
        reasons.append(
            f"{count} error{plural} {verb} recorded during the scan; see Errors below."
        )
    if not reasons:
        reasons.append("The scan was marked inconclusive without a recorded cause; see the sections below.")
    return reasons


def _what_was_tested(report: ScanReport) -> list[str]:
    return [
        f"- Tool version: {report.tool_version}",
        f"- Target: {report.target}",
        f"- Attacker principal: {report.attacker_principal}",
        f"- Scan window: {report.started_at} to {report.finished_at} (UTC)",
        f"- Attacks run: {report.attacks_run}",
        f"- Attempts run: {report.attempts_run}",
        f"- Discovery runs per attack: {report.discovery_runs}",
        f"- Replays per verified finding: {report.reproduction_trials}",
    ]


def _slots(report: ScanReport) -> list[str]:
    if not report.slots:
        return [_EMPTY_SECTION]
    lines: list[str] = []
    for slot in report.slots:
        detail = f" — {_code(slot.detail)}" if slot.detail else ""
        allowed = ", ".join(slot.authorized) if slot.authorized else "(none listed)"
        lines.append(f"- **{slot.slot_id}** ({slot.kind}): {slot.description}")
        lines.append(f"  - State: {slot.state}{detail}")
        lines.append(f"  - Principals authorized to see it: {allowed}")
    return lines


def _tasks(report: ScanReport) -> list[str]:
    if not report.tasks:
        return [_EMPTY_SECTION]
    lines: list[str] = []
    for task in report.tasks:
        outcome = "worked as expected" if task.passed else "did not work"
        detail = f" — {_code(task.detail)}" if task.detail else ""
        lines.append(f"- **{task.task_id}**: {outcome}{detail}")
    return lines


def _findings(report: ScanReport, report_path: str | None) -> list[str]:
    if not report.findings:
        return [_EMPTY_SECTION]
    lines: list[str] = []
    for finding in report.findings:
        lines.extend(_finding(finding, report_path))
    return lines[:-1]  # drop the trailing blank before the next section


def _finding(finding: Finding, report_path: str | None) -> list[str]:
    target_file = report_path if report_path else "<report.json>"
    allowed = ", ".join(finding.authorized) if finding.authorized else "(none listed)"
    lines = [
        f"### {finding.id}: {finding.title}",
        "",
        f"- Evidence level: {finding.level.label}",
        f"- Technique: {finding.technique}",
        f"- Slot: {finding.slot_id}",
        f"- Policy: principals authorized to see this slot: {allowed}",
        f"- How the canary appeared: encoding `{finding.encoding}`, scope `{finding.scope}`",
        f"- Discovery: {_rate_text('found in', 'search attempts', finding.discovery)}",
        f"- Reproduction: {_rate_text('reproduced in', 'replays from reset', finding.reproduction)}",
        f"- Replay: {_code(f'promptproof replay {target_file} --finding {finding.id}')}",
        "",
        "#### Transcript",
        "",
    ]
    lines.extend(_transcript_lines(finding.transcript))
    return lines


def _rate_text(verb: str, noun_plural: str, rate: Rate) -> str:
    if rate.trials == 0:
        return f"no {noun_plural} were run"
    plural = "" if rate.errors == 1 else "s"
    errors = (
        f", {rate.errors} errored run{plural} not counted"
        if rate.errors
        else ""
    )
    if rate.interval_low is None or rate.interval_high is None:
        interval = " (no interval recorded)"
    else:
        method = (
            "95% Wilson interval"
            if rate.interval_method == "wilson-95"
            else f"interval method {rate.interval_method}"
        )
        low = _percent(rate.interval_low)
        high = _percent(rate.interval_high)
        interval = f" ({method} {low}% to {high}%)"
    return f"{verb} {rate.successes} of {rate.trials} {noun_plural}{errors}{interval}"


def _percent(value: float) -> int:
    """Round a fraction to a whole percentage, half up (0.565 -> 57)."""
    scaled = Decimal(str(value)) * 100
    return int(scaled.quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def _suspected(report: ScanReport) -> list[str]:
    lines = [
        "Suspected items are **not verified** and are **not counted** as violations; "
        "they are shown for triage only.",
        "",
    ]
    if not report.suspected:
        lines.append(_EMPTY_SECTION)
        return lines
    for index, item in enumerate(report.suspected, start=1):
        lines.extend(
            [
                f"### Suspected {index}: {item.title}",
                "",
                f"- Attack: {item.attack_id} (technique: {item.technique})",
                f"- Slot: {item.slot_id}",
                f"- Why it is only suspected: {_code(item.reason)}",
                "",
                "#### Transcript",
                "",
            ]
        )
        lines.extend(_transcript_lines(item.transcript))
    return lines[:-1]


def _contaminated(report: ScanReport) -> list[str]:
    if report.contaminated_attempts == 0:
        return [_EMPTY_SECTION]
    count = report.contaminated_attempts
    plural = "" if count == 1 else "s"
    return [
        f"Discarded {count} attempt{plural} because the canary appeared in "
        "attacker-visible input; these runs prove nothing and are excluded from "
        "every rate in this report."
    ]


def _errors(report: ScanReport) -> list[str]:
    if not report.errors:
        return [_EMPTY_SECTION]
    lines: list[str] = []
    for error in report.errors:
        where = f"attack {error.attack_id}" if error.attack_id else "scan-wide"
        lines.append(f"- [{error.phase}] {where}: {_code(error.message)}")
    return lines


def _limitations(report: ScanReport) -> list[str]:
    if not report.limitations:
        return [_EMPTY_SECTION]
    return [f"- {item}" for item in report.limitations]


def _transcript_lines(transcript: tuple[Turn, ...]) -> list[str]:
    if not transcript:
        return ["(empty transcript)", ""]
    lines: list[str] = []
    for turn in transcript:
        speaker = "Attacker" if turn.role == "attacker" else "Target"
        fence = _fence(turn.text)
        lines.append(f"**{speaker}:**")
        lines.append("")
        lines.append(fence)
        lines.append(turn.text)
        lines.append(fence)
        lines.append("")
    return lines  # ends with a blank line; callers trim the one after their last item


def _code(text: str) -> str:
    """`text` as an inline code span that nothing inside it can close or escape.

    Details and error messages can quote a model's reply or a server's response, so
    they are untrusted and must not be able to add links, images, HTML or headings.
    """
    flat = " ".join(text.split())
    longest_run = max((len(run) for run in re.findall(r"`+", flat)), default=0)
    ticks = "`" * (longest_run + 1)
    return f"{ticks} {flat} {ticks}" if flat else "(empty)"


def _fence(text: str) -> str:
    """A fence line guaranteed to be longer than any backtick run in `text`."""
    longest_run = max((len(run) for run in re.findall(r"`+", text)), default=0)
    return "`" * max(3, longest_run + 1)
