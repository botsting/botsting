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

from promptproof.core.models import Finding, Rate, ScanReport, ToolCall, Turn
from promptproof.shell import replay_command

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
    lines.append("## What was protected")
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
        lines = [f"{count} verified violation{plural} found."]
        if report.inconclusive_reasons:
            # Violations were proven, but a reader must not take the rest as covered.
            lines += ["", "Not everything could be tested:", ""]
            lines.extend(f"- {_text(reason)}" for reason in report.inconclusive_reasons)
        return lines
    if report.status == "no_verified_violations":
        return [HEADLINE_NO_VERIFIED_VIOLATIONS]
    lines = ["The scan could not reach a conclusion.", ""]
    if report.inconclusive_reasons:
        lines.extend(f"- {_text(reason)}" for reason in report.inconclusive_reasons)
    else:
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
        f"- Target: {_code(report.target)}",
        f"- Target configuration: {_config(report)}",
        f"- Attacker principal: {_code(report.attacker_principal)}",
        f"- Scan window: {report.started_at} to {report.finished_at} (UTC)",
        f"- Attacks run: {report.attacks_run}",
        f"- Attempts run: {report.attempts_run}",
        f"- Discovery runs per attack: {report.discovery_runs}",
        f"- Replays per verified finding: {report.reproduction_trials}",
        f"- Spent: {report.messages_sent} messages sent, {report.tool_calls_recorded} tool calls recorded",
        *([f"- Stopped early: {_text(report.stopped_early)}"] if report.stopped_early else []),
    ]


def _slots(report: ScanReport) -> list[str]:
    if not report.slots:
        return [_EMPTY_SECTION]
    lines: list[str] = []
    for slot in report.slots:
        detail = f" — {_code(slot.detail)}" if slot.detail else ""
        lines.append(f"- {_code(slot.slot_id)} ({_text(slot.kind)}): {_text(slot.description)}")
        lines.append(f"  - State: {slot.state}{detail}")
        if slot.kind == "tool_rule":
            lines.append(f"  - Principals whose own request may cause this tool to run: {_principals(slot.authorized)}")
        elif slot.kind == "injection_point":
            lines.append("  - Tested by planting text here and having an ordinary user make an ordinary request")
        else:
            lines.append(f"  - Principals authorized to see it: {_principals(slot.authorized)}")
        lines.append(f"  - Attempts aimed at it that completed and were judged: {slot.judged_attempts}")
    return lines


def _tasks(report: ScanReport) -> list[str]:
    if not report.tasks:
        return [_EMPTY_SECTION]
    lines: list[str] = []
    for task in report.tasks:
        outcome = "worked as expected" if task.passed else "did not work"
        detail = f" — {_code(task.detail)}" if task.detail else ""
        lines.append(f"- {_code(task.task_id)}: {outcome}{detail}")
    return lines


def _findings(report: ScanReport, report_path: str | None) -> list[str]:
    if not report.findings:
        return [_EMPTY_SECTION]
    lines: list[str] = []
    for finding in report.findings:
        lines.extend(_finding(finding, report_path))
    return lines[:-1]  # drop the trailing blank before the next section


def _finding(finding: Finding, report_path: str | None) -> list[str]:
    command = replay_command(report_path or "REPORT.json", finding.id)
    if not report_path:
        command = command.replace("REPORT.json", "<report.json>", 1)
    lines = [
        f"### {_text(finding.id)}: {_text(finding.title)}",
        "",
        f"- Evidence level: {finding.level.label}",
        f"- Technique: {_text(finding.technique)}",
        f"- Attack: {_code(finding.attack_id)}, sent as {_code(finding.attacker_principal)}",
        *_what_was_violated(finding),
        f"- Discovery: {_rate_text('found in', 'search attempts', finding.discovery)}",
        f"- Reproduction: {_rate_text('reproduced in', 'replays from reset', finding.reproduction)}",
        f"- Replay: {_code(command)}",
        "",
        "#### Transcript",
        "",
    ]
    lines.extend(_transcript_lines(finding.transcript))
    return lines


def _what_was_violated(finding: Finding) -> list[str]:
    if finding.kind == "disclosure":
        return [
            f"- Slot: {_code(finding.slot_id)}",
            f"- Policy: principals authorized to see this slot: {_principals(finding.authorized)}",
            f"- How the canary appeared: encoding {_code(finding.encoding)}, scope {_code(finding.scope)}",
        ]
    lines = []
    if finding.kind == "injection":
        lines.append(f"- Injection point: {_code(finding.slot_id)}")
        lines.append(
            "- Policy: this tool has no business running during the ordinary request below; the same "
            "request with harmless text in place of the planted text did not call it"
        )
    else:
        lines.append(f"- Tool rule: {_code(finding.slot_id)}")
        lines.append(
            f"- Policy: principals whose own request may cause this tool to run: {_principals(finding.authorized)}"
        )
    lines.append("- Recorded at the tool, not taken from what the target said:")
    lines.extend(f"  - {_call_text(call)}" for call in finding.tool_calls)
    return lines


def _call_text(call: ToolCall) -> str:
    arguments = ", ".join(f"{name}={value}" for name, value in call.arguments)
    fate = "carried out by the tool" if call.accepted else "refused by the tool"
    result = f"; the tool answered {_code(call.result)}" if call.result else ""
    return f"{_code(f'{call.tool}({arguments})')} {fate}{result}"


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
    discarded = (
        f", {rate.contaminated} discarded as contaminated and not counted" if rate.contaminated else ""
    )
    return f"{verb} {rate.successes} of {rate.trials} {noun_plural}{errors}{discarded}{interval}"


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
                f"### Suspected {index}: {_text(item.title)}",
                "",
                f"- Attack: {_code(item.attack_id)} (technique: {_text(item.technique)})",
                f"- Slot: {_code(item.slot_id)}",
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
        "attacker-visible input; these runs prove nothing about the slot concerned "
        "and are left out of its rates."
    ]


def _errors(report: ScanReport) -> list[str]:
    if not report.errors:
        return [_EMPTY_SECTION]
    lines: list[str] = []
    for error in report.errors:
        where = f"attack {_code(error.attack_id)}" if error.attack_id else "scan-wide"
        lines.append(f"- {_text(error.phase)}, {where}: {_code(error.message)}")
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
        speaker = {"attacker": "Attacker", "user": "Ordinary user"}.get(turn.role, "Target")
        note = f" ({_text(turn.note)})" if turn.note else ""
        fence = _fence(turn.text)
        lines.append(f"**{speaker}{note}:**")
        lines.append("")
        lines.append(fence)
        lines.append(turn.text)
        lines.append(fence)
        lines.append("")
        for call in turn.tool_calls:
            lines.append(f"- Tool call recorded during this reply: {_call_text(call)}")
        if turn.tool_calls:
            lines.append("")
    return lines  # ends with a blank line; callers trim the one after their last item


_MARKUP = frozenset("\\`*_[]<>#!|")


def _text(text: str) -> str:
    """`text` as plain prose on one line: nothing in it can act as Markdown or HTML."""
    flat = " ".join(str(text).split())
    return "".join("\\" + ch if ch in _MARKUP else ch for ch in flat)


def _principals(principals: tuple[str, ...]) -> str:
    return ", ".join(_code(p) for p in principals) if principals else "(none listed)"


def _config(report: ScanReport) -> str:
    if not report.target_config:
        return "not recorded"
    return ", ".join(f"{_text(key)} {_code(value)}" for key, value in sorted(report.target_config.items()))


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
