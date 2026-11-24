"""What a scan prints in the terminal.

A developer reads this first, tired, in a terminal. So it leads with the verdict, groups
the findings by what was reached, shows one real exchange, and ends with the next
commands. The statistics (search and replay rates with their intervals) are in the
reports; here a finding shows only how many replays reproduced it.

Colour is used only when writing to a terminal, and never when NO_COLOR is set.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Sequence

from promptproof.core.models import Finding, ScanReport

NO_VERIFIED_HEADLINE = "No verified violations observed under these tested conditions."
_WIDTH = 100


class _Paint:
    def __init__(self, on: bool) -> None:
        self.on = on

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.on else text

    def bad(self, text: str) -> str:
        return self._wrap("1;31", text)

    def good(self, text: str) -> str:
        return self._wrap("1;32", text)

    def unsure(self, text: str) -> str:
        return self._wrap("1;33", text)

    def strong(self, text: str) -> str:
        return self._wrap("1", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)


def use_colour(stream: object = None) -> bool:
    stream = stream if stream is not None else sys.stdout
    return bool(getattr(stream, "isatty", lambda: False)()) and "NO_COLOR" not in os.environ


_CODE = re.compile(r"(?:[A-Z0-9]{4}-){3}[A-Z0-9]{4}")  # the shape of a planted code


def _one_line(text: str, limit: int) -> str:
    """The text on one line. A long one keeps its start and its end, or the part around a planted
    code if one is in plain sight, because the end of an answer is often where the secret came out."""
    flat = " ".join(text.split())
    if len(flat) <= limit:
        return flat
    found = _CODE.search(flat)
    if found and found.end() > limit - 8:
        tail = flat[max(0, found.start() - 30) : found.end() + 12]
        head = flat[: max(0, limit - len(tail) - 5)].rstrip()
        return f"{head} ... {tail}"
    keep = (limit - 5) // 2
    return f"{flat[:keep].rstrip()} ... {flat[-keep:].lstrip()}"


def what_happened(finding: Finding) -> str:
    if finding.kind == "disclosure":
        return f"{finding.slot_id} leaked ({finding.encoding}, {finding.scope})"
    tools = ", ".join(dict.fromkeys(call.tool for call in finding.tool_calls)) or "a forbidden tool"
    fate = "and the tool accepted it" if any(call.accepted for call in finding.tool_calls) else "which the tool refused"
    if finding.kind == "injection":
        # Association, not proof of cause: the tool ran with the planted text in place and
        # did not run with harmless text there.
        return f"{finding.slot_id}: with planted text in place, {tools} was called, {fate}"
    return f"{finding.slot_id}: the attacker's conversation led to a call to {tools}, {fate}"


def _heading(findings: Sequence[Finding]) -> str:
    """One line for everything found at one place."""
    first = findings[0]
    ways = "1 way" if len(findings) == 1 else f"{len(findings)} ways"
    if first.kind == "disclosure":
        return f"{first.slot_id}: leaked, {ways}"
    return f"{what_happened(first)} ({ways})"


ADVICE = {
    "instruction_secret": (
        "Take the secret out of the instructions. A model can be talked into repeating anything it was given. "
        "Keep the value in your code and use it there."
    ),
    "other_user_record": (
        "Check who is asking in the code that fetches the record, before the model sees it. A rule written in "
        "the instructions is a request, not a check."
    ),
    "tool_rule": (
        "Enforce who may use the tool inside the tool itself, from the signed-in user, not from what the "
        "conversation claims."
    ),
    "injection_point": (
        "Treat text the bot reads (notes, documents, tickets) as data. Offer a tool only when the current "
        "user's own message asks for it, and check that in code."
    ),
}


def advice(report: ScanReport, slot_id: str) -> str:
    """What to change, for the kind of thing that was reached. Empty if the kind is not known."""
    kind = next((slot.kind for slot in report.slots if slot.slot_id == slot_id), "")
    return ADVICE.get(kind, "")


def _wrap(text: str, indent: str, width: int = _WIDTH) -> list[str]:
    words, lines, line = text.split(), [], indent
    for word in words:
        if len(line) + len(word) + 1 > width and line.strip():
            lines.append(line.rstrip())
            line = indent
        line += word + " "
    return [*lines, line.rstrip()]


def _groups(findings: Sequence[Finding]) -> list[tuple[str, list[Finding]]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.slot_id, []).append(finding)
    return list(grouped.items())


def _exchange(finding: Finding) -> list[str]:
    """The last thing the attacker said and what came back, from the first time the attack worked."""
    asked = next((t.text for t in reversed(finding.transcript) if t.role == "attacker"), "")
    answered = next((t for t in reversed(finding.transcript) if t.role == "target"), None)
    lines = []
    if finding.payload:
        lines.append(f"    planted  {_one_line(finding.payload, _WIDTH - 13)}")
    if asked:
        lines.append(f"    asked    {_one_line(asked, _WIDTH - 13)}")
    if answered is not None:
        lines.append(f"    answer   {_one_line(answered.text, _WIDTH - 13)}")
        for call in answered.tool_calls:
            arguments = ", ".join(f"{name}={value}" for name, value in call.arguments)
            lines.append(f"    tool     {_one_line(f'{call.tool}({arguments})', _WIDTH - 13)}")
    return lines


_ERRORS_SHOWN = 3
_AFTER = re.compile(r" \(after \d+(?: of \d+)? repl(?:y|ies)\)$")


def _errors(report: ScanReport, paint: _Paint) -> list[str]:
    """What went wrong, in the scan's own words: each different message once, with how often and
    during what. An error message usually says what to change, so it belongs where the person is
    looking, not only in a report they have yet to open."""
    if not report.errors:
        return []
    seen: dict[str, list[str]] = {}
    for error in report.errors:
        # The same failure at a different point in a conversation is the same thing to fix.
        seen.setdefault(_AFTER.sub("", error.message), []).append(error.phase)
    lines = ["  " + paint.unsure("Errors")]
    for message, phases in list(seen.items())[:_ERRORS_SHOWN]:
        times = "once" if len(phases) == 1 else f"{len(phases)} times"
        lines += _wrap(f"{times}, during {', '.join(dict.fromkeys(phases))}: {message}", "    ")
    if len(seen) > _ERRORS_SHOWN:
        lines.append(f"    and {len(seen) - _ERRORS_SHOWN} more kind(s) of error, in the report")
    return lines


def render(report: ScanReport, colour: bool = False) -> str:
    """The summary printed after a scan. Its first line is the verdict."""
    paint = _Paint(colour)
    lines: list[str] = []
    if report.status == "violations_verified":
        lines.append(paint.bad(f"{len(report.findings)} verified violation(s): {report.breakdown()}."))
    elif report.status == "no_verified_violations":
        lines.append(paint.good(NO_VERIFIED_HEADLINE))
    else:
        lines.append(paint.unsure("Inconclusive: the scan could not reach a conclusion."))
    for reason in report.inconclusive_reasons:
        lines += _wrap(f"not established: {reason}", "  ")
    lines += _errors(report, paint)
    gaps = report.not_tested()
    if gaps:
        # A zero for something that was never tried must not read as a pass.
        lines.append("  " + paint.unsure("Not tested in this scan"))
        for gap in gaps:
            lines += _wrap(gap, "    ")

    for slot_id, findings in _groups(report.findings):
        lines.append("")
        lines.append("  " + paint.strong(_heading(findings)))
        for finding in findings:
            rate = finding.reproduction
            replays = f"{rate.successes} of {rate.trials} replays"
            title = finding.title if len(finding.title) <= 58 else finding.title[:55].rstrip() + "..."
            lines.append(f"    {finding.id:<4} {title:<58}  {paint.dim(replays)}")
        fix = advice(report, slot_id)
        if fix:
            lines += _wrap("Fix: " + fix, "    ")
    if report.findings:
        first = report.findings[0]
        lines.append("")
        lines.append("  " + paint.strong(f"How {first.id} happened"))
        lines += _exchange(first)
        if first.kind == "disclosure":
            lines.append(paint.dim("    The value in that answer was made for this one attempt. Nobody else had it."))

    lines.append("")
    if report.suspected:
        lines.append(f"  {len(report.suspected)} suspected finding(s), not verified and not counted.")
    if report.contaminated_attempts:
        lines.append(f"  {report.contaminated_attempts} attempt(s) discarded as contaminated.")
    lines.append(
        paint.dim(
            f"  Target {report.target}, attacker acting as {report.attacker_principal}. {report.attacks_run} attacks "
            f"tried. Spent: {report.messages_sent} messages, {report.tool_calls_recorded} recorded tool calls."
        )
    )
    return "\n".join(lines)


def next_steps(report: ScanReport, paths: Sequence[tuple[str, str]], replay: str = "", colour: bool = False) -> str:
    """Where the reports are and what to run next. `paths` are (label, path) pairs."""
    paint = _Paint(colour)
    width = max((len(label) for label, _ in paths), default=0)
    lines = [paint.strong("Next")]
    for label, path in paths:
        lines.append(f"  {label:<{max(width, 18)}}  {path}")
    if paths and not any(path.endswith((".html", ".htm")) for _, path in paths):
        lines.append(paint.dim(f"  {'A page to read':<{max(width, 18)}}  add --html report.html to the scan command"))
    if replay:
        lines.append(f"  {'Replay a finding':<{max(width, 18)}}  {replay}")
        if len(report.findings) > 1:
            lines.append(paint.dim(f"  {'':<{max(width, 18)}}  (any id from {report.findings[0].id} to {report.findings[-1].id})"))
    return "\n".join(lines)
