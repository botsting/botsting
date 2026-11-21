"""Command line: `promptproof scan` and `promptproof replay`.

Exit codes: 0 no verified violations, 1 violations verified (or reproduced, for replay),
2 inconclusive or a usage error. A script can therefore tell "found nothing" from
"could not tell", and a broken target can never be mistaken for a fixed one.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import signal
import sys
from collections.abc import Callable
from pathlib import Path

from promptproof import __version__
from promptproof.attacks.library import default_attacks
from promptproof.core.models import Finding, Rate, ScanReport
from promptproof.core.runner import ScanConfig, identity_unknown, replay_finding, run_scan
from promptproof.shell import replay_command
from promptproof.targets.registry import SpecError, build_target

EXIT_NO_VERIFIED = 0
EXIT_VIOLATIONS = 1
EXIT_INCONCLUSIVE = 2

NO_VERIFIED_HEADLINE = "No verified violations observed under these tested conditions."


def _percent(value: float | None) -> str:
    return "n/a" if value is None else f"{round(value * 100)}%"


def describe_rate(rate: Rate, noun: str) -> str:
    text = f"{rate.successes} of {rate.trials} {noun}"
    if rate.trials:
        text += f" (95% Wilson interval {_percent(rate.interval_low)} to {_percent(rate.interval_high)})"
    if rate.errors:
        text += f", {rate.errors} more did not complete"
    if rate.contaminated:
        text += f", {rate.contaminated} more discarded as contaminated"
    return text


def _summary(report: ScanReport) -> str:
    lines: list[str] = []
    if report.status == "violations_verified":
        lines.append(f"{len(report.findings)} verified violation(s).")
    elif report.status == "no_verified_violations":
        lines.append(NO_VERIFIED_HEADLINE)
    else:
        lines.append("Inconclusive: the scan could not reach a conclusion.")
    lines.append(
        f"Target {report.target}; {report.attacks_run} attacks, {report.attempts_run} attempts, "
        f"attacker acting as {report.attacker_principal}."
    )
    for reason in report.inconclusive_reasons:
        lines.append(f"  not established: {reason}")
    for finding in report.findings:
        lines.append(
            f"  {finding.id} [{finding.level.label}] {finding.attack_id}: {what_happened(finding)}; found in "
            f"{describe_rate(finding.discovery, 'search attempts')}; reproduced in "
            f"{describe_rate(finding.reproduction, 'replays from reset')}"
        )
    if report.suspected:
        lines.append(f"  {len(report.suspected)} suspected finding(s), not verified and not counted.")
    if report.contaminated_attempts:
        lines.append(f"  {report.contaminated_attempts} attempt(s) discarded as contaminated.")
    lines.append(f"  Spent: {report.messages_sent} messages, {report.tool_calls_recorded} recorded tool calls.")
    return "\n".join(lines)


def what_happened(finding: Finding) -> str:
    if finding.kind == "disclosure":
        return f"{finding.slot_id} leaked ({finding.encoding}, {finding.scope})"
    tools = ", ".join(dict.fromkeys(call.tool for call in finding.tool_calls)) or "a forbidden tool"
    fate = "and the tool carried it out" if any(call.accepted for call in finding.tool_calls) else "which the tool refused"
    how = "planted text caused a call to" if finding.kind == "injection" else "the attacker caused a call to"
    return f"{finding.slot_id}: {how} {tools}, {fate}"


def _run_until_done_or_cancelled(start: Callable[[Callable[[], bool]], object]) -> object:
    """Run a scan so that Ctrl+C stops it after the current message and a partial report is still written.

    A second Ctrl+C gives up immediately.
    """
    state = {"cancelled": False}

    def on_interrupt(signum: int, frame: object) -> None:
        if state["cancelled"]:
            raise KeyboardInterrupt
        state["cancelled"] = True
        print("Stopping after the current message. Press Ctrl+C again to abandon the scan.", file=sys.stderr)

    try:
        previous = signal.signal(signal.SIGINT, on_interrupt)
    except ValueError:  # not the main thread; run without the handler
        return asyncio.run(start(lambda: False))  # type: ignore[arg-type]
    try:
        return asyncio.run(start(lambda: state["cancelled"]))  # type: ignore[arg-type]
    finally:
        signal.signal(signal.SIGINT, previous)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _scan(args: argparse.Namespace) -> int:
    try:
        target = build_target(args.target)
        limits = {
            "discovery_runs": args.discovery_runs,
            "reproduction_trials": args.replays,
            "max_messages": args.max_messages,
            "max_tool_calls": args.max_tool_calls,
            "max_seconds": args.max_seconds,
        }
        ScanConfig(**limits)  # validate before anything runs
        attacks = default_attacks(target)
    except (SpecError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INCONCLUSIVE
    try:
        report = _run_until_done_or_cancelled(
            lambda cancelled: run_scan(target, attacks, ScanConfig(**limits, cancelled=cancelled))
        )
    except ValueError as exc:  # the runner refused the target or the attack list
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INCONCLUSIVE
    assert isinstance(report, ScanReport)

    out = Path(args.out)
    _write(out, json.dumps(report.to_dict(), indent=2))
    print(_summary(report))
    print(f"Report: {out}")
    if args.markdown:
        from promptproof.report_markdown import render_markdown

        _write(Path(args.markdown), render_markdown(report, str(out)))
        print(f"Readable report: {args.markdown}")
    for finding in report.findings:
        print(f"Replay {finding.id}: {replay_command(str(out), finding.id)}")
    return {
        "violations_verified": EXIT_VIOLATIONS,
        "no_verified_violations": EXIT_NO_VERIFIED,
        "inconclusive": EXIT_INCONCLUSIVE,
    }[report.status]


def _replay(args: argparse.Namespace) -> int:
    try:
        report = ScanReport.from_dict(json.loads(Path(args.report).read_text(encoding="utf-8")))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: could not read report {args.report}: {exc}", file=sys.stderr)
        return EXIT_INCONCLUSIVE
    finding = next((f for f in report.findings if f.id == args.finding), None)
    if finding is None:
        known = ", ".join(f.id for f in report.findings) or "none"
        print(f"error: no finding {args.finding!r} in this report (findings: {known})", file=sys.stderr)
        return EXIT_INCONCLUSIVE
    if args.trials < 1:
        print("error: --trials must be at least 1", file=sys.stderr)
        return EXIT_INCONCLUSIVE
    try:
        target = build_target(args.target or report.target)
    except SpecError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INCONCLUSIVE

    result = asyncio.run(replay_finding(target, finding, args.trials))
    verb = "leaked" if finding.kind == "disclosure" else "was violated"
    print(
        f"{finding.id} ({finding.attack_id}) against {target.spec}: {finding.slot_id} {verb} in "
        f"{describe_rate(result.rate, 'replays from reset with fresh canaries')}."
    )
    changed = sorted(
        key
        for key in set(report.target_config) | set(result.target_config)
        if report.target_config.get(key) != result.target_config.get(key)
    )
    if changed:
        print("Note: this is not the configuration that was scanned. Changed: " + ", ".join(changed) + ".")
    unknown = sorted(set(identity_unknown(report.target_config)) | set(identity_unknown(result.target_config)))
    if unknown:
        print(
            f"Note: the target's {', '.join(unknown)} could not be read, then or now, so it is not known "
            "whether this is the configuration that was scanned."
        )
    if result.rate.successes:
        return EXIT_VIOLATIONS
    if result.problems:
        print("Inconclusive: no leak was observed, but that cannot be relied on:")
        for problem in result.problems:
            print(f"  {problem}")
        return EXIT_INCONCLUSIVE
    print("What it reached still works by its legitimate route, and normal use still works.")
    return EXIT_NO_VERIFIED


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="promptproof",
        description="Evidence-first security testing for LLM applications.",
    )
    parser.add_argument("--version", action="version", version=f"promptproof {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="attack a target and report what was proven")
    scan.add_argument("--target", required=True, help="for example toy:vulnerable or toy:fixed?model=ollama:llama3.2")
    scan.add_argument("--out", default="reports/scan.promptproof.json", help="where to write the JSON report")
    scan.add_argument("--markdown", help="also write a readable report to this path")
    scan.add_argument("--discovery-runs", type=int, default=1, help="attempts per attack while searching")
    scan.add_argument("--replays", type=int, default=5, help="replays of each attack that worked")
    scan.add_argument("--max-messages", type=int, default=5000, help="stop after sending this many messages")
    scan.add_argument("--max-tool-calls", type=int, default=500, help="stop once more than this many tool calls were recorded")
    scan.add_argument("--max-seconds", type=float, default=3600, help="stop after this much time")
    scan.set_defaults(handler=_scan)

    rep = commands.add_parser("replay", help="replay a finding from a reset state with fresh canaries")
    rep.add_argument("report", help="a JSON report written by scan")
    rep.add_argument("--finding", required=True, help="finding id, for example F1")
    rep.add_argument("--trials", type=int, default=5)
    rep.add_argument("--target", help="replay against a different target, for example the fixed build")
    rep.set_defaults(handler=_replay)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
