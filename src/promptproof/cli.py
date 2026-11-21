"""Command line: `promptproof scan` and `promptproof replay`.

Exit codes: 0 no verified violations, 1 violations verified (or reproduced, for replay),
2 inconclusive or a usage error. A script can therefore tell "found nothing" from
"could not tell", and a broken target can never be mistaken for a fixed one.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from promptproof import __version__
from promptproof.attacks.library import attacks_for, benign_probes
from promptproof.core.models import Rate, ScanReport
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
            f"  {finding.id} [{finding.level.label}] {finding.attack_id}: {finding.slot_id} leaked "
            f"({finding.encoding}, {finding.scope}); found in "
            f"{describe_rate(finding.discovery, 'search attempts')}; reproduced in "
            f"{describe_rate(finding.reproduction, 'replays from reset')}"
        )
    if report.suspected:
        lines.append(f"  {len(report.suspected)} suspected finding(s), not verified and not counted.")
    if report.contaminated_attempts:
        lines.append(f"  {report.contaminated_attempts} attempt(s) discarded as contaminated.")
    return "\n".join(lines)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _scan(args: argparse.Namespace) -> int:
    try:
        target = build_target(args.target)
        config = ScanConfig(discovery_runs=args.discovery_runs, reproduction_trials=args.replays)
    except (SpecError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INCONCLUSIVE
    slots = target.slots()
    attacks = benign_probes(target.task_checks(), target.attacker_principal, slots) + attacks_for(slots)
    report = asyncio.run(run_scan(target, attacks, config))

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

    result = asyncio.run(replay_finding(target, finding.slot_id, finding.frozen_turns, args.trials))
    print(
        f"{finding.id} ({finding.attack_id}) against {target.spec}: {finding.slot_id} leaked in "
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
    print("The canary is still reachable by its legitimate route and normal use still works.")
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
