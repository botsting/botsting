"""Command line: `promptproof scan` and `promptproof replay`.

Exit codes: 0 no verified violations, 1 violations verified (or reproduced, for replay),
2 inconclusive or a usage error. A script can therefore tell "found nothing" from
"could not tell", and a broken target can never be mistaken for a fixed one.
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
from collections.abc import Callable
from pathlib import Path

from promptproof import __version__
from promptproof.attacks.adaptive import LLMAdaptiveStrategy
from promptproof.attacks.library import default_attacks
from promptproof.core.benchmark import DEFAULT_MARGIN, compare_strategies, render_benchmark_markdown
from promptproof.core.models import Finding, Rate, ScanReport
from promptproof.core.runner import ScanConfig, identity_unknown, replay_finding, run_scan, run_to_completion
from promptproof.shell import replay_command
from promptproof.targets.registry import SpecError, build_model, build_target

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
        lines.append(f"{len(report.findings)} verified violation(s): {report.breakdown()}.")
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
    if finding.kind == "injection":
        # Association, not proof of cause: the tool ran with the planted text in place and
        # did not run with harmless text there.
        return f"{finding.slot_id}: with planted text in place, {tools} was called, {fate}"
    return f"{finding.slot_id}: the attacker's conversation led to a call to {tools}, {fate}"


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
        return run_to_completion(start(lambda: False))  # type: ignore[arg-type]
    try:
        return run_to_completion(start(lambda: state["cancelled"]))  # type: ignore[arg-type]
    finally:
        signal.signal(signal.SIGINT, previous)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _scan(args: argparse.Namespace) -> int:
    try:
        target = build_target(args.target)
        limits: dict[str, object] = {
            "discovery_runs": args.discovery_runs,
            "reproduction_trials": args.replays,
            "max_messages": args.max_messages,
            "max_tool_calls": args.max_tool_calls,
            "max_seconds": args.max_seconds,
            "discovery_budget_per_objective": args.budget_per_objective,
        }
        ScanConfig(**limits)  # type: ignore[arg-type]
        attacks = default_attacks(target) if args.strategy in ("static", "both") else []
        strategy = None
        if args.strategy in ("adaptive", "both"):
            attacker_model = build_model(args.attacker_model)
            strategy = LLMAdaptiveStrategy(
                model=attacker_model,
                max_turns=args.max_turns,
                max_episodes=args.max_episodes,
            )
    except (SpecError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INCONCLUSIVE
    try:
        report = _run_until_done_or_cancelled(
            lambda cancelled: run_scan(
                target,
                attacks,
                ScanConfig(**limits, cancelled=cancelled),  # type: ignore[arg-type]
                strategy=strategy,
            )
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
    if args.html:
        from promptproof.report_html import render_html

        _write(Path(args.html), render_html(report, str(out)))
        print(f"Report to open in a browser: {args.html}")
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

    result = run_to_completion(replay_finding(target, finding, args.trials))
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
    if result.unattributable:
        print("Inconclusive: the tool ran, but that cannot be pinned on the planted text:")
        print(f"  {result.unattributable}")
        return EXIT_INCONCLUSIVE
    if result.rate.successes:
        return EXIT_VIOLATIONS
    if result.problems:
        print("Inconclusive: no leak was observed, but that cannot be relied on:")
        for problem in result.problems:
            print(f"  {problem}")
        return EXIT_INCONCLUSIVE
    print("What it reached still works by its legitimate route, and normal use still works.")
    return EXIT_NO_VERIFIED


def _benchmark(args: argparse.Namespace) -> int:
    try:
        hardened = [build_target(spec) for spec in args.hardened]
        controls = [build_target(spec) for spec in args.controls]
        attacker_model = build_model(args.attacker_model)
        strategy = LLMAdaptiveStrategy(
            model=attacker_model,
            max_turns=args.max_turns,
            max_episodes=args.max_episodes,
        )
    except (SpecError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INCONCLUSIVE

    try:
        report = run_to_completion(
            compare_strategies(
                hardened,
                controls,
                strategy,
                budget_per_objective=args.budget_per_objective,
                reproduction_trials=args.replays,
                required_margin=args.margin,
                max_seconds=args.max_seconds,
            )
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INCONCLUSIVE

    text = render_benchmark_markdown(report)
    print(text, end="")
    if args.out:
        _write(Path(args.out), json.dumps(report.to_dict(), indent=2))
        print(f"Benchmark JSON: {args.out}")
    return EXIT_NO_VERIFIED if report.passed else EXIT_VIOLATIONS


def _practice_server(args: argparse.Namespace) -> int:
    import time

    from promptproof.practice_server import PracticeBot, practice_description, start, write_description
    from promptproof.targets.http import targets_file
    from promptproof.targets.registry import build_model

    try:
        bot = PracticeBot(args.variant, build_model(args.model))
        server = start(bot, port=args.port)
    except (SpecError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INCONCLUSIVE
    port = server.server_address[1]
    print(f"Practice bot ({args.variant}) listening on http://127.0.0.1:{port}. Press Ctrl+C to stop.")
    if args.write_config:
        path = targets_file()
        write_description(path, "practice", practice_description(port, args.variant))
        print(f"Described it as target 'practice' in {path}. Scan it with: promptproof scan --target http:practice")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.shutdown()
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
    scan.add_argument("--html", help="also write a self-contained report to open in a browser or print")
    scan.add_argument(
        "--strategy",
        choices=("static", "adaptive", "both"),
        default="static",
        help="run the static attack list, the adaptive attacker, or both",
    )
    scan.add_argument(
        "--attacker-model",
        default="scripted-attacker",
        help="model driving the adaptive attacker (scripted-attacker or ollama:<model>)",
    )
    scan.add_argument("--max-turns", type=int, default=3, help="maximum turns per adaptive conversation episode")
    scan.add_argument("--max-episodes", type=int, default=4, help="maximum adaptive episodes per objective")
    scan.add_argument(
        "--budget-per-objective",
        type=int,
        default=None,
        help="optional cap on discovery target messages per objective",
    )
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

    bench = commands.add_parser(
        "benchmark",
        help="compare static vs. adaptive attacks at equal per-objective target-message budgets",
    )
    bench.add_argument(
        "--hardened",
        nargs="+",
        default=["hardened:keyword", "hardened:multiturn"],
        help="held-out hardened target specs",
    )
    bench.add_argument(
        "--controls",
        nargs="*",
        default=["hardened:keyword-fixed", "hardened:multiturn-fixed"],
        help="fixed control target specs that must return no verified violations",
    )
    bench.add_argument("--attacker-model", default="scripted-attacker")
    bench.add_argument("--budget-per-objective", type=int, default=8)
    bench.add_argument("--max-turns", type=int, default=3)
    bench.add_argument("--max-episodes", type=int, default=4)
    bench.add_argument("--replays", type=int, default=3)
    bench.add_argument("--margin", type=float, default=DEFAULT_MARGIN)
    bench.add_argument("--max-seconds", type=float, default=300.0)
    bench.add_argument("--out", help="optional path to write benchmark JSON")
    bench.set_defaults(handler=_benchmark)

    from promptproof.authorize_cli import register as register_authorize

    register_authorize(commands)

    practice = commands.add_parser(
        "practice-server",
        help="serve the practice bot over HTTP on this machine, to try the HTTP adapter",
    )
    practice.add_argument("--variant", choices=["vulnerable", "hardened", "fixed"], default="vulnerable")
    practice.add_argument("--port", type=int, default=8765)
    practice.add_argument("--model", default="scripted", help="scripted, or ollama:<model name>")
    practice.add_argument(
        "--write-config", action="store_true",
        help="add this server as target 'practice' to the targets file (promptproof.targets.json)",
    )  # fmt: skip
    practice.set_defaults(handler=_practice_server)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
