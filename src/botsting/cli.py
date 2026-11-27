"""Command line: `botsting scan` and `botsting replay`.

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

from botsting import __version__
from botsting.attacks.adaptive import LLMAdaptiveStrategy
from botsting.attacks.library import all_attacks, default_attacks
from botsting.console import NO_VERIFIED_HEADLINE, what_happened  # noqa: F401  (re-exported)
from botsting.core.benchmark import DEFAULT_MARGIN, compare_strategies, render_benchmark_markdown
from botsting.core.models import Rate, ScanReport
from botsting.core.runner import ScanConfig, identity_unknown, replay_finding, run_scan, run_to_completion
from botsting.exits import EXIT_FAILED, EXIT_INCONCLUSIVE, EXIT_NO_VERIFIED, EXIT_OK, EXIT_VIOLATIONS
from botsting.reporting import earlier_report, open_for_a_person, show_summary, write_file, write_reports
from botsting.shell import replay_command
from botsting.targets.registry import SpecError, build_model, build_target


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


def run_scan_command(args: argparse.Namespace) -> int:
    """The `botsting scan` command, once the target is known: scan it, write the reports, say what to do next.

    `quick` (a first scan of a URL) and `ci` call this too, with their own arguments
    already folded into `args`.
    """
    if not args.target:
        print(
            "error: say what to scan: a chat URL (botsting scan http://localhost:8000/chat) or --target NAME",
            file=sys.stderr,
        )
        return EXIT_INCONCLUSIVE
    try:
        target = build_target(args.target)
        limits: dict[str, object] = {
            "discovery_runs": args.discovery_runs,
            "reproduction_trials": args.replays,
            "max_messages": args.max_messages,
            "max_tool_calls": args.max_tool_calls,
            "max_seconds": args.max_seconds,
            "discovery_budget_per_objective": args.budget_per_objective,
            "tester": args.tester,
            "independence": args.independence,
        }
        ScanConfig(**limits)  # type: ignore[arg-type]
        listed = default_attacks if getattr(args, "attacks", "all") == "built-in" else all_attacks
        attacks = listed(target) if args.strategy in ("static", "both") else []
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

    previous = earlier_report(Path(args.out))  # read before this scan's report replaces it
    paths = write_reports(
        report,
        Path(args.out),
        Path(args.markdown) if args.markdown else None,
        Path(args.html) if args.html else None,
        Path(args.sarif) if getattr(args, "sarif", None) else None,
        Path(args.statement) if getattr(args, "statement", None) else None,
    )
    if args.html:
        open_for_a_person(Path(args.html), getattr(args, "no_open", False))
    replay = replay_command(str(args.out), report.findings[0].id) if report.findings else ""
    show_summary(report, paths, replay, previous)
    return {
        "violations_verified": EXIT_VIOLATIONS,
        "no_verified_violations": EXIT_NO_VERIFIED,
        "inconclusive": EXIT_INCONCLUSIVE,
    }[report.status]


def _scan_or_first_scan(args: argparse.Namespace) -> int:
    if args.url and args.target:
        print("error: give a URL for a first scan, or --target for a described target, not both", file=sys.stderr)
        return EXIT_INCONCLUSIVE
    if args.url:
        from botsting.quick import run

        return run(args)
    return run_scan_command(args)


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
        write_file(Path(args.out), json.dumps(report.to_dict(), indent=2))
        print(f"Benchmark JSON: {args.out}")
    return EXIT_NO_VERIFIED if report.passed else EXIT_VIOLATIONS


def _practice_server(args: argparse.Namespace) -> int:
    import time

    from botsting.practice_server import PracticeBot, practice_description, start, write_description
    from botsting.targets.http import targets_file
    from botsting.targets.registry import build_model

    try:
        bot = PracticeBot(args.variant, build_model(args.model))
        server = start(bot, port=args.port)
    except (SpecError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAILED
    port = server.server_address[1]
    print(f"Practice bot ({args.variant}) listening on http://127.0.0.1:{port}. Press Ctrl+C to stop.")
    if args.write_config:
        path = targets_file()
        write_description(path, "practice", practice_description(port, args.variant))
        print(f"Described it as target 'practice' in {path}. Scan it with: botsting scan --target http:practice")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.shutdown()
        return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="botsting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Evidence-first security testing for LLM applications.\n\n"
            "Start here:\n"
            "  botsting demo                              see it work on a built-in practice bot, in a minute\n"
            "  botsting guide                             the lines to add to your own bot\n"
            "  botsting scan http://localhost:8000/chat   scan your own bot, at its chat address\n"
            "  botsting doctor --target http:NAME         when something is not working: what to fix next"
        ),
    )
    parser.add_argument("--version", action="version", version=f"botsting {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    # What a scan does, shared by `scan` and `ci`. Where the reports go is each command's own.
    scan = options = argparse.ArgumentParser(add_help=False)
    scan.add_argument("--target", help="for example toy:vulnerable, or http:NAME for a bot described in the targets file")
    scan.add_argument(
        "--strategy",
        choices=("static", "adaptive", "both"),
        default="static",
        help="run the static attack list, the adaptive attacker, or both",
    )
    scan.add_argument(
        "--attacks",
        choices=("all", "built-in"),
        default="all",
        help="which static attacks to run: all (the built-in ones and those reused from public collections), or only the built-in ones",
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
    scan.add_argument(
        "--tester",
        default="",
        help='who ran this scan, for example "Dana Levi, Example Audit"',
    )
    scan.add_argument(
        "--independence",
        choices=("self", "internal", "third-party"),
        default="self",
        help="independence of the tester from the team that built or operates the target",
    )
    scan = commands.add_parser(
        "scan",
        parents=[options],
        help="attack a target and report what was proven",
        description=(
            "botsting scan http://localhost:8000/chat   a first scan of a bot that carries the drop-in harness: "
            "no description file is needed. botsting scan --target NAME   a described target."
        ),
    )
    scan.add_argument("url", nargs="?", help="the chat address of a bot that carries the drop-in harness")
    scan.add_argument("--name", help="with a URL: the name to save the worked-out description under")
    scan.add_argument("--field", help="with a URL: the request field that carries the message, if it is not found")
    scan.add_argument("--session-field", help="with a URL: a request field for the conversation id, if the bot has one")
    scan.add_argument("--reply", help="with a URL: a JSON pointer to the reply text, such as /data/answer")
    scan.add_argument(
        "--message",
        help='with a URL: an ordinary request to send while working the bot out (default "Hello"); give one that '
        "makes the bot read its notes or documents, so planted text there is tested",
    )
    scan.add_argument("--out", default="reports/scan.botsting.json", help="where to write the JSON report")
    scan.add_argument("--markdown", help="also write a readable report to this path")
    scan.add_argument("--html", help="also write a self-contained report to open in a browser or print")
    scan.add_argument("--sarif", help="also write the findings as SARIF 2.1.0, for a code-scanning dashboard")
    scan.add_argument("--statement", help="also write a one-page statement of the scan, to show to someone else")
    scan.add_argument("--no-open", action="store_true", help="do not open the browser report when the scan ends")
    scan.set_defaults(handler=_scan_or_first_scan)

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

    from botsting.authorize_cli import register as register_authorize

    register_authorize(commands)

    from botsting.seal import register as register_seal

    register_seal(commands)

    from botsting.egress_trap import register as register_trap

    register_trap(commands)

    from botsting.ci import register as register_ci

    register_ci(commands, [options])

    from botsting.mcp_server import register as register_mcp

    register_mcp(commands)

    from botsting.statement import register as register_statement

    register_statement(commands)

    from botsting.demo import register as register_demo

    register_demo(commands)

    from botsting.doctor import register as register_doctor

    register_doctor(commands)

    from botsting.presets import register as register_presets

    register_presets(commands)

    from botsting.sterility import register as register_sterility

    register_sterility(commands)

    key = commands.add_parser("harness-key", help="make a key for the drop-in test harness (botsting.harness)")
    key.set_defaults(handler=_harness_key)

    practice = commands.add_parser(
        "practice-server",
        help="serve the practice bot over HTTP on this machine, to try the HTTP adapter",
    )
    practice.add_argument("--variant", choices=["vulnerable", "hardened", "fixed"], default="vulnerable")
    practice.add_argument("--port", type=int, default=8765)
    practice.add_argument("--model", default="scripted", help="scripted, or ollama:<model name>")
    practice.add_argument(
        "--write-config", action="store_true",
        help="add this server as target 'practice' to the targets file (botsting.targets.json)",
    )  # fmt: skip
    practice.set_defaults(handler=_practice_server)
    return parser


def _harness_key(args: argparse.Namespace) -> int:
    from botsting.harness import KEY_ENV, new_key

    print(new_key())
    print(
        f"Set this as {KEY_ENV} on the deployment under test and in the environment where you run the scan. "
        "Keep it off production unless you mean to test the real system (see the README).",
        file=sys.stderr,
    )
    return EXIT_OK


def _print_anything() -> None:
    """A bot may answer in any alphabet, and its words are printed in the summary. A Windows console or
    pipe in a legacy code page cannot encode all of them, and would stop the command with an error
    after the scan had finished. Characters it cannot show are replaced instead."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(errors="replace")
            except (ValueError, OSError):  # a stream that is closed or was replaced by something else
                pass


def main(argv: list[str] | None = None) -> int:
    _print_anything()
    args = build_parser().parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
