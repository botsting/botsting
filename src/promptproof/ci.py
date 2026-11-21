"""`promptproof ci`: one command for a build pipeline.

It runs a scan, writes the JSON, readable and browser reports into one directory, seals
that directory into an evidence bundle, and exits in a way a pipeline can act on:

    promptproof ci --target http:staging --fail-on violations

On GitHub Actions it also adds the readable report to the job summary and sets the
outputs `status`, `findings`, `seal` and `bundle`. The same command works on any
other pipeline; those two extras are simply skipped.

`--fail-on` chooses what fails the build:
    violations     (default) a proven finding fails it; an inconclusive scan does not
    inconclusive   a proven finding or an inconclusive scan fails it
    never          nothing fails it; read the report

A scan that could not run at all (a target that is not described, no authorization)
fails the build under both `violations` and `inconclusive`: a pipeline that tests
nothing must not look green.

An inconclusive scan is not a clean one: it means the scan could not show that its
attacks would have been seen. With the default, the summary says so in its first line.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from promptproof.seal import SealError, seal

FAIL_ON = ("violations", "inconclusive", "never")
_SUMMARY_LIMIT = 900_000  # GitHub refuses step summaries over 1 MB


def register(commands: argparse._SubParsersAction, scan_parents: list[argparse.ArgumentParser]) -> None:  # type: ignore[type-arg]
    parser = commands.add_parser(
        "ci",
        parents=scan_parents,
        help="scan, write every report, seal the evidence, and exit for a build pipeline",
    )
    parser.add_argument("--dir", default="promptproof-report", help="where the reports go (default promptproof-report)")
    parser.add_argument("--fail-on", choices=FAIL_ON, default="violations", help="what fails the build")
    parser.set_defaults(handler=_ci)


def _append(path: str | None, text: str) -> None:
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as file:
            file.write(text)
    except OSError as error:
        print(f"note: could not write to {path}: {error}", file=sys.stderr)


def _ci(args: argparse.Namespace) -> int:
    from promptproof.cli import (
        EXIT_INCONCLUSIVE,
        EXIT_NO_VERIFIED,
        EXIT_VIOLATIONS,
        _scan,
    )

    directory = Path(args.dir)
    if directory.exists() and any(directory.iterdir()):
        print(f"error: {directory} is not empty; give an empty or new --dir so old evidence is not mixed in", file=sys.stderr)
        return EXIT_INCONCLUSIVE
    args.out = str(directory / "scan.promptproof.json")
    args.markdown = str(directory / "report.md")
    args.html = str(directory / "report.html")
    code = _scan(args)

    status, findings = "not_run", 0
    report = Path(args.out)
    if report.exists():
        data = json.loads(report.read_text(encoding="utf-8"))
        status, findings = str(data.get("status", "unknown")), len(data.get("findings", []))

    value, bundle = "", directory.with_name(directory.name + ".sealed.zip")
    if directory.is_dir() and any(directory.iterdir()):
        try:
            value = seal(directory, bundle)
            print(f"Evidence bundle: {bundle}")
            print(f"Seal: {value}")
        except SealError as error:
            print(f"note: the evidence was not sealed: {error}", file=sys.stderr)

    headline = {
        EXIT_VIOLATIONS: f"Promptproof: {findings} proven finding(s).",
        EXIT_NO_VERIFIED: "Promptproof: no verified violations under the tested conditions.",
    }.get(code, "Promptproof: INCONCLUSIVE. This is not a clean result; the report says what could not be shown.")
    if status == "not_run":
        headline = "Promptproof: NOT RUN. Nothing was tested; see the error above."
    summary = f"## {headline}\n\n"
    if value:
        summary += f"Evidence seal: `{value}`\n\n"
    readable = Path(args.markdown)
    if readable.exists():
        text = readable.read_text(encoding="utf-8")
        if len(text) > _SUMMARY_LIMIT:
            text = text[:_SUMMARY_LIMIT] + "\n\n(The report is longer; see the uploaded files.)\n"
        summary += text
    _append(os.environ.get("GITHUB_STEP_SUMMARY"), summary)
    _append(
        os.environ.get("GITHUB_OUTPUT"),
        f"status={status}\nfindings={findings}\nseal={value}\nbundle={bundle if value else ''}\n",
    )
    print(headline)

    if args.fail_on == "never":
        return 0
    if code == EXIT_VIOLATIONS:
        return EXIT_VIOLATIONS
    if status == "not_run":
        return EXIT_INCONCLUSIVE
    if code != EXIT_NO_VERIFIED and args.fail_on == "inconclusive":
        return EXIT_INCONCLUSIVE
    return 0
