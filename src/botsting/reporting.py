"""The reports a scan writes, and what it prints when it ends.

Shared by the commands that end in a person reading something: `scan` (and the first
scan behind it), `ci` and `demo`. Each report format itself lives in its own module
(report_markdown, report_html); this one owns where they are written and what the
terminal shows.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from botsting.core.models import ScanReport


def write_file(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_reports(
    report: ScanReport, out: Path, markdown: Path | None = None, html: Path | None = None
) -> list[tuple[str, str]]:
    """Write the JSON report, and the readable and browser reports when paths are given.

    Returns the (label, full path) pairs for the next-steps note. Full paths: a
    relative one is wrong as soon as the reader is in another folder.
    """
    write_file(out, json.dumps(report.to_dict(), indent=2))
    paths = [("Report (JSON)", str(out.resolve()))]
    if markdown is not None:
        from botsting.report_markdown import render_markdown

        write_file(markdown, render_markdown(report, str(out)))
        paths.append(("Readable report", str(markdown.resolve())))
    if html is not None:
        from botsting.report_html import render_html

        write_file(html, render_html(report, str(out)))
        paths.insert(0, ("Report to open in a browser", str(html.resolve())))
    return paths


def summary(report: ScanReport) -> str:
    """What a scan prints: the verdict first, findings grouped, one real exchange. See console.py."""
    from botsting.console import render, use_colour

    return render(report, use_colour())


def show_summary(report: ScanReport, paths: list[tuple[str, str]], replay: str = "") -> None:
    """Print what the scan found, then the next steps: where the reports are and how to replay a finding."""
    from botsting.console import next_steps, use_colour

    print(summary(report))
    print()
    print(next_steps(report, paths, replay, use_colour()))


def open_for_a_person(page: Path, declined: bool = False) -> bool:
    """Open a report in the browser, but only when someone is sitting at a terminal: never in a
    pipeline, a test, or when output is piped somewhere."""
    import os
    import webbrowser

    if declined or not sys.stdout.isatty() or os.environ.get("CI") or os.environ.get("BOTSTING_NO_OPEN"):
        return False
    try:
        return webbrowser.open(page.resolve().as_uri())
    except Exception:
        return False
