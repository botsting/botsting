"""A scan statement: one page that says what one scan tested and what it found.

    botsting scan ... --statement reports/statement.html
    botsting statement reports/scan.botsting.json            # from a report that already exists

It is for showing to someone else: a client, a manager, a customer's security form. It holds
no conversation and no planted value, only the outcome, the coverage and the limits, and the
SHA-256 of the full report, so whoever holds that report can see the two belong together.

It is a record of one scan. It is not a certification, and it never says more than the
report does: an inconclusive scan is stated as inconclusive, and what was not tested is
listed as prominently as what was found.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from html import escape
from pathlib import Path
from typing import Any

from botsting import ratings
from botsting.core.models import ScanReport
from botsting.exits import EXIT_FAILED, EXIT_OK
from botsting.report_markdown import HEADLINE_NO_VERIFIED_VIOLATIONS

KINDS = {
    "instruction_secret": "A secret in the bot's instructions coming out",
    "other_user_record": "One user's protected record reaching another user",
    "tool_rule": "A tool no chat user may cause being called from the conversation",
    "injection_point": "Text the bot reads from elsewhere making it call a tool",
}
WHAT_THIS_IS = (
    "This page records one scan by BotSting, an open-source tool that tests a bot the way an attacker would and "
    "reports only what it can prove. It is not a certification of the bot. A scan in which nothing was proven "
    "shows that the attacks listed did not work on that day; it is not a statement that the bot is protected."
)

_CSS = """
:root { --paper:#f7f9fb; --sheet:#ffffff; --ink:#14181f; --muted:#56606e; --rule:#d3dae3; --bad:#b81a36; --ok:#0d6657; --unsure:#855600;
  --display:Bahnschrift,"DIN Alternate","Avenir Next Condensed","Roboto Condensed","Arial Narrow",sans-serif;
  --text:Charter,"Bitstream Charter","Sitka Text",Cambria,Georgia,serif;
  --mono:ui-monospace,"Cascadia Mono","SF Mono",Menlo,Consolas,monospace; }
@media (prefers-color-scheme: dark) { :root { --paper:#0f1217; --sheet:#151a21; --ink:#e6eaf0; --muted:#9aa5b3; --rule:#2a323d;
  --bad:#ff8397; --ok:#6fd3bd; --unsure:#e5bd62; } }
* { box-sizing:border-box; }
body { margin:0; background:var(--paper); color:var(--ink); font:1.0625rem/1.6 var(--text); }
main { max-width:46rem; margin:2rem auto; padding:2.5rem 2rem 3rem; background:var(--sheet); border:1px solid var(--rule); }
h1, h2, dt, .verdict { font-family:var(--display); }
h1 { font-size:.95rem; font-weight:600; color:var(--muted); margin:0 0 1.25rem; }
h2 { font-size:1.15rem; font-weight:700; margin:2rem 0 .5rem; }
.verdict { font-size:clamp(1.7rem,5vw,2.4rem); font-weight:700; line-height:1.08; margin:0; padding-top:1rem; border-top:.5rem solid var(--muted); }
.verdict.bad { color:var(--bad); border-color:var(--bad); } .verdict.ok { color:var(--ok); border-color:var(--ok); }
.verdict.unsure { color:var(--unsure); border-color:var(--unsure); }
p { margin:.6rem 0; } ul { margin:.4rem 0; padding-left:1.2rem; } li { margin:.25rem 0; }
dl { display:grid; grid-template-columns:11rem minmax(0,1fr); gap:.35rem 1rem; margin:.6rem 0; }
dt { color:var(--muted); font-size:.95rem; } dd { margin:0; overflow-wrap:anywhere; }
code { font:.84em var(--mono); overflow-wrap:anywhere; }
.note { color:var(--muted); font-size:.94rem; }
@media (max-width:36rem) { main { margin:0; border:0; padding:1.5rem 1rem; } dl { grid-template-columns:minmax(0,1fr); gap:0; } dd { margin-bottom:.5rem; } }
@media print { body { background:#fff; } main { margin:0; border:0; max-width:none; } }
"""


def _e(text: object) -> str:
    return escape(str(text), quote=True)


def fingerprint(report_file: bytes) -> str:
    """The SHA-256 of the report file as written, which the statement carries."""
    return hashlib.sha256(report_file).hexdigest()


def _verdict(report: ScanReport) -> tuple[str, str]:
    if report.status == "violations_verified":
        count = len(report.findings)
        return "bad", f"{count} verified violation{'' if count == 1 else 's'} found."
    if report.status == "no_verified_violations":
        return "ok", HEADLINE_NO_VERIFIED_VIOLATIONS
    return "unsure", "The scan could not reach a conclusion."


def render_statement(report: ScanReport, report_sha256: str = "") -> str:
    """The statement as one HTML page that loads nothing and prints on one sheet."""
    kind, headline = _verdict(report)
    result = ratings.grade(report)
    tested = [KINDS[slot_kind] for slot_kind in KINDS if any(s.kind == slot_kind and s.judged_attempts > 0 for s in report.slots)]
    found = ratings.counts(report)
    body = [
        "<h1>BotSting scan statement</h1>",
        f'<p class="verdict {kind}">{_e(headline)}</p>',
        f"<p>{_e(result.text)} {_e(ratings.NOT_THE_BOT)}</p>",
    ]
    if report.inconclusive_reasons:
        body.append("<p>Why:</p><ul>" if report.status == "inconclusive" else "<p>Not everything could be tested:</p><ul>")
        body += [f"<li>{_e(reason)}</li>" for reason in report.inconclusive_reasons]
        body.append("</ul>")
    if found:
        body.append("<h2>What was proven</h2><ul>")
        body += [f"<li>{_e(count)} {_e(name)}</li>" for name, count in found.items()]
        body.append(f"</ul><p>Of these: {_e(report.breakdown())}.</p>")
    body.append("<h2>What was tested</h2>")
    if tested:
        body.append("<ul>" + "".join(f"<li>{_e(name)}</li>" for name in tested) + "</ul>")
    else:
        body.append("<p>Nothing was tested to an outcome in this scan.</p>")
    gaps = report.not_tested()
    if gaps:
        body.append("<h2>What was not tested</h2><ul>" + "".join(f"<li>{_e(gap)}</li>" for gap in gaps) + "</ul>")
    facts: list[tuple[str, str]] = [
        ("Bot tested", _e(report.target_config.get("origin") or report.target)),
        ("Scan finished", f"{_e(report.finished_at)} (UTC)"),
        ("Attacks tried", f"{_e(report.attacks_run)}, in {_e(report.messages_sent)} messages"),
        ("Replays of each finding", _e(report.reproduction_trials)),
        ("Tool version", f"BotSting {_e(report.tool_version)}"),
    ]
    if report.authorization.get("authorized_by"):
        facts.append(("Test authorized by", _e(report.authorization["authorized_by"])))
    if report.tester.strip():
        facts.append(("Tested by", _e(report.tester)))
    if report.stopped_early:
        facts.append(("Stopped early", _e(report.stopped_early)))
    if report_sha256:
        facts.append(("Full report (SHA-256)", f"<code>{_e(report_sha256)}</code>"))
    body.append("<h2>The scan</h2><dl>" + "".join(f"<dt>{name}</dt><dd>{value}</dd>" for name, value in facts) + "</dl>")
    body.append(f'<h2>What this statement is</h2><p class="note">{_e(WHAT_THIS_IS)}</p>')
    if report_sha256:
        body.append(
            '<p class="note">The full report holds every conversation and each replay. Whoever holds that file can compare its '
            "SHA-256 with the one above to see that this statement was made from it.</p>"
        )
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        '<meta name="referrer" content="no-referrer">'
        f"<title>BotSting scan statement: {_e(report.target)}</title>"
        f"<style>{_CSS}</style></head>\n<body><main>\n" + "\n".join(body) + "\n</main></body></html>\n"
    )


def run(args: argparse.Namespace) -> int:
    source = Path(args.report)
    try:
        raw = source.read_bytes()
        report = ScanReport.from_dict(json.loads(raw.decode("utf-8")))
    except OSError as error:
        print(f"error: could not read {source}: {error.strerror or error}")
        return EXIT_FAILED
    except (ValueError, KeyError, TypeError):
        print(f"error: {source} is not a BotSting scan report (the file a scan writes as scan.botsting.json)")
        return EXIT_FAILED
    out = Path(args.out) if args.out else source.with_name("statement.html")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_statement(report, fingerprint(raw)), encoding="utf-8")
    print(f"Scan statement written to {out.resolve()}")
    print("Open it in a browser; printing it from there gives a one-page PDF.")
    return EXIT_OK


def register(commands: Any) -> None:
    parser = commands.add_parser(
        "statement",
        help="make a one-page statement of a finished scan, to show to someone else",
        description="Make a one-page statement from a scan report: what was tested, what was found, what was not tested.",
    )
    parser.add_argument("report", nargs="?", default="reports/scan.botsting.json", help="the JSON report of a scan (default: reports/scan.botsting.json)")
    parser.add_argument("--out", help="where to write the page (default: statement.html beside the report)")
    parser.set_defaults(handler=run)
