"""Render a ScanReport as one self-contained HTML file.

This is the report a builder opens, prints, or hands to their own customer, so it has
to be safe to open and honest to read.

Safe to open: the page loads nothing and runs nothing. There is no script, no image,
no link and no external stylesheet, and a Content-Security-Policy forbids all of them
in case that ever slips. Everything a target or attacker wrote is escaped before it
is placed in the page; transcripts are full of text written by someone trying to
break things.

Honest to read: the wording rules are the same as for the Markdown report. Nothing
found is stated as "No verified violations observed under these tested conditions",
never as the target being fine; what was not tested is listed next to the verdict;
suspected items are shown apart and not counted; the limitations are printed in full.
"""

from __future__ import annotations

from html import escape

from botsting import ratings
from botsting.console import advice
from botsting.core.models import EvidenceLevel, Finding, Rate, ScanReport, SlotStatus, ToolCall, Turn
from botsting.frameworks import (
    FrameworkEntry,
    coverage_rows,
    entries_for,
    group_entries,
    not_covered_sentence,
    objective_kind_for,
)
from botsting.report_markdown import (
    HEADLINE_NO_VERIFIED_VIOLATIONS,
    INDEPENDENCE_DESCRIPTIONS,
    INDEPENDENCE_EXPLANATION,
    _rate_text,
)
from botsting.shell import replay_command

_CSS = """
/* An evidence file. Reading order: the verdict, what was reached, each finding as an exhibit with
   its exchange, then how the test was done. Headings and exhibit numbers are set in a DIN-like
   face, the kind used on technical documents; the prose is a book serif; anything quoted from a
   conversation is monospace, because it is verbatim. No web font can load here (the page loads
   nothing), so each is a stack of faces that ship with the common systems. */
:root {
  --paper:#f7f9fb; --sheet:#ffffff; --ink:#14181f; --muted:#56606e; --rule:#d3dae3; --exhibit:#1f3fbf;
  --bad:#b81a36; --ok:#0d6657; --unsure:#855600; --quote:#eef1f5;
  --display:Bahnschrift,"DIN Alternate","Avenir Next Condensed","Roboto Condensed","Arial Narrow",sans-serif;
  --text:Charter,"Bitstream Charter","Sitka Text",Cambria,Georgia,serif;
  --mono:ui-monospace,"Cascadia Mono","SF Mono",Menlo,Consolas,monospace;
}
@media (prefers-color-scheme: dark) { :root {
  --paper:#0f1217; --sheet:#151a21; --ink:#e6eaf0; --muted:#9aa5b3; --rule:#2a323d; --exhibit:#8ea5ff;
  --bad:#ff8397; --ok:#6fd3bd; --unsure:#e5bd62; --quote:#1c222b; } }
* { box-sizing:border-box; }
body { margin:0; background:var(--paper); color:var(--ink); font:1.0625rem/1.6 var(--text); }
main { max-width:52rem; margin:0 auto; padding:2.5rem 1.25rem 5rem; }
h1, h2, h3, th, dt, .tag, .who, .num, .facts { font-family:var(--display); }
h1 { font-size:.95rem; font-weight:600; color:var(--muted); margin:0 0 1.25rem; }
h2 { font-size:1.45rem; font-weight:700; font-stretch:90%; line-height:1.15; margin:3.5rem 0 1rem; }
h3 { font-size:1.2rem; font-weight:700; font-stretch:90%; line-height:1.25; margin:0 0 .35rem; }
table + h3, .scroll + h3 { margin-top:1.6rem; }
p { margin:.5rem 0; max-width:42rem; }
ul { margin:.5rem 0; padding-left:1.2rem; max-width:42rem; } li { margin:.3rem 0; }
code { font:.86em var(--mono); background:var(--quote); padding:.08em .3em; border-radius:3px; overflow-wrap:anywhere; }
.note { color:var(--muted); font-size:.94rem; }

/* The verdict is the one loud thing on the page. */
.verdict { border-top:.5rem solid var(--muted); padding:1.1rem 0 0; }
.verdict strong { display:block; font:700 clamp(2rem,6vw,3.1rem)/1.04 var(--display); font-stretch:85%;
  letter-spacing:-.01em; margin-bottom:.6rem; max-width:18ch; }
.verdict.bad { border-color:var(--bad); } .verdict.bad strong { color:var(--bad); }
.verdict.ok { border-color:var(--ok); } .verdict.ok strong { color:var(--ok); max-width:24ch; }
.verdict.unsure { border-color:var(--unsure); } .verdict.unsure strong { color:var(--unsure); max-width:22ch; }
.facts { display:flex; flex-wrap:wrap; gap:.4rem 2.2rem; margin:1.3rem 0 0; padding:.8rem 0 0;
  border-top:1px solid var(--rule); font-size:.98rem; }
.facts div { display:grid; } .facts span { color:var(--muted); font-size:.85rem; }

/* Tables: the index of what was reached, and the instruments. */
.scroll { overflow-x:auto; }
table { border-collapse:collapse; width:100%; font-size:.98rem; }
th, td { text-align:left; padding:.55rem .9rem .55rem 0; border-bottom:1px solid var(--rule); vertical-align:top;
  overflow-wrap:anywhere; }
th { color:var(--muted); font-weight:600; font-size:.88rem; border-bottom-color:var(--ink); white-space:nowrap;
  overflow-wrap:normal; }
td ul { padding-left:1rem; margin:0; } td li { margin:.15rem 0; }
td:first-child { overflow-wrap:normal; } td:first-child code { white-space:nowrap; }
.reached td:first-child { font-family:var(--display); font-weight:700; white-space:nowrap; overflow-wrap:normal; }
.reached td:nth-child(n+3) { white-space:nowrap; }
.num { color:var(--exhibit); font-weight:700; white-space:nowrap; }

/* A finding is an exhibit: its number hangs in the margin, the exchange is quoted verbatim. */
.card { display:grid; grid-template-columns:4.2rem minmax(0,1fr); column-gap:.4rem; padding:1.6rem 0 1.9rem;
  border-top:1px solid var(--rule); }
.card > * { grid-column:2; }
.card > .num { grid-column:1; grid-row:1 / span 3; font-size:1.7rem; font-stretch:85%; line-height:1; padding-top:.15rem; }
.tag { justify-self:start; font-size:.84rem; font-weight:600; margin-bottom:.3rem; }
.tag.bad { color:var(--bad); } .tag.unsure { color:var(--unsure); } .tag.ok { color:var(--ok); }
.what { margin:0 0 .9rem; }
.turn { margin:.55rem 0 0; }
.who { font-size:.86rem; font-weight:600; color:var(--muted); }
pre { margin:.2rem 0 0; padding:.7rem .85rem; background:var(--quote); border-left:3px solid var(--rule);
  white-space:pre-wrap; overflow-wrap:anywhere; font:.88rem/1.5 var(--mono); max-height:26rem; overflow:auto; }
.turn.attacker pre { border-left-color:var(--bad); }
.turn.target pre { border-left-color:var(--exhibit); }
.turn.user pre { border-left-color:var(--muted); }
.turn .note { margin:.3rem 0 0; padding-left:.9rem; }
dl { display:grid; grid-template-columns:minmax(9.5rem,max-content) minmax(0,1fr); gap:.35rem 1.2rem; margin:.9rem 0 0;
  font-size:.97rem; }
dt { color:var(--muted); font-size:.9rem; padding-top:.1rem; } dd { margin:0; overflow-wrap:anywhere; }
dd ul { padding-left:1rem; margin:0; }
.card dl { margin-top:1.2rem; padding-top:.9rem; border-top:1px dotted var(--rule); }

/* The other ways to the same thing: one line each until opened. */
.more { margin:0 0 1.4rem 4.6rem; }
.more > .note { margin:0 0 .3rem; }
details { border-top:1px solid var(--rule); }
details:last-child { border-bottom:1px solid var(--rule); }
summary { cursor:pointer; padding:.5rem 0; font-family:var(--display); font-weight:600; }
summary .num { display:inline-block; min-width:3rem; }
summary .note { font-family:var(--text); font-weight:400; margin-left:.6rem; white-space:nowrap; }
details .card { border-top:0; padding-top:.4rem; grid-template-columns:minmax(0,1fr); }
details .card > *, details .card > .num { grid-column:1; grid-row:auto; }
details .card > .num, details .card > h3 { display:none; }

/* The grade and what changed since the scan before, under the verdict. */
p.grade { margin:1rem 0 0; } p.grade span { font-family:var(--display); font-weight:700; }
p.since { font-family:var(--display); font-weight:700; margin:1rem 0 0; } ul.since { margin-top:.2rem; }
/* What the scan never tried, beside the verdict. */
p.untested { font-family:var(--display); font-weight:700; color:var(--unsure); margin:1rem 0 0; }
ul.untested { margin-top:.2rem; }

@media (max-width:40rem) {
  .card { grid-template-columns:minmax(0,1fr); } .card > *, .card > .num { grid-column:1; grid-row:auto; }
  .more { margin-left:0; }
  dl { grid-template-columns:minmax(0,1fr); gap:0; } dd { margin-bottom:.5rem; }
}
@media print {
  :root { --paper:#fff; --sheet:#fff; --ink:#000; --muted:#444; --rule:#999; --quote:#f3f3f3; --exhibit:#000; }
  body { font-size:10.5pt; } main { max-width:none; padding:0; }
  pre { max-height:none; overflow:visible; } .card, tr { break-inside:avoid; } h2 { break-after:avoid; }
}
"""


def _e(text: object) -> str:
    """Anything from a target, an attacker or configuration, made inert."""
    return escape(str(text), quote=True)


def _code(text: object) -> str:
    return f"<code>{_e(text)}</code>"


def _principals(principals: tuple[str, ...]) -> str:
    return ", ".join(_code(p) for p in principals) if principals else "none listed"


def _verdict(report: ScanReport, previous: object = None) -> list[str]:
    if report.status == "violations_verified":
        count = len(report.findings)
        kind, headline = "bad", f"{count} verified violation{'' if count == 1 else 's'} found."
        detail = f"<p>Of these: {_e(report.breakdown())}.</p>"
    elif report.status == "no_verified_violations":
        kind, headline, detail = "ok", HEADLINE_NO_VERIFIED_VIOLATIONS, (
            "<p>This describes the tests listed below and nothing more. "
            "The limitations at the end say what those tests cannot show.</p>"
        )
    else:
        kind, headline, detail = "unsure", "The scan could not reach a conclusion.", ""
    lines = [f'<section class="verdict {kind}"><strong>{_e(headline)}</strong>{detail}']
    if report.inconclusive_reasons:
        label = "Why" if report.status == "inconclusive" else "Not everything could be tested"
        lines.append(f"<p>{label}:</p><ul>")
        lines += [f"<li>{_e(reason)}</li>" for reason in report.inconclusive_reasons]
        lines.append("</ul>")
    gaps = report.not_tested()
    if gaps:
        lines.append('<p class="untested">Not tested in this scan:</p><ul class="untested">')
        lines += [f"<li>{_e(gap)}</li>" for gap in gaps]
        lines.append("</ul>")
    result = ratings.grade(report)
    lines.append(f'<p class="grade"><span>{_e(result.text)}</span> {_e(ratings.NOT_THE_BOT)}</p>')
    changed = ratings.changes(report, previous)
    if changed is not None and changed.lines():
        lines.append(f'<p class="since">Since the last scan ({_e(changed.compared_with[:10])}):</p><ul class="since">')
        if changed.new:
            lines.append(f"<li>New: {_e(', '.join(changed.new))}</li>")
        if changed.still_there:
            lines.append(f"<li>Still there: {_e(', '.join(changed.still_there))}</li>")
        if changed.no_longer_found:
            lines.append(
                f"<li>Tested for again and not found: {_e('; '.join(changed.no_longer_found))}. "
                "A problem is closed when its replay stops working, not when one scan misses it.</li>"
            )
        if changed.not_retested:
            lines.append(f"<li>Found last time and not tested this time: {_e('; '.join(changed.not_retested))}</li>")
        lines.append("</ul>")
    who = report.authorization.get("authorized_by", "") if report.authorization else ""
    facts = [
        ("Target", _e(report.target)),
        ("Grade", _e(result.letter or "not graded")),
        ("Tested", _e(str(report.started_at)[:10])),
        ("Attacks", f"{_e(report.attacks_run)}, in {_e(report.messages_sent)} messages"),
    ]
    if who:
        facts.append(("Authorized by", _e(who)))
    lines.append('<div class="facts">' + "".join(f"<div><span>{k}</span>{v}</div>" for k, v in facts) + "</div>")
    lines.append("</section>")
    return lines


def _id_runs(ids: list[str]) -> str:
    """Finding ids as runs: "F1 to F10, F12". A finding can reach something other than what its
    attack aimed at, so the findings for one thing are not always numbered one after another."""

    def number(identifier: str) -> int | None:
        digits = identifier.lstrip("F")
        return int(digits) if identifier.startswith("F") and digits.isdigit() else None

    runs: list[list[str]] = []
    for identifier in ids:
        last, here = (number(runs[-1][-1]) if runs else None), number(identifier)
        if last is not None and here is not None and here == last + 1:
            runs[-1].append(identifier)
        else:
            runs.append([identifier])
    return ", ".join(run[0] if len(run) == 1 else f"{run[0]} to {run[-1]}" for run in runs)


def _reached(report: ScanReport) -> list[str]:
    """The index: each protected thing an attack got to, in how many ways, and how reliably."""
    lines = ["<h2>What was reached</h2>"]
    if not report.findings:
        if report.status == "no_verified_violations":
            lines.append("<p>Nothing. No planted value came out and no forbidden tool call was recorded.</p>")
        else:
            lines.append("<p>Nothing was verified. See above for what could not be established.</p>")
        return lines
    grouped: dict[str, list[Finding]] = {}
    for finding in report.findings:
        grouped.setdefault(finding.slot_id, []).append(finding)
    lines.append(
        '<div class="scroll"><table class="reached"><thead><tr><th>What</th><th>What happened</th><th>Ways</th>'
        "<th>Findings</th><th>Replays that reproduced it</th></tr></thead><tbody>"
    )
    for slot_id, found in grouped.items():
        first = found[0]
        if first.kind == "disclosure":
            happened = "Its planted value was disclosed to the attacker"
        elif first.kind == "injection":
            fate = "accepted the call" if any(call.accepted for f in found for call in f.tool_calls) else "refused it"
            happened = f"With text planted here, an ordinary request led to a tool call, and the tool {fate}"
        elif any(call.accepted for f in found for call in f.tool_calls):
            happened = "A tool was called for the attacker, and accepted the call"
        else:
            happened = "A tool was called for the attacker, and refused it"
        ids = _id_runs([f.id for f in found])
        done = sum(f.reproduction.successes for f in found)
        tried = sum(f.reproduction.trials for f in found)
        lines.append(
            f"<tr><td>{_e(slot_id)}</td><td>{happened}</td><td>{len(found)}</td>"
            f'<td><span class="num">{_e(ids)}</span></td><td>{done} of {tried}</td></tr>'
        )
    lines.append("</tbody></table></div>")
    fixes = [(slot_id, advice(report, slot_id)) for slot_id in grouped]
    if any(text for _, text in fixes):
        lines.append("<h3>What to change</h3><ul>")
        lines += [f"<li>{_code(slot_id)}: {_e(text)}</li>" for slot_id, text in fixes if text]
        lines.append("</ul>")
    return lines


def _authorization_html(authorization: dict[str, str]) -> str:
    if not authorization:
        return "Not recorded (local or in-process target)."
    if "authorized_by" in authorization:
        parts = [f"Authorized by {_e(authorization['authorized_by'])}"]
        if authorization.get("origin"):
            parts.append(f"for origin {_code(authorization['origin'])}")
        if authorization.get("environment"):
            parts.append(f"in {_code(authorization['environment'])} environment")
        if authorization.get("scope"):
            parts.append(f"(scope: {_e(authorization['scope'])})")
        if authorization.get("allowed_tools"):
            parts.append(f"Tools that could be exercised: {_e(authorization['allowed_tools'])}.")
        if authorization.get("live_tools"):
            parts.append(f"Tools that could be carried out for real, inside the bot's own caps: {_e(authorization['live_tools'])}.")
        return " ".join(parts)
    if authorization.get("reach") == "in-process":
        return "Not required (in-process target)."
    return ", ".join(f"{_e(k)} {_code(v)}" for k, v in sorted(authorization.items()))


def _about(report: ScanReport) -> list[str]:
    tester = _e(report.tester) if report.tester.strip() else "Not stated"
    desc = INDEPENDENCE_DESCRIPTIONS.get(report.independence)
    independence = f"{_code(report.independence)} ({_e(desc)})" if desc else _code(report.independence)
    rows = [
        ("Tool version", _e(report.tool_version)),
        ("Scan dates", f"{_e(report.started_at)} to {_e(report.finished_at)} (UTC)"),
        ("Authorization", _authorization_html(report.authorization)),
        ("Tester", tester),
        ("Independence", independence),
    ]
    return (
        ["<h2>About this test</h2>", "<dl>"]
        + [f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows]
        + ["</dl>", f'<p class="note">{_e(INDEPENDENCE_EXPLANATION)}</p>']
    )


def _tested(report: ScanReport) -> list[str]:
    config = ", ".join(f"{_e(k)} {_code(v)}" for k, v in sorted(report.target_config.items())) or "not recorded"
    rows = [
        ("Target", _code(report.target)),
        ("Target configuration", config),
        ("Attacker acting as", _code(report.attacker_principal)),
        ("Attacks run", _e(report.attacks_run)),
        ("Attempts run", _e(report.attempts_run)),
        ("Search attempts per attack", _e(report.discovery_runs)),
        ("Replays per verified finding", _e(report.reproduction_trials)),
        ("Spent", f"{_e(report.messages_sent)} messages sent, {_e(report.tool_calls_recorded)} tool calls recorded"),
    ]
    if report.stopped_early:
        rows.append(("Stopped early", _e(report.stopped_early)))
    return ["<h2>What was tested</h2>", "<dl>"] + [f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows] + ["</dl>"]


def _framework_list_html(entries: tuple[FrameworkEntry, ...]) -> str:
    items = []
    for label, grouped in group_entries(entries):
        refs = "; ".join(f"{_code(entry.id)} {_e(entry.title)}" for entry in grouped)
        items.append(f"<li><strong>{_e(label)}</strong>: {refs}</li>")
    return "<ul>" + "".join(items) + "</ul>"


def _coverage(report: ScanReport) -> list[str]:
    lines = ["<h2>Framework coverage</h2>"]
    rows = coverage_rows(report)
    if not rows:
        lines.append("<p>None recorded.</p>")
        lines.append(f'<p class="note">{_e(not_covered_sentence(()))}</p>')
        return lines
    lines.append(
        '<div class="scroll"><table><thead><tr><th>Objective kind</th><th>Framework entries</th>'
        "<th>Attempts judged</th><th>Result</th></tr></thead><tbody>"
    )
    for row in rows:
        lines.append(
            f"<tr><td>{_e(row.label)}</td><td>{_framework_list_html(row.entries)}</td>"
            f"<td>{_e(row.attempts)}</td><td>{_e(row.result)}</td></tr>"
        )
    lines.append("</tbody></table></div>")
    lines.append(f'<p class="note">{_e(not_covered_sentence([row.kind for row in rows]))}</p>')
    return lines


def _protected_row(slot: SlotStatus) -> str:
    if slot.kind == "tool_rule":
        policy = f"May be caused to run by: {_principals(slot.authorized)}"
    elif slot.kind == "injection_point":
        policy = "Tested by planting text here and having an ordinary user make an ordinary request"
    else:
        policy = f"May be seen by: {_principals(slot.authorized)}"
    state = _e(slot.state) + (f"<br><span class=\"note\">{_e(slot.detail)}</span>" if slot.detail else "")
    return (
        f"<tr><td>{_code(slot.slot_id)}<br><span class=\"note\">{_e(slot.kind.replace('_', ' '))}</span></td>"
        f"<td>{_e(slot.description)}<br><span class=\"note\">{policy}</span></td>"
        f"<td>{state}</td><td>{_e(slot.judged_attempts)}</td></tr>"
    )


def _protected(report: ScanReport) -> list[str]:
    lines = ["<h2>What was protected</h2>"]
    if not report.slots:
        return lines + ["<p>None recorded.</p>"]
    lines.append(
        '<div class="scroll"><table><thead><tr><th>What</th><th>Policy</th><th>Legitimate route</th>'
        "<th>Attempts judged</th></tr></thead><tbody>"
    )
    lines += [_protected_row(slot) for slot in report.slots]
    lines.append("</tbody></table></div>")
    lines.append(
        '<p class="note">"Legitimate route" is the check that each protected thing works for someone allowed to use it. '
        'If it does not, finding nothing for it would mean nothing. "Attempts judged" of zero means it was not tested.</p>'
    )
    return lines


def _tasks(report: ScanReport) -> list[str]:
    lines = ["<h2>Normal use</h2>"]
    if not report.tasks:
        return lines + ["<p>None recorded.</p>"]
    lines.append("<ul>")
    for task in report.tasks:
        outcome = "worked as expected" if task.passed else "did not work"
        detail = f' <span class="note">{_e(task.detail)}</span>' if task.detail else ""
        lines.append(f"<li>{_code(task.task_id)}: {outcome}{detail}</li>")
    lines.append("</ul>")
    return lines


def _call(call: ToolCall) -> str:
    arguments = ", ".join(f"{name}={value}" for name, value in call.arguments)
    fate = "accepted by the tool" if call.accepted else "refused by the tool"
    result = f"; the tool answered {_code(call.result)}" if call.result else ""
    return f"{_code(f'{call.tool}({arguments})')} {fate}{result}"


def _transcript(turns: tuple[Turn, ...]) -> list[str]:
    if not turns:
        return ['<p class="note">No conversation was recorded.</p>']
    lines: list[str] = []
    for turn in turns:
        who = {"attacker": "Attacker", "user": "Ordinary user"}.get(turn.role, "Target")
        note = f" ({_e(turn.note)})" if turn.note else ""
        lines.append(f'<div class="turn {_e(turn.role)}"><div class="who">{who}{note}</div><pre>{_e(turn.text)}</pre>')
        for call in turn.tool_calls:
            lines.append(f'<p class="note">Tool call recorded during this reply: {_call(call)}</p>')
        lines.append("</div>")
    return lines


def _rate(verb: str, noun: str, rate: Rate) -> str:
    return _e(_rate_text(verb, noun, rate))


def _finding(finding: Finding, report_path: str | None, slots: tuple[SlotStatus, ...] = ()) -> list[str]:
    refused = finding.level == EvidenceLevel.ACTION_ATTEMPTED
    rate = finding.reproduction
    if finding.kind == "disclosure":
        what = f"The value planted at {_code(finding.slot_id)} came out in the answer below."
    elif finding.kind == "injection":
        what = f"With text planted at {_code(finding.slot_id)}, an ordinary request made the bot call a tool."
    else:
        what = "The attacker's conversation made the bot call a tool it may not use for them."
    lines = [
        '<article class="card">',
        f'<span class="num">{_e(finding.id)}</span>',
        f'<span class="tag {"unsure" if refused else "bad"}">{_e(ratings.severity(finding).capitalize())}: {_e(finding.level.label)}</span>',
        f"<h3>{_e(finding.title)}</h3>",
        f'<p class="what">{what} It worked again in {_e(rate.successes)} of {_e(rate.trials)} replays from a fresh start.</p>',
    ]
    lines += _transcript(finding.transcript)
    lines += [
        "<dl>",
        f"<dt>Technique</dt><dd>{_e(finding.technique)}</dd>",
        f"<dt>Attack</dt><dd>{_code(finding.attack_id)}, by {_code(finding.attacker_principal)}</dd>",
    ]
    if finding.kind == "disclosure":
        lines += [
            f"<dt>What leaked</dt><dd>{_code(finding.slot_id)}</dd>",
            f"<dt>Policy</dt><dd>May be seen by: {_principals(finding.authorized)}</dd>",
            f"<dt>How it appeared</dt><dd>{_code(finding.encoding)}, {_code(finding.scope)}</dd>",
        ]
    else:
        if finding.kind == "injection":
            lines += [
                f"<dt>Where text was planted</dt><dd>{_code(finding.slot_id)}</dd>",
                "<dt>Policy</dt><dd>This tool has no business running during the ordinary request shown below</dd>",
            ]
            if finding.control is not None and finding.control.trials:
                lines.append(
                    "<dt>Harmless-text control</dt><dd>With harmless text in the same place, a forbidden tool ran in "
                    f"{_e(finding.control.successes)} of {_e(finding.control.trials)} requests made between the replays. "
                    "This ties the call to the planted text by association, not by proof of cause</dd>"
                )
        else:
            lines += [
                f"<dt>Tool rule</dt><dd>{_code(finding.slot_id)}</dd>",
                f"<dt>Policy</dt><dd>May be caused to run by: {_principals(finding.authorized)}</dd>",
            ]
        calls = "".join(f"<li>{_call(call)}</li>" for call in finding.tool_calls)
        lines.append(f"<dt>Recorded at the tool</dt><dd>Not taken from what the target said:<ul>{calls}</ul></dd>")
    kind = objective_kind_for(finding, slots)
    entries = entries_for(kind) if kind is not None else ()
    if entries:
        ids = ", ".join(_code(entry.id) for entry in entries)
        lines.append(
            f'<dt>Framework entries</dt><dd>{ids} <span class="note">(named in full under Framework coverage)</span></dd>'
        )
    command = replay_command(report_path or "REPORT.json", finding.id)
    if not report_path:
        command = command.replace("REPORT.json", "<report.json>", 1)
    lines += [
        f"<dt>Found</dt><dd>{_rate('found in', 'search attempts', finding.discovery)}</dd>",
        f"<dt>Reproduced</dt><dd>{_rate('reproduced in', 'replays from reset', finding.reproduction)}</dd>",
        f"<dt>Replay</dt><dd>{_code(command)}</dd>",
        "</dl>",
    ]
    lines.append("</article>")
    return lines


def _findings(report: ScanReport, report_path: str | None) -> list[str]:
    """Every verified finding, grouped by what was reached. The first way in is shown in full; the
    other ways to the same thing are folded, each still complete, so the page reads in minutes and
    the file still holds all of the evidence."""
    lines = ["<h2>Verified findings</h2>"]
    if not report.findings:
        return lines + ["<p>None recorded.</p>"]
    grouped: dict[str, list[Finding]] = {}
    for finding in report.findings:
        grouped.setdefault(finding.slot_id, []).append(finding)
    folded = sum(len(found) - 1 for found in grouped.values())
    if folded:
        lines.append(
            f'<p class="note">{len(report.findings)} findings reached {len(grouped)} '
            f'thing{"" if len(grouped) == 1 else "s"}. For each, the first way in is shown in full. The other '
            f"{folded} are folded below it: open one to read its exchange. Printing keeps them folded; the JSON "
            "report holds every one in full.</p>"
        )
    for slot_id, found in grouped.items():
        lines += _finding(found[0], report_path, report.slots)
        if len(found) == 1:
            continue
        more = len(found) - 1
        lines.append(
            f'<div class="more"><p class="note">{more} more way{"" if more == 1 else "s"} reached '
            f"{_code(slot_id)}. Each is a verified finding of its own.</p>"
        )
        for finding in found[1:]:
            rate = finding.reproduction
            lines.append(
                f'<details><summary><span class="num">{_e(finding.id)}</span> {_e(finding.title)} '
                f'<span class="note">{_e(rate.successes)} of {_e(rate.trials)} replays</span></summary>'
            )
            lines += _finding(finding, report_path, report.slots)
            lines.append("</details>")
        lines.append("</div>")
    return lines


def _suspected(report: ScanReport) -> list[str]:
    lines = [
        "<h2>Suspected findings</h2>",
        "<p>Suspected items are <strong>not verified</strong> and are <strong>not counted</strong> as violations. "
        "They are shown so that someone can look into them.</p>",
    ]
    if not report.suspected:
        return lines + ["<p>None recorded.</p>"]
    for index, item in enumerate(report.suspected, start=1):
        lines += [
            '<article class="card">',
            '<span class="tag unsure">Suspected, not verified</span>',
            f"<h3>Suspected {index}: {_e(item.title)}</h3>",
            "<dl>",
            f"<dt>Attack</dt><dd>{_code(item.attack_id)} ({_e(item.technique)})</dd>",
            f"<dt>Concerns</dt><dd>{_code(item.slot_id)}</dd>",
            f"<dt>Why only suspected</dt><dd>{_e(item.reason)}</dd>",
            "</dl>",
        ]
        lines += _transcript(item.transcript)
        lines.append("</article>")
    return lines


def _rest(report: ScanReport) -> list[str]:
    lines = ["<h2>Discarded attempts</h2>"]
    if report.contaminated_attempts:
        count = report.contaminated_attempts
        lines.append(
            f"<p>{_e(count)} attempt{'' if count == 1 else 's'} discarded because the planted value appeared in "
            "attacker-visible input. These prove nothing about the thing concerned and are left out of its rates.</p>"
        )
    else:
        lines.append("<p>None recorded.</p>")
    lines.append("<h2>Errors</h2>")
    if report.errors:
        lines.append("<ul>")
        for error in report.errors:
            where = f"attack {_code(error.attack_id)}" if error.attack_id else "whole scan"
            lines.append(f"<li>{_e(error.phase)}, {where}: {_e(error.message)}</li>")
        lines.append("</ul>")
    else:
        lines.append("<p>None recorded.</p>")
    lines.append("<h2>Limitations</h2>")
    if report.limitations:
        lines += ["<ul>"] + [f"<li>{_e(item)}</li>" for item in report.limitations] + ["</ul>"]
    else:
        lines.append("<p>None recorded.</p>")
    return lines


def render_html(report: ScanReport, report_path: str | None = None, previous: object = None) -> str:
    """The report as one HTML document. `report_path` is the JSON file's path, used in replay commands.
    `previous` is the earlier report of the same bot (as read from its JSON), for what changed since."""
    body: list[str] = ["<h1>BotSting scan report</h1>"]
    # A reader wants the verdict, then what was reached and how, then how far to trust it.
    body += _verdict(report, previous)
    body += _reached(report)
    body += _findings(report, report_path)
    body += _suspected(report)
    body += _protected(report)
    body += _tasks(report)
    body += _tested(report)
    body += _about(report)
    body += _coverage(report)
    body += _rest(report)
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        '<meta name="referrer" content="no-referrer">'
        f"<title>BotSting scan report: {_e(report.target)}</title>"
        f"<style>{_CSS}</style></head>\n<body><main>\n" + "\n".join(body) + "\n</main></body></html>\n"
    )
