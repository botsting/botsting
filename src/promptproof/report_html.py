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

from promptproof.core.models import EvidenceLevel, Finding, Rate, ScanReport, SlotStatus, ToolCall, Turn
from promptproof.frameworks import (
    FrameworkEntry,
    coverage_rows,
    entries_for,
    group_entries,
    not_covered_sentence,
    objective_kind_for,
)
from promptproof.report_markdown import (
    HEADLINE_NO_VERIFIED_VIOLATIONS,
    INDEPENDENCE_DESCRIPTIONS,
    INDEPENDENCE_EXPLANATION,
    _rate_text,
)
from promptproof.shell import replay_command

_CSS = """
:root { --bg:#f6f5f1; --card:#fff; --ink:#1c1b18; --muted:#66625a; --line:#dcd8cf; --bad:#a1260d; --badbg:#fbeee9;
  --ok:#2c5f4a; --okbg:#eaf3ee; --unsure:#7a5a00; --unsurebg:#fbf4dc; --code:#f0eee8; }
@media (prefers-color-scheme: dark) { :root { --bg:#161513; --card:#201f1c; --ink:#ece9e1; --muted:#a39e93;
  --line:#3a3833; --bad:#ff9d85; --badbg:#3a1d16; --ok:#8fd0b1; --okbg:#18301f; --unsure:#e8c766; --unsurebg:#332b10;
  --code:#2a2925; } }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--ink); font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif; }
main { max-width:60rem; margin:0 auto; padding:2rem 1rem 4rem; }
h1 { font-size:1.15rem; font-weight:600; color:var(--muted); margin:0 0 1rem; letter-spacing:.02em; }
h2 { font-size:1.2rem; margin:2.5rem 0 .75rem; padding-top:1rem; border-top:1px solid var(--line); }
h3 { font-size:1.05rem; margin:0 0 .5rem; }
p { margin:.5rem 0; }
.verdict { padding:1.25rem 1.5rem; border-radius:.5rem; border:1px solid var(--line); background:var(--card); }
.verdict strong { display:block; font-size:1.6rem; line-height:1.25; }
.verdict.bad { border-color:var(--bad); background:var(--badbg); } .verdict.bad strong { color:var(--bad); }
.verdict.ok { border-color:var(--ok); background:var(--okbg); } .verdict.ok strong { color:var(--ok); }
.verdict.unsure { border-color:var(--unsure); background:var(--unsurebg); } .verdict.unsure strong { color:var(--unsure); }
ul { margin:.5rem 0; padding-left:1.25rem; } li { margin:.25rem 0; }
dl { display:grid; grid-template-columns:minmax(9rem,max-content) 1fr; gap:.3rem 1rem; margin:.5rem 0; }
dt { color:var(--muted); } dd { margin:0; overflow-wrap:anywhere; }
code { background:var(--code); padding:.1rem .3rem; border-radius:.25rem; font:0.9em ui-monospace,Consolas,monospace;
  overflow-wrap:anywhere; }
.card { background:var(--card); border:1px solid var(--line); border-radius:.5rem; padding:1rem 1.25rem; margin:1rem 0; }
.tag { display:inline-block; font-size:.8rem; font-weight:600; padding:.1rem .5rem; border-radius:1rem;
  border:1px solid currentColor; margin-bottom:.5rem; }
.tag.bad { color:var(--bad); } .tag.unsure { color:var(--unsure); } .tag.ok { color:var(--ok); }
.turn { margin:.75rem 0; } .who { font-size:.85rem; font-weight:600; color:var(--muted); }
pre { margin:.25rem 0 0; padding:.75rem; background:var(--code); border-radius:.375rem; white-space:pre-wrap;
  overflow-wrap:anywhere; font:0.9rem/1.45 ui-monospace,Consolas,monospace; max-height:28rem; overflow:auto; }
.turn.attacker pre { border-left:3px solid var(--bad); } .turn.target pre { border-left:3px solid var(--muted); }
.turn.user pre { border-left:3px solid var(--ok); }
.note { color:var(--muted); font-size:.9rem; }
table { border-collapse:collapse; width:100%; } th,td { text-align:left; padding:.4rem .6rem; border-bottom:1px solid var(--line);
  vertical-align:top; overflow-wrap:anywhere; } th { color:var(--muted); font-weight:600; font-size:.9rem; }
.scroll { overflow-x:auto; }
@media print { body { background:#fff; } pre { max-height:none; } .card { break-inside:avoid; } }
"""


def _e(text: object) -> str:
    """Anything from a target, an attacker or configuration, made inert."""
    return escape(str(text), quote=True)


def _code(text: object) -> str:
    return f"<code>{_e(text)}</code>"


def _principals(principals: tuple[str, ...]) -> str:
    return ", ".join(_code(p) for p in principals) if principals else "none listed"


def _verdict(report: ScanReport) -> list[str]:
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
    lines.append("</section>")
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
    fate = "carried out by the tool" if call.accepted else "refused by the tool"
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
    lines = [
        '<article class="card">',
        f'<span class="tag {"unsure" if refused else "bad"}">{_e(finding.level.label)}</span>',
        f"<h3>{_e(finding.id)}: {_e(finding.title)}</h3>",
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
        lines.append(f"<dt>Framework entries</dt><dd>{_framework_list_html(entries)}</dd>")
    command = replay_command(report_path or "REPORT.json", finding.id)
    if not report_path:
        command = command.replace("REPORT.json", "<report.json>", 1)
    lines += [
        f"<dt>Found</dt><dd>{_rate('found in', 'search attempts', finding.discovery)}</dd>",
        f"<dt>Reproduced</dt><dd>{_rate('reproduced in', 'replays from reset', finding.reproduction)}</dd>",
        f"<dt>Replay</dt><dd>{_code(command)}</dd>",
        "</dl>",
    ]
    lines += _transcript(finding.transcript)
    lines.append("</article>")
    return lines


def _findings(report: ScanReport, report_path: str | None) -> list[str]:
    lines = ["<h2>Verified findings</h2>"]
    if not report.findings:
        return lines + ["<p>None recorded.</p>"]
    for finding in report.findings:
        lines += _finding(finding, report_path, report.slots)
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


def render_html(report: ScanReport, report_path: str | None = None) -> str:
    """The report as one HTML document. `report_path` is the JSON file's path, used in replay commands."""
    body: list[str] = ["<h1>Promptproof scan report</h1>"]
    body += _verdict(report)
    body += _about(report)
    body += _tested(report)
    body += _coverage(report)
    body += _protected(report)
    body += _tasks(report)
    body += _findings(report, report_path)
    body += _suspected(report)
    body += _rest(report)
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        '<meta name="referrer" content="no-referrer">'
        f"<title>Promptproof scan report: {_e(report.target)}</title>"
        f"<style>{_CSS}</style></head>\n<body><main>\n" + "\n".join(body) + "\n</main></body></html>\n"
    )
