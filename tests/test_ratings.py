"""Severity, the grade, what changed since the last scan, and the SARIF export: all worked out from a report by fixed rules."""

import asyncio
import json
from dataclasses import replace

import pytest

from botsting import ratings
from botsting.attacks.library import default_attacks
from botsting.cli import main
from botsting.core.models import EvidenceLevel, ScanReport
from botsting.core.runner import ScanConfig, run_scan
from botsting.reporting import earlier_report, with_ratings, write_reports
from botsting.targets.registry import build_target


@pytest.fixture(scope="module")
def report() -> ScanReport:
    target = build_target("toy:vulnerable")
    found = asyncio.run(run_scan(target, default_attacks(target), ScanConfig(reproduction_trials=1)))
    assert found.findings, "the practice bot has findings, or these tests prove nothing"
    return found


def at_level(report: ScanReport, level: EvidenceLevel) -> ScanReport:
    return replace(report, findings=tuple(replace(f, level=level) for f in report.findings[:2]))


def clean(report: ScanReport, **changes) -> ScanReport:
    return replace(report, findings=(), status="no_verified_violations", **changes)


def test_severity_follows_from_what_was_proven(report):
    by_level = {
        EvidenceLevel.DISCLOSED: "high",
        EvidenceLevel.ACTION_ATTEMPTED: "medium",
        EvidenceLevel.ACTION_ACCEPTED: "critical",
        EvidenceLevel.STATE_VERIFIED: "critical",
    }
    for level, expected in by_level.items():
        assert ratings.severity(replace(report.findings[0], level=level)) == expected
    mixed = replace(
        report,
        findings=(
            replace(report.findings[0], level=EvidenceLevel.ACTION_ATTEMPTED),
            replace(report.findings[0], level=EvidenceLevel.ACTION_ACCEPTED),
            replace(report.findings[0], level=EvidenceLevel.DISCLOSED),
            replace(report.findings[0], level=EvidenceLevel.DISCLOSED),
        ),
    )
    assert list(ratings.counts(mixed).items()) == [("critical", 1), ("high", 2), ("medium", 1)]
    assert ratings.counts(clean(report)) == {}


def test_the_grade_is_set_by_the_most_serious_finding(report):
    assert ratings.grade(at_level(report, EvidenceLevel.ACTION_ACCEPTED)).letter == "F"
    assert ratings.grade(at_level(report, EvidenceLevel.DISCLOSED)).letter == "D"
    assert ratings.grade(at_level(report, EvidenceLevel.ACTION_ATTEMPTED)).letter == "C"
    worst_wins = replace(
        report,
        findings=(
            replace(report.findings[0], level=EvidenceLevel.ACTION_ATTEMPTED),
            replace(report.findings[0], level=EvidenceLevel.ACTION_ACCEPTED),
        ),
    )
    assert ratings.grade(worst_wins).letter == "F"


def test_a_scan_with_nothing_proven_gets_an_a_only_when_everything_was_tested(report):
    full = clean(report)
    if full.not_tested():
        assert ratings.grade(full).letter == "B" and "not tested" in ratings.grade(full).reason
    else:
        assert ratings.grade(full).letter == "A"
        assert ratings.grade(clean(report, attacks_run=3)).letter == "B"
        assert "only 3 attack(s) ran" in ratings.grade(clean(report, attacks_run=3)).reason
    untested = clean(report, slots=tuple(s for s in report.slots if s.kind == "instruction_secret"))
    assert untested.not_tested() and ratings.grade(untested).letter == "B"


def test_an_inconclusive_scan_is_never_graded(report):
    for findings in ((), report.findings):
        unsure = replace(report, findings=findings, status="inconclusive", inconclusive_reasons=("the secret could not be fetched",))
        result = ratings.grade(unsure)
        assert result.letter == "" and result.text.startswith("Not graded: the scan was inconclusive")


def test_a_grade_always_says_it_is_about_the_scan_and_never_uses_the_word_safe(report):
    for case in (report, clean(report), at_level(report, EvidenceLevel.ACTION_ATTEMPTED)):
        written = ratings.grade(case).to_dict()
        assert written["note"] == ratings.NOT_THE_BOT and "not a statement that the bot is protected" in written["note"]
        assert not any(word in (written["reason"] + written["note"]).lower() for word in ("safe", "secure", "clean", "certified", "passed"))


def test_changes_since_the_last_scan(report):
    before = report.to_dict()
    assert ratings.changes(report, before).to_dict() == {
        "compared_with": report.finished_at,
        "new": [],
        "still_there": [f.id for f in report.findings],
        "no_longer_found": [],
        "not_retested": [],
    }
    # One finding was not there before, and one that was there is gone.
    gone = {**before["findings"][0], "attack_id": "an-attack-that-worked-last-time", "title": "An older way in"}
    earlier = {**before, "findings": [*before["findings"][1:], gone]}
    changed = ratings.changes(report, earlier)
    assert changed.new == (report.findings[0].id,) and changed.no_longer_found == ("An older way in",)
    assert changed.still_there == tuple(f.id for f in report.findings[1:]) and changed.not_retested == ()
    said = "\n".join(changed.lines())
    assert "No longer found since the last scan: 1 (An older way in)" in said and f"New since the last scan: {report.findings[0].id}" in said
    assert "A problem is closed when its replay stops working" in said


def test_a_finding_whose_place_was_not_tested_again_is_not_called_gone(report):
    before = report.to_dict()
    slot = report.findings[0].slot_id
    this_time = clean(report, slots=tuple(replace(s, judged_attempts=0) if s.slot_id == slot else s for s in report.slots))
    changed = ratings.changes(this_time, before)
    lost = [f.title for f in report.findings if f.slot_id == slot]
    assert set(changed.not_retested) == set(lost) and not set(changed.no_longer_found) & set(lost)
    assert "Found last time and not tested this time" in "\n".join(changed.lines())


@pytest.mark.parametrize("previous", [None, "text", [], {}, {"target": "toy:vulnerable"}, {"target": "toy:vulnerable", "findings": "many"}, {"target": "toy:vulnerable", "findings": [1]}])
def test_nothing_to_compare_with_is_not_an_error(report, previous):
    assert ratings.changes(report, previous) is None


def test_a_report_of_another_bot_is_not_compared(report):
    assert ratings.changes(report, {**report.to_dict(), "target": "http:another-bot"}) is None


def test_sarif_has_one_result_for_each_finding_and_one_rule_for_each_kind(report):
    out = ratings.sarif(report)
    assert out["version"] == "2.1.0" and len(out["runs"]) == 1
    run = out["runs"][0]
    assert run["tool"]["driver"]["name"] == "BotSting" and run["tool"]["driver"]["version"] == report.tool_version
    kinds = {slot.slot_id: slot.kind for slot in report.slots}
    assert [r["ruleId"] for r in run["results"]] == [f"botsting/{kinds[f.slot_id]}" for f in report.findings]
    assert {rule["id"] for rule in run["tool"]["driver"]["rules"]} == {r["ruleId"] for r in run["results"]}
    for finding, result in zip(report.findings, run["results"], strict=True):
        level = ratings.severity(finding)
        assert result["level"] == ("warning" if level == "medium" else "error")
        assert result["properties"]["severity"] == level and float(result["properties"]["security-severity"]) > 0
        assert finding.id in result["message"]["text"] and result["partialFingerprints"]["botsting/v1"] == f"{finding.slot_id}:{finding.attack_id}"
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "botsting.targets.json"
    # No conversation, canary or tool argument is copied into the export.
    text = json.dumps(out)
    assert not any(turn.text and turn.text in text for f in report.findings for turn in f.transcript)
    assert ratings.sarif(clean(report))["runs"][0]["results"] == []


def test_the_json_report_carries_the_ratings_and_can_still_be_read_back(report, tmp_path):
    out = tmp_path / "reports" / "scan.botsting.json"
    assert earlier_report(out) is None
    write_reports(report, out, sarif=tmp_path / "reports" / "scan.sarif")
    first = json.loads(out.read_text(encoding="utf-8"))
    assert first["grade"]["letter"] == ratings.grade(report).letter and "changes" not in first
    assert [f["severity"] for f in first["findings"]] == [ratings.severity(f) for f in report.findings]
    assert json.loads((tmp_path / "reports" / "scan.sarif").read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert ScanReport.from_dict(first) == report, "what is added for the reader does not get in the way of reading it back"
    # The same scan again: now there is a scan before it to compare with.
    write_reports(report, out)
    second = json.loads(out.read_text(encoding="utf-8"))
    assert second["changes"]["still_there"] == [f.id for f in report.findings] and second["changes"]["new"] == []
    assert with_ratings(report)["grade"] == first["grade"]


def test_the_command_line_prints_the_grade_and_what_changed(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    arguments = ["scan", "--target", "toy:vulnerable", "--replays", "1", "--out", "reports/scan.botsting.json", "--sarif", "reports/scan.sarif"]
    main(arguments)
    first = capsys.readouterr().out
    assert "Grade " in first and ratings.NOT_THE_BOT in first and "since the last scan" not in first
    assert (tmp_path / "reports" / "scan.sarif").exists() and "SARIF" in first
    main(arguments)
    assert "Still there since the last scan: F1" in capsys.readouterr().out


def test_the_browser_and_readable_reports_show_the_grade_and_each_severity(report):
    from botsting.report_html import render_html
    from botsting.report_markdown import render_markdown

    page, text = render_html(report), render_markdown(report)
    result = ratings.grade(report)
    for rendered in (page, text):
        assert result.text.replace("'", "&#x27;") in rendered or result.text in rendered
        assert ratings.NOT_THE_BOT in rendered and "Since the last scan" not in rendered
    assert f"<div><span>Grade</span>{result.letter}</div>" in page
    for finding in report.findings:
        assert f"{ratings.severity(finding).capitalize()}: {finding.level.label}" in page
    assert text.count("- Severity: ") == len(report.findings)
    unsure = replace(report, findings=(), status="inconclusive", inconclusive_reasons=("the secret could not be fetched",))
    assert "<div><span>Grade</span>not graded</div>" in render_html(unsure) and "Not graded: the scan was inconclusive" in render_markdown(unsure)


def test_the_reports_say_what_changed_since_the_scan_before(report, tmp_path):
    from botsting.report_html import render_html
    from botsting.report_markdown import render_markdown

    before = report.to_dict()
    gone = {**before["findings"][0], "attack_id": "an-attack-that-worked-last-time", "title": "An older <way> in"}
    earlier = {**before, "findings": [*before["findings"][1:], gone]}
    page, text = render_html(report, None, earlier), render_markdown(report, None, earlier)
    day = report.finished_at[:10]
    assert f"Since the last scan ({day}):" in page and f"Since the last scan ({day}):" in text
    assert f"<li>New: {report.findings[0].id}</li>" in page
    assert "Tested for again and not found: An older &lt;way&gt; in." in page, "a title from an old report is shown as text, never as markup"
    assert "A problem is closed when its replay stops working" in page and "A problem is closed when its replay stops working" in text
    # Written by a scan: the second scan to the same place carries the comparison into all three files.
    out = tmp_path / "scan.botsting.json"
    for _ in range(2):
        write_reports(report, out, tmp_path / "report.md", tmp_path / "report.html")
    assert "Since the last scan" in (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "Still there since the last scan" in (tmp_path / "report.md").read_text(encoding="utf-8")
