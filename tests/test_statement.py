"""The one-page scan statement: the outcome, the coverage and the limits, and nothing that is not in the report."""

import asyncio
import hashlib
import json
from dataclasses import replace
from html.parser import HTMLParser

import pytest

from botsting import ratings
from botsting.attacks.library import default_attacks
from botsting.cli import main
from botsting.core.models import ScanReport
from botsting.core.runner import ScanConfig, run_scan
from botsting.report_markdown import HEADLINE_NO_VERIFIED_VIOLATIONS
from botsting.reporting import write_reports
from botsting.statement import WHAT_THIS_IS, fingerprint, render_statement
from botsting.targets.registry import build_target

HOSTILE = '<script>alert(1)</script><img src=x onerror="go()">'


@pytest.fixture(scope="module")
def report() -> ScanReport:
    target = build_target("toy:vulnerable")
    found = asyncio.run(run_scan(target, default_attacks(target), ScanConfig(reproduction_trials=1)))
    assert found.findings
    return found


def text_of(page: str) -> str:
    """What a reader sees: the page without its markup and its style sheet."""

    class Reader(HTMLParser):
        def __init__(self) -> None:
            super().__init__()
            self.parts: list[str] = []
            self.skipping = False

        def handle_starttag(self, tag, attrs):
            self.skipping = self.skipping or tag in ("style", "title")

        def handle_endtag(self, tag):
            if tag in ("style", "title"):
                self.skipping = False

        def handle_data(self, data):
            if not self.skipping:
                self.parts.append(data)

    reader = Reader()
    reader.feed(page)
    return " ".join(" ".join(reader.parts).split())


def test_a_statement_of_a_scan_with_findings_says_how_many_and_how_serious(report):
    seen = text_of(render_statement(report, "ab" * 32))
    assert f"{len(report.findings)} verified violations found." in seen
    assert ratings.grade(report).text in seen and ratings.NOT_THE_BOT in seen
    for name, count in ratings.counts(report).items():
        assert f"{count} {name}" in seen
    assert report.breakdown() in seen and "What was tested" in seen
    assert f"{report.attacks_run}, in {report.messages_sent} messages" in seen and f"BotSting {report.tool_version}" in seen
    assert "ab" * 32 in seen and "compare its SHA-256" in seen
    assert WHAT_THIS_IS in seen and "It is not a certification of the bot." in seen


def test_a_statement_holds_no_conversation_and_no_planted_value(report):
    page = render_statement(report, "ab" * 32)
    for finding in report.findings:
        for turn in finding.transcript:
            if turn.text and len(turn.text) > 12:
                assert turn.text not in page
        assert not finding.payload or finding.payload not in page
        for call in finding.tool_calls:
            assert all(value not in page for _, value in call.arguments if len(value) > 6)


def test_a_statement_with_nothing_proven_never_reads_as_a_promise(report):
    quiet = replace(report, findings=(), status="no_verified_violations")
    seen = text_of(render_statement(quiet))
    assert HEADLINE_NO_VERIFIED_VIOLATIONS in seen and "What was proven" not in seen
    assert "it is not a statement that the bot is protected" in seen
    lowered = seen.lower()
    # "certification" appears once, in the sentence that says the page is not one.
    assert lowered.count("certif") == 1 and "not a certification" in lowered
    for word in ("safe", "secure", "clean", "passed", "guarantee"):
        assert word not in lowered, word


def test_what_was_not_tested_is_stated_as_plainly_as_what_was(report):
    partial = replace(report, findings=(), status="no_verified_violations", slots=tuple(s for s in report.slots if s.kind == "instruction_secret"))
    seen = text_of(render_statement(partial))
    assert "What was not tested" in seen
    for gap in partial.not_tested():
        assert gap in seen
    untried = replace(partial, slots=tuple(replace(s, judged_attempts=0) for s in partial.slots))
    assert "Nothing was tested to an outcome in this scan." in text_of(render_statement(untried))


def test_an_inconclusive_scan_is_stated_as_inconclusive_with_its_reasons(report):
    unsure = replace(report, findings=(), status="inconclusive", inconclusive_reasons=("the secret could not be fetched by its allowed route",))
    seen = text_of(render_statement(unsure))
    assert "The scan could not reach a conclusion." in seen and "Not graded: the scan was inconclusive" in seen
    assert "Why: the secret could not be fetched by its allowed route" in seen


def test_text_from_the_bot_or_the_person_cannot_become_markup(report):
    hostile = replace(
        report,
        target=HOSTILE,
        tester=HOSTILE,
        stopped_early=HOSTILE,
        authorization={"authorized_by": HOSTILE},
        target_config={"origin": HOSTILE},
        inconclusive_reasons=(HOSTILE,),
    )
    page = render_statement(hostile, "ab" * 32)
    assert "<script" not in page and "<img" not in page and "onerror=" not in page.replace("onerror=&quot;", "")
    assert page.count("&lt;script&gt;") >= 4
    assert "default-src 'none'" in page, "the page can load nothing"


def test_a_scan_writes_the_statement_with_the_fingerprint_of_its_own_report(report, tmp_path):
    out = tmp_path / "reports" / "scan.botsting.json"
    paths = write_reports(report, out, statement=tmp_path / "reports" / "statement.html")
    page = (tmp_path / "reports" / "statement.html").read_text(encoding="utf-8")
    written = hashlib.sha256(out.read_bytes()).hexdigest()
    assert written == fingerprint(out.read_bytes()) and written in page
    assert any(label.startswith("Scan statement") for label, _ in paths)


def test_the_statement_command_makes_one_from_an_existing_report(report, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    write_reports(report, tmp_path / "reports" / "scan.botsting.json")
    assert main(["statement"]) == 0
    printed = capsys.readouterr().out
    page = (tmp_path / "reports" / "statement.html").read_text(encoding="utf-8")
    assert "Scan statement written to" in printed and "one-page PDF" in printed
    assert hashlib.sha256((tmp_path / "reports" / "scan.botsting.json").read_bytes()).hexdigest() in page
    assert main(["statement", "reports/scan.botsting.json", "--out", "elsewhere/page.html"]) == 0
    assert (tmp_path / "elsewhere" / "page.html").exists()


@pytest.mark.parametrize(("content", "said"), [(None, "could not read"), ("not json", "is not a BotSting scan report"), (json.dumps({"hello": 1}), "is not a BotSting scan report")])
def test_the_statement_command_refuses_what_is_not_a_report(tmp_path, monkeypatch, capsys, content, said):
    monkeypatch.chdir(tmp_path)
    if content is not None:
        (tmp_path / "x.json").write_text(content, encoding="utf-8")
    assert main(["statement", "x.json"]) == 2
    assert said in capsys.readouterr().out and not (tmp_path / "statement.html").exists()


def test_the_scan_command_takes_the_statement_flag(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    main(["scan", "--target", "toy:vulnerable", "--replays", "1", "--out", "reports/scan.botsting.json", "--statement", "reports/statement.html"])
    assert "Scan statement" in capsys.readouterr().out and (tmp_path / "reports" / "statement.html").exists()
