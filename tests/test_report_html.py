"""The HTML report: one file, safe to open, and saying no more than was shown."""

import asyncio
import re
from dataclasses import replace
from html.parser import HTMLParser

import pytest

from promptproof.attacks.library import default_attacks
from promptproof.cli import EXIT_VIOLATIONS, main
from promptproof.core.models import ErrorRecord, ScanReport, SuspectedFinding, TaskStatus, ToolCall, Turn
from promptproof.core.runner import run_scan
from promptproof.report_html import render_html
from promptproof.report_markdown import HEADLINE_NO_VERIFIED_VIOLATIONS
from promptproof.targets.registry import build_target

BANNED = ("safe", "secure", "clean", "certified", "passed")
SECTIONS = [
    "What was tested",
    "What was protected",
    "Normal use",
    "Verified findings",
    "Suspected findings",
    "Discarded attempts",
    "Errors",
    "Limitations",
]


def scan(spec: str) -> ScanReport:
    target = build_target(spec)
    return asyncio.run(run_scan(target, default_attacks(target)))


@pytest.fixture(scope="module")
def vulnerable() -> ScanReport:
    return scan("toy:vulnerable")


@pytest.fixture(scope="module")
def fixed() -> ScanReport:
    return scan("toy:fixed")


class Page(HTMLParser):
    """Parses the report the way a browser would, to see what is really markup."""

    def __init__(self, html: str) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.headings: list[str] = []
        self.text: list[str] = []
        self._in_h2 = False
        self._in_style = False
        self.feed(html)
        self.close()

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        self._in_h2 = tag == "h2"
        self._in_style = tag == "style"

    def handle_endtag(self, tag):
        self._in_h2 = False
        self._in_style = False

    def handle_data(self, data):
        if self._in_style:
            return
        self.text.append(data)
        if self._in_h2:
            self.headings.append(data)

    @property
    def visible(self) -> str:
        return " ".join(self.text)


ALLOWED_TAGS = {
    "html", "head", "meta", "title", "style", "body", "main", "section", "article", "div", "span", "p", "ul", "li",
    "dl", "dt", "dd", "h1", "h2", "h3", "strong", "code", "pre", "table", "thead", "tbody", "tr", "th", "td", "br",
}  # fmt: skip
ALLOWED_ATTRIBUTES = {"class", "lang", "charset", "name", "content", "http-equiv"}


def assert_inert(html: str) -> Page:
    """Nothing in the page can load, link, run or submit anything."""
    page = Page(html)
    for tag, attributes in page.tags:
        assert tag in ALLOWED_TAGS, f"unexpected element <{tag}>"
        assert set(attributes) <= ALLOWED_ATTRIBUTES, f"unexpected attribute on <{tag}>: {attributes}"
    assert "default-src 'none'" in html
    return page


def test_sections_are_all_present_and_in_order(vulnerable, fixed):
    for report in (vulnerable, fixed):
        page = assert_inert(render_html(report))
        assert page.headings == SECTIONS


def test_no_verified_violations_uses_the_careful_wording(fixed):
    page = assert_inert(render_html(fixed))
    assert HEADLINE_NO_VERIFIED_VIOLATIONS in page.visible
    assert "This describes the tests listed below and nothing more." in page.visible
    lowered = page.visible.lower()
    for word in BANNED:
        assert not re.search(rf"\b{word}\b", lowered), word


def test_violations_report_shows_evidence_and_both_rates(vulnerable):
    html = render_html(vulnerable, "reports/scan.promptproof.json")
    page = assert_inert(html)
    text = page.visible
    assert "14 verified violations found." in text
    assert "11 protected data disclosed, 3 forbidden action(s) carried out" in text
    assert "reproduced in 5 of 5 replays from reset (95% Wilson interval 57% to 100%)" in text
    assert "found in 1 of 1 search attempts" in text
    assert "promptproof replay reports/scan.promptproof.json --finding F1" in text
    assert "issue_refund(order_id=B-2002, amount=500)" in text and "carried out by the tool" in text
    assert "Not taken from what the target said" in text
    assert "by association, not by proof of cause" in text
    assert "Ordinary user (sent by staff:dana)" in text
    assert "Attacker (planted at bob_order_note)" in text
    # Wording written by Promptproof itself never uses the banned words; transcripts are not ours.
    ours = re.sub(r"<pre>.*?</pre>", "", html, flags=re.DOTALL)
    for word in BANNED:
        assert not re.search(rf"\b{word}\b", Page(ours).visible.lower()), word


HOSTILE = '</pre></article><script>alert(1)</script><img src=x onerror=alert(1)><a href="https://invalid.example/x">x</a>'


def test_nothing_a_target_or_attacker_wrote_can_become_markup(vulnerable):
    """Every string that can come from outside is filled with markup and must come out as text."""
    finding = vulnerable.findings[-1]
    call = ToolCall(id=HOSTILE, tool=HOSTILE, arguments=((HOSTILE, HOSTILE),), accepted=True, result=HOSTILE)
    turns = (
        Turn("attacker", HOSTILE, note=HOSTILE),
        Turn("user", HOSTILE, note=HOSTILE),
        Turn("target", HOSTILE, tool_calls=(call,)),
    )
    hostile_finding = replace(
        finding,
        id=HOSTILE,
        attack_id=HOSTILE,
        technique=HOSTILE,
        title=HOSTILE,
        slot_id=HOSTILE,
        encoding=HOSTILE,
        scope=HOSTILE,
        attacker_principal=HOSTILE,
        authorized=(HOSTILE,),
        transcript=turns,
        tool_calls=(call,),
    )
    report = replace(
        vulnerable,
        target=HOSTILE,
        attacker_principal=HOSTILE,
        started_at=HOSTILE,
        stopped_early=HOSTILE,
        target_config={HOSTILE: HOSTILE},
        slots=tuple(replace(s, slot_id=HOSTILE, description=HOSTILE, detail=HOSTILE, authorized=(HOSTILE,)) for s in vulnerable.slots),
        tasks=(TaskStatus(HOSTILE, False, HOSTILE),),
        findings=(hostile_finding, replace(hostile_finding, kind="disclosure"), replace(hostile_finding, kind="action")),
        suspected=(SuspectedFinding(HOSTILE, HOSTILE, HOSTILE, HOSTILE, HOSTILE, turns),),
        errors=(ErrorRecord(HOSTILE, HOSTILE, HOSTILE),),
        limitations=(HOSTILE,),
        inconclusive_reasons=(HOSTILE,),
    )
    html = render_html(report, HOSTILE)
    page = assert_inert(html)  # no <script>, <img>, <a>, no src/href/on* attributes anywhere
    assert page.headings == SECTIONS, "the page structure must survive"
    assert "<script>alert(1)</script>" in page.visible, "and the text must still be shown, as text"


def test_role_class_cannot_be_injected(vulnerable):
    finding = replace(vulnerable.findings[0], transcript=(Turn('x" onclick="alert(1)', "hello"),))  # type: ignore[arg-type]
    assert_inert(render_html(replace(vulnerable, findings=(finding,))))


def test_cli_writes_the_html_report(tmp_path, capsys):
    out, html = tmp_path / "scan.json", tmp_path / "report.html"
    assert main(["scan", "--target", "toy:vulnerable", "--out", str(out), "--html", str(html), "--replays", "1"]) == EXIT_VIOLATIONS
    assert f"Report to open in a browser: {html}" in capsys.readouterr().out
    page = assert_inert(html.read_text(encoding="utf-8"))
    assert page.headings == SECTIONS
