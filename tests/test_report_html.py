"""The HTML report: one file, safe to open, and saying no more than was shown."""

import asyncio
import re
from dataclasses import replace
from html.parser import HTMLParser

import pytest

from botsting.attacks.library import default_attacks
from botsting.cli import EXIT_VIOLATIONS, main
from botsting.core.models import ErrorRecord, ScanReport, SuspectedFinding, TaskStatus, ToolCall, Turn
from botsting.core.runner import run_scan
from botsting.report_html import render_html
from botsting.report_markdown import HEADLINE_NO_VERIFIED_VIOLATIONS, INDEPENDENCE_EXPLANATION
from botsting.targets.registry import build_target

BANNED = ("safe", "secure", "clean", "certified", "passed", "compliant")
# Reading order: the verdict (not a section), what was reached, each finding, then how far to trust it.
SECTIONS = [
    "What was reached",
    "Verified findings",
    "Suspected findings",
    "What was protected",
    "Normal use",
    "What was tested",
    "About this test",
    "Framework coverage",
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
    "details", "summary",  # folded findings: inert, and no script is needed to open them
}  # fmt: skip
ALLOWED_ATTRIBUTES = {"class", "lang", "charset", "name", "content", "http-equiv"}


EXPECTED_META = [
    {"charset": "utf-8"},
    {"name": "viewport", "content": "width=device-width, initial-scale=1"},
    {"http-equiv": "Content-Security-Policy", "content": "default-src 'none'; style-src 'unsafe-inline'"},
    {"name": "referrer", "content": "no-referrer"},
]


def assert_inert(html: str) -> Page:
    """Nothing in the page can load, link, run or submit anything."""
    page = Page(html)
    # A <meta> can redirect the page (refresh), so only the report's own four are allowed, exactly.
    assert [attributes for tag, attributes in page.tags if tag == "meta"] == EXPECTED_META
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
    html = render_html(vulnerable, "reports/scan.botsting.json")
    page = assert_inert(html)
    text = page.visible
    assert "14 verified violations found." in text
    assert "11 protected data disclosed, 3 forbidden action(s) accepted" in text
    assert "reproduced in 5 of 5 replays from reset (95% Wilson interval 57% to 100%)" in text
    assert "found in 1 of 1 search attempts" in text
    assert "botsting replay reports/scan.botsting.json --finding F1" in text
    assert "issue_refund(order_id=B-2002, amount=500)" in text and "accepted by the tool" in text
    assert "Not taken from what the target said" in text
    assert "by association, not by proof of cause" in text
    assert "Ordinary user (sent by staff:dana)" in text
    assert "Attacker (planted at bob_order_note)" in text
    # Wording written by BotSting itself never uses the banned words; transcripts are not ours.
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
        tester=HOSTILE,
        authorization={
            "authorized_by": HOSTILE,
            "origin": HOSTILE,
            "environment": HOSTILE,
            "scope": HOSTILE,
        },
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
    printed = capsys.readouterr().out
    assert "Report to open in a browser" in printed and str(html) in printed
    page = assert_inert(html.read_text(encoding="utf-8"))
    assert page.headings == SECTIONS


def test_a_report_file_with_markup_in_a_number_is_refused(vulnerable):
    """Review: a hand-edited count reached the HTML unescaped and could add a redirecting <meta>."""
    import json

    data = json.loads(json.dumps(vulnerable.to_dict()))
    hostile = '</p><meta http-equiv="refresh" content="0;url=https://invalid.example/"><p>'
    for field in ("contaminated_attempts", "attempts_run", "messages_sent"):
        with pytest.raises(ValueError, match=field):
            ScanReport.from_dict({**data, field: hostile})
    with pytest.raises(ValueError):
        ScanReport.from_dict({**data, "contaminated_attempts": True})
    bad_rate = json.loads(json.dumps(data))
    bad_rate["findings"][0]["reproduction"]["successes"] = hostile
    with pytest.raises(ValueError):
        ScanReport.from_dict(bad_rate)
    # And even if a bad value got into a report object, the page escapes it.
    page = assert_inert(render_html(replace(vulnerable, contaminated_attempts=hostile)))  # type: ignore[arg-type]
    assert hostile in page.visible


def test_html_includes_about_coverage_table_and_per_finding_frameworks(vulnerable, fixed):
    custom = replace(
        vulnerable,
        tester="Dana Levi, Example Audit",
        independence="third-party",
        authorization={
            "reach": "network",
            "origin": "https://staging.example.com",
            "authorized_by": "Dana Levi",
            "environment": "staging",
            "scope": "support bot",
        },
    )
    html = render_html(custom, "reports/scan.botsting.json")
    page = assert_inert(html)
    text = page.visible
    assert "About this test" in text
    assert "Dana Levi, Example Audit" in text
    assert "third-party" in text
    assert "Authorized by Dana Levi" in text
    assert "https://staging.example.com" in text
    assert INDEPENDENCE_EXPLANATION in text

    # Coverage table has all four exercised objective kinds and the non-coverage sentence.
    assert "Framework coverage" in text
    assert "Leak of an instruction secret" in text
    assert "Leak of another user's record" in text
    assert "Unauthorized tool action by direct request" in text
    assert "Unauthorized tool action through injected content" in text
    assert "proven finding" in text
    assert "This scan did not cover" in text

    # Per-finding framework entries appear inside finding cards.
    assert "Framework entries" in text
    assert "LLM08:2026" in text
    assert "ASI02" in text
    assert "AML.T0053" in text
    assert "MS-2.7-007" in text
    assert "B006" in text

    # Fixed report shows no verified violation and default tester/independence.
    fixed_page = assert_inert(render_html(fixed))
    assert "Not stated" in fixed_page.visible
    assert "self" in fixed_page.visible
    assert "no verified violation" in fixed_page.visible


def test_html_renders_old_report_json_without_new_fields(vulnerable):
    import json

    legacy = json.loads(json.dumps(vulnerable.to_dict()))
    legacy.pop("tester", None)
    legacy.pop("independence", None)
    legacy.pop("authorization", None)
    loaded = ScanReport.from_dict(legacy)
    assert loaded.tester == ""
    assert loaded.independence == "self"
    page = assert_inert(render_html(loaded))
    assert page.headings == SECTIONS
    assert "Not stated" in page.visible
    assert "Framework coverage" in page.visible


def test_generated_reports_never_contain_forbidden_framework_claims(vulnerable, fixed):
    from botsting.report_markdown import render_markdown

    inconclusive = replace(fixed, status="inconclusive", inconclusive_reasons=("Target stopped early.",))
    for report in (vulnerable, fixed, inconclusive):
        md = render_markdown(report)
        # Exclude transcripts (untrusted target/attacker words) when checking our own prose.
        md_outside = re.sub(r"```.*?```", "", md, flags=re.DOTALL)
        for word in ("compliant", "certified", "passed"):
            assert word not in md_outside.lower(), f"word {word!r} in markdown report"

        html = render_html(report)
        html_outside = re.sub(r"<pre>.*?</pre>", "", html, flags=re.DOTALL)
        visible_outside = Page(html_outside).visible.lower()
        for word in ("compliant", "certified", "passed"):
            assert word not in visible_outside, f"word {word!r} in html report"


def test_the_report_says_what_was_reached_and_what_to_change(vulnerable, fixed):
    text = assert_inert(render_html(vulnerable)).visible
    assert "Its planted value was disclosed to the attacker" in text
    assert "A tool was called for the attacker, and accepted the call" in text
    assert "What to change" in text and "Take the secret out of the instructions" in text
    clean = assert_inert(render_html(fixed)).visible
    assert "No planted value came out and no forbidden tool call was recorded." in clean
    assert "What to change" not in clean


def test_finding_ids_are_shown_as_runs_only_where_the_numbers_run_on():
    from botsting.report_html import _id_runs

    assert _id_runs(["F3"]) == "F3"
    assert _id_runs(["F1", "F2", "F3"]) == "F1 to F3"
    assert _id_runs(["F1", "F2", "F3", "F4", "F12"]) == "F1 to F4, F12"
    assert _id_runs(["F11", "F13", "F14"]) == "F11, F13 to F14"
