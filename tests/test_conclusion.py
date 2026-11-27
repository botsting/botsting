"""`botsting conclusion`: the one way a report leaves the machine, and only after the person answers."""

import argparse
import asyncio
import json

import httpx
import pytest

from botsting import conclusion
from botsting.attacks.library import default_attacks
from botsting.cli import main
from botsting.core.runner import ScanConfig, run_scan
from botsting.targets.registry import build_target


@pytest.fixture(scope="module")
def report_dict():
    target = build_target("toy:vulnerable")
    report = asyncio.run(run_scan(target, default_attacks(target), ScanConfig(reproduction_trials=1)))
    data = report.to_dict()
    data["authorization"] = {**data.get("authorization", {}), "authorized_by": "Dana Levi"}
    data["tester"] = "Dana Levi, Example Audit"
    return data


@pytest.fixture
def report_file(tmp_path, monkeypatch, report_dict):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(conclusion.URL_ENV, raising=False)
    path = tmp_path / "reports" / "scan.botsting.json"
    path.parent.mkdir()
    path.write_text(json.dumps(report_dict), encoding="utf-8")
    return path


REFERENCE = "202611-" + "ab" * 16


def service(seen: list, status: int = 200, answer: dict | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, json=answer if answer is not None else {"id": REFERENCE, "text": "Our conclusion.\nFix F1 first.", "kept": True})

    return httpx.MockTransport(handler)


def args(**changes):
    return argparse.Namespace(**{"report": "reports/scan.botsting.json", "without_conversations": False, "yes": False, "remove": None, **changes})


def test_nothing_is_sent_when_the_answer_is_not_yes(report_file, monkeypatch, capsys):
    seen: list = []
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    for typed in ("n", "no", "maybe", "w"):
        monkeypatch.setattr("builtins.input", lambda prompt, typed=typed: typed)
        assert conclusion.run(args(), service(seen)) == 0
        assert "Nothing was sent." in capsys.readouterr().out
    assert seen == []


def test_without_a_terminal_it_refuses_unless_told_yes(report_file, monkeypatch, capsys):
    seen: list = []
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert conclusion.run(args(), service(seen)) == 2
    printed = capsys.readouterr().out
    assert "Not sent: there is no terminal to ask at; add --yes" in printed and seen == []
    assert "This will send the report" in printed  # what would be sent is shown even then


@pytest.mark.parametrize("typed", ["", "y", "YES"])
def test_a_yes_or_enter_sends_it_to_botsting_and_prints_the_conclusion(report_file, monkeypatch, capsys, typed):
    seen: list = []
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: typed)
    assert conclusion.run(args(), service(seen)) == 0
    (request,) = seen
    assert str(request.url) == "https://api.botsting.com/conclusion" and request.method == "POST"
    sent = json.loads(request.content)
    assert sent["format"] == 1 and sent["conversations"] is True and sent["client"]["tool_version"]
    assert sent["report"]["status"] == "violations_verified" and sent["report"]["findings"][0]["transcript"]
    printed = capsys.readouterr().out
    assert "Our conclusion." in printed and f"botsting conclusion --remove {REFERENCE}" in printed
    assert (report_file.parent / "conclusion.txt").read_text(encoding="utf-8") == "Our conclusion.\nFix F1 first.\n"
    # Before the question, the person was told what goes and where, and how long it is kept.
    assert "It includes the conversations" in printed and "until you ask us to remove it" in printed
    assert "botsting.com/privacy" in printed and "180" not in printed


def test_names_are_removed_before_anything_is_sent(report_file, report_dict):
    seen: list = []
    assert conclusion.run(args(yes=True), service(seen)) == 0
    body = seen[0].content.decode("utf-8")
    assert "Dana Levi" not in body and "Example Audit" not in body
    sent = json.loads(body)["report"]
    assert sent["authorization"]["authorized_by"] == conclusion.REMOVED and sent["tester"] == conclusion.REMOVED
    assert report_dict["authorization"]["authorized_by"] == "Dana Levi"  # the file on disk is not touched
    assert "Dana Levi" in report_file.read_text(encoding="utf-8")


def test_without_conversations_no_message_reply_planted_text_or_tool_argument_leaves(report_file, report_dict, capsys):
    seen: list = []
    assert conclusion.run(args(yes=True, without_conversations=True), service(seen)) == 0
    sent = json.loads(seen[0].content)
    assert sent["conversations"] is False
    said = {turn["text"] for f in report_dict["findings"] for turn in f["transcript"] if turn["text"]}
    planted = {f["payload"] for f in report_dict["findings"] if f["payload"]}
    arguments = {value for f in report_dict["findings"] for call in f["tool_calls"] for _, value in call["arguments"]}
    assert said and planted and arguments, "the practice report has all three, or this test proves nothing"
    body = seen[0].content.decode("utf-8")
    for text in said | planted:
        assert json.dumps(text)[1:-1] not in body
    findings = sent["report"]["findings"]
    assert all(f["transcript"] == [] and f["frozen_turns"] == [] for f in findings)
    assert all(call["arguments"] == [] and call["result"] == "" for f in findings for call in f["tool_calls"])
    # What makes it a finding stays: which tool was called, the titles, the counts.
    assert {call["tool"] for f in findings for call in f["tool_calls"]} == {"issue_refund"}
    assert [f["title"] for f in findings] == [f["title"] for f in report_dict["findings"]]
    assert "The conversations are left out" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("content", "reason"),
    [("not json at all", "is not a JSON report"), ('{"hello": 1}', "is not a BotSting scan report"), ('{"tool_version":"1","status":"fine","slots":[],"findings":[],"attacks_run":0}', "is not a BotSting scan report")],
)
def test_a_file_that_is_not_a_report_is_not_sent(report_file, content, reason, capsys):
    report_file.write_text(content, encoding="utf-8")
    seen: list = []
    assert conclusion.run(args(yes=True), service(seen)) == 2
    assert reason in capsys.readouterr().out and seen == []


def test_a_missing_report_and_an_oversized_one_are_plain_errors(report_file, report_dict, monkeypatch, capsys):
    seen: list = []
    assert conclusion.run(args(yes=True, report="nowhere.json"), service(seen)) == 2
    assert "Not sent: could not read nowhere.json" in capsys.readouterr().out
    monkeypatch.setattr(conclusion, "MAX_BYTES", 1000)
    assert conclusion.run(args(yes=True), service(seen)) == 2
    assert "the limit is" in capsys.readouterr().out and seen == []


@pytest.mark.parametrize(
    ("status", "answer", "said"),
    [
        (429, {"error": "slow down"}, "too many reports"),
        (413, {"error": "too large"}, "--without-conversations"),
        (400, {"error": "that is not a report"}, "that is not a report"),
        (500, {}, "HTTP 500"),
        (200, {"id": "x"}, "did not return a conclusion"),
    ],
)
def test_what_the_service_can_answer_is_each_explained(report_file, status, answer, said, capsys):
    assert conclusion.run(args(yes=True), service([], status, answer)) == 2
    assert said in capsys.readouterr().out
    assert not (report_file.parent / "conclusion.txt").exists()


def test_the_service_being_unreachable_is_said_plainly(report_file, capsys):
    def down(request):
        raise httpx.ConnectError("no route")

    assert conclusion.run(args(yes=True), httpx.MockTransport(down)) == 2
    assert "No conclusion: could not reach api.botsting.com" in capsys.readouterr().out


def test_the_address_can_only_be_https_or_this_machine(report_file, monkeypatch, capsys):
    seen: list = []
    monkeypatch.setenv(conclusion.URL_ENV, "http://example.com/api/conclusion")
    assert conclusion.run(args(yes=True), service(seen)) == 2
    assert "must be an https address" in capsys.readouterr().out and seen == []
    monkeypatch.setenv(conclusion.URL_ENV, "http://127.0.0.1:8787/api/conclusion")
    assert conclusion.run(args(yes=True), service(seen)) == 0
    assert str(seen[0].url) == "http://127.0.0.1:8787/api/conclusion"


def test_the_command_is_on_the_command_line(report_file, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "n")
    assert main(["conclusion"]) == 0
    assert "Nothing was sent." in capsys.readouterr().out


def test_a_report_the_service_could_not_keep_still_gets_its_conclusion_and_no_removal_line(report_file, capsys):
    answer = {"id": "", "text": "Our conclusion.\nThis report was not kept.", "kept": False}
    assert conclusion.run(args(yes=True), service([], 200, answer)) == 0
    printed = capsys.readouterr().out
    assert "This report was not kept." in printed and "--remove" not in printed


def test_what_comes_back_cannot_recolour_or_move_the_terminal(report_file, capsys):
    answer = {"id": REFERENCE, "text": "Fine.\x1b[2J\x1b[31m red\x07\r\nNext line.\x7f"}
    assert conclusion.run(args(yes=True), service([], 200, answer)) == 0
    printed = capsys.readouterr().out
    assert "Fine.[2J[31m red\nNext line." in printed
    assert not any(ch in printed for ch in "\x1b\x07\r\x7f")
    assert (report_file.parent / "conclusion.txt").read_text(encoding="utf-8") == "Fine.[2J[31m red\nNext line.\n"


def test_a_report_is_removed_by_its_reference(report_file, capsys):
    seen: list = []
    answer = {"removed": True, "text": "The report with this reference is removed."}
    assert conclusion.run(args(remove=f"  {REFERENCE.upper()} "), service(seen, 200, answer)) == 0
    (request,) = seen
    assert str(request.url) == "https://api.botsting.com/delete" and json.loads(request.content) == {"id": REFERENCE}
    assert capsys.readouterr().out.strip() == "The report with this reference is removed."


@pytest.mark.parametrize(
    ("reference", "status", "answer", "said"),
    [
        ("r-123", 200, {}, "that is not a report reference"),
        ("../../etc/passwd", 200, {}, "that is not a report reference"),
        (REFERENCE, 429, {"error": "slow"}, "too many requests"),
        (REFERENCE, 500, {}, "did not confirm the removal (HTTP 500)"),
        (REFERENCE, 200, {"removed": True}, "did not confirm the removal"),
    ],
)
def test_a_removal_that_did_not_happen_is_said_plainly(report_file, reference, status, answer, said, capsys):
    seen: list = []
    assert conclusion.run(args(remove=reference), service(seen, status, answer)) == 2
    printed = capsys.readouterr().out
    assert printed.startswith("Not removed: ") and said in printed
    assert len(seen) == (0 if "not a report reference" in said else 1)


def test_the_removal_address_follows_the_one_reports_go_to(report_file, monkeypatch):
    seen: list = []
    monkeypatch.setenv(conclusion.URL_ENV, "http://127.0.0.1:8791/conclusion")
    assert conclusion.run(args(remove=REFERENCE), service(seen, 200, {"text": "Removed."})) == 0
    assert str(seen[0].url) == "http://127.0.0.1:8791/delete"


# The question at the end of a scan.


@pytest.fixture
def at_a_terminal(monkeypatch):
    # Not sys.stdout.isatty itself: pytest swaps sys.stdout between a test's set-up and its body.
    monkeypatch.setattr(conclusion, "_someone_is_there", lambda: True)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv(conclusion.OFF_ENV, raising=False)


@pytest.mark.parametrize("typed", ["", "y", "Yes"])
def test_at_the_end_of_a_scan_enter_sends_the_report_after_showing_what_goes(report_file, at_a_terminal, monkeypatch, capsys, typed):
    seen: list = []
    asked: list = []
    monkeypatch.setattr("builtins.input", lambda prompt: asked.append(prompt) or typed)
    assert conclusion.offer(report_file, service(seen)) is True
    assert asked == ["Send it? [Y/n], or w to send it without the conversations: "]
    assert json.loads(seen[0].content)["conversations"] is True
    printed = capsys.readouterr().out
    told, answered = printed.index("This will send the report"), printed.index("Our conclusion.")
    assert told < answered and "until you ask us to remove it" in printed[:answered] and "api.botsting.com" in printed[:answered]


def test_at_the_end_of_a_scan_w_sends_it_without_the_conversations(report_file, report_dict, at_a_terminal, monkeypatch):
    seen: list = []
    monkeypatch.setattr("builtins.input", lambda prompt: "w")
    assert conclusion.offer(report_file, service(seen)) is True
    sent = json.loads(seen[0].content)
    assert sent["conversations"] is False and all(f["transcript"] == [] for f in sent["report"]["findings"])


@pytest.mark.parametrize("typed", ["n", "no", "later", "q"])
def test_at_the_end_of_a_scan_any_other_answer_sends_nothing(report_file, at_a_terminal, monkeypatch, capsys, typed):
    seen: list = []
    monkeypatch.setattr("builtins.input", lambda prompt: typed)
    assert conclusion.offer(report_file, service(seen)) is False
    printed = capsys.readouterr().out
    assert seen == [] and "Nothing was sent." in printed and "BOTSTING_NO_CONCLUSION=1" in printed


def test_ctrl_c_at_the_question_sends_nothing(report_file, at_a_terminal, monkeypatch):
    seen: list = []

    def interrupted(prompt):
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", interrupted)
    assert conclusion.offer(report_file, service(seen)) is False and seen == []


@pytest.mark.parametrize("where", ["no input terminal", "no output terminal", "a pipeline", "switched off"])
def test_where_nobody_can_answer_the_question_is_not_asked_and_nothing_is_sent(report_file, at_a_terminal, monkeypatch, capsys, where):
    seen: list = []
    if where in ("no input terminal", "no output terminal"):
        monkeypatch.undo()
        monkeypatch.chdir(report_file.parent.parent)
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.delenv(conclusion.OFF_ENV, raising=False)
        monkeypatch.setattr("sys.stdin.isatty", lambda: where == "no output terminal")
        monkeypatch.setattr("sys.stdout.isatty", lambda: where == "no input terminal")
    elif where == "a pipeline":
        monkeypatch.setenv("CI", "true")
    else:
        monkeypatch.setenv(conclusion.OFF_ENV, "1")

    def must_not_ask(prompt):
        raise AssertionError("asked where nobody can answer")

    monkeypatch.setattr("builtins.input", must_not_ask)
    assert conclusion.offer(report_file, service(seen)) is False
    assert seen == [] and capsys.readouterr().out == ""


def test_a_service_that_is_down_never_spoils_the_end_of_a_scan(report_file, at_a_terminal, monkeypatch, capsys):
    def down(request):
        raise httpx.ConnectError("no route")

    monkeypatch.setattr("builtins.input", lambda prompt: "")
    assert conclusion.offer(report_file, httpx.MockTransport(down)) is False
    assert "Nothing came back: could not reach api.botsting.com" in capsys.readouterr().out

    def broken(prompt):
        raise RuntimeError("the terminal went away")

    monkeypatch.setattr("builtins.input", broken)
    assert conclusion.offer(report_file, service([])) is False
    assert "Nothing was sent (RuntimeError)." in capsys.readouterr().out


def test_only_a_scan_of_the_persons_own_bot_asks(tmp_path, at_a_terminal, monkeypatch, capsys):
    """A built-in practice bot is ours; its report teaches us nothing, so the question is not asked."""
    monkeypatch.chdir(tmp_path)

    def must_not_ask(prompt):
        raise AssertionError("asked after a scan of a practice bot")

    monkeypatch.setattr("builtins.input", must_not_ask)
    main(["scan", "--target", "toy:vulnerable", "--replays", "1", "--out", "reports/scan.botsting.json"])
    assert "Want BotSting's conclusion" not in capsys.readouterr().out
