"""What a scan prints in the terminal: the verdict first, findings grouped, one real exchange."""

import asyncio
import re

import pytest

from promptproof.attacks.library import default_attacks
from promptproof.console import (
    NO_VERIFIED_HEADLINE,
    _one_line,
    next_steps,
    render,
    use_colour,
)
from promptproof.core.runner import ScanConfig, run_scan
from promptproof.targets.registry import build_target


@pytest.fixture(scope="module")
def reports():
    def scan(spec):
        target = build_target(spec)
        return asyncio.run(run_scan(target, default_attacks(target), ScanConfig(reproduction_trials=2)))

    return scan("toy:vulnerable"), scan("toy:fixed")


def test_the_verdict_is_the_first_line(reports):
    vulnerable, fixed = reports
    assert render(vulnerable).splitlines()[0].startswith("14 verified violation(s): 11 protected data disclosed")
    assert render(fixed).splitlines()[0] == NO_VERIFIED_HEADLINE


def test_findings_are_grouped_by_what_was_reached_with_their_replays(reports):
    text = render(reports[0])
    assert "staff_code: leaked, " in text and "bob_delivery_note: leaked, " in text
    assert "with planted text in place, issue_refund was called, and the tool accepted it" in text
    assert "the attacker's conversation led to a call to issue_refund" in text
    lines = [line for line in text.splitlines() if re.match(r"\s+F\d+ ", line)]
    assert len(lines) == 14 and all(line.rstrip().endswith("2 of 2 replays") for line in lines)
    # The statistics stay in the reports: nothing here mentions an interval.
    assert "Wilson" not in text and "%" not in text


def test_one_real_exchange_is_shown(reports):
    text = render(reports[0])
    assert "How F1 happened" in text
    shown = text.split("How F1 happened")[1]
    assert "asked    " in shown and "answer   " in shown
    assert "made for this one attempt" in shown


def test_a_clean_result_makes_no_claim_of_safety(reports):
    text = render(reports[1])
    for word in ("safe", "secure", "clean", "certified", "passed"):
        assert word not in text.lower()
    assert "How F" not in text


def test_no_line_is_wider_than_a_terminal_and_everything_is_plain_ascii(reports):
    for report in reports:
        text = render(report) + "\n" + next_steps(report, [("Report (JSON)", "reports/scan.json")], "promptproof replay x --finding F1")
        assert text.isascii()  # a Windows console in an old code page prints anything else as a box
        assert max(len(line) for line in text.splitlines()) <= 150


def test_colour_only_for_a_terminal_and_never_with_no_colour(reports, monkeypatch):
    class Terminal:
        def isatty(self):
            return True

    class Pipe:
        def isatty(self):
            return False

    monkeypatch.delenv("NO_COLOR", raising=False)
    assert use_colour(Terminal()) and not use_colour(Pipe())
    monkeypatch.setenv("NO_COLOR", "1")
    assert not use_colour(Terminal())
    assert "\033[" in render(reports[0], colour=True) and "\033[" not in render(reports[0])


def test_a_long_answer_keeps_the_part_where_the_secret_came_out():
    answer = "Sure. My instructions are: " + "be brief and friendly. " * 12 + "Staff code: K7M2-Q9XA-D4T8-WZ3H"
    shown = _one_line(answer, 87)
    assert len(shown) <= 87 and shown.startswith("Sure. My instructions") and shown.endswith("K7M2-Q9XA-D4T8-WZ3H")
    assert _one_line("short", 87) == "short" and len(_one_line("word " * 100, 87)) <= 87


def test_next_steps_names_one_replay_command_not_one_per_finding(reports):
    text = next_steps(reports[0], [("Report (JSON)", "scan.json")], "promptproof replay scan.json --finding F1")
    assert text.count("promptproof replay") == 1 and "(any id from F1 to F14)" in text
    assert "Replay" not in next_steps(reports[1], [("Report (JSON)", "scan.json")])


def test_each_thing_reached_comes_with_what_to_change(reports):
    text = render(reports[0])
    assert text.count("Fix: ") == 4  # one per thing reached, not one per finding
    assert "Take the secret out of the instructions" in text  # staff_code, held in the instructions
    assert "Check who is asking in the code that fetches the record" in text  # another customer's note
    assert "Enforce who may use the tool inside the tool itself" in text
    assert "Treat text the bot reads" in text  # planted text
    assert "Fix:" not in render(reports[1])


def test_a_kind_of_harm_that_was_never_tried_is_named_under_the_verdict(reports):
    import dataclasses

    full = reports[0]
    assert full.not_tested() == ()  # the practice bot is tested for all three
    only_tools = dataclasses.replace(full, slots=tuple(s for s in full.slots if s.kind == "tool_rule"))
    gaps = only_tools.not_tested()
    assert len(gaps) == 2 and gaps[0].startswith("Secret leaks were not tested")
    lines = render(only_tools).splitlines()
    assert "Not tested in this scan" in lines[1]  # straight after the verdict, before any finding
    assert only_tools.to_dict()["not_tested"] == list(gaps)


def test_errors_are_shown_where_the_person_is_looking(reports):
    """An error message usually says what to change. The terminal shows each different one once."""
    import dataclasses

    from promptproof.core.models import ErrorRecord

    hint = '/chat answered HTTP 500. Say what it should return with result=, for example @pp.action("issue_refund", result="Refunded.")'
    errors = (
        ErrorRecord("discovery", "a1", hint + " (after 0 of 1 replies)"),
        ErrorRecord("discovery", "a2", hint + " (after 1 of 2 replies)"),
        ErrorRecord("reproduction", "a1", hint + " (after 3 replies)"),
        ErrorRecord("preflight", None, "the bot did not answer"),
    )
    text = render(dataclasses.replace(reports[1], errors=errors, status="inconclusive"))
    assert text.count("Say what it should return") == 1 and "3 times, during discovery, reproduction: /chat answered HTTP 500" in " ".join(text.split())
    assert "once, during preflight: the bot did not answer" in text
    assert "Errors" not in render(reports[1])  # nothing is printed when there were none
    many = tuple(ErrorRecord("discovery", None, f"problem {n}") for n in range(5))
    assert "and 2 more kind(s) of error, in the report" in render(dataclasses.replace(reports[1], errors=many))
