"""`kritalon mcp`: what a coding assistant can and cannot do through it."""

import io
import json
import subprocess
import sys
from datetime import UTC, datetime

import pytest

from kritalon.cli import main
from kritalon.core.authorization import AuthorizationStore, new_authorization
from kritalon.mcp_server import GUIDE, TOOLS, handle, serve


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


def call(root, tool, /, **arguments):
    reply = handle(root, {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": tool, "arguments": arguments}})
    assert reply["id"] == 7
    return reply["result"]["content"][0]["text"], reply["result"]["isError"]


# -- the protocol -----------------------------------------------------------------------------


def test_the_handshake_and_the_tool_list(project):
    reply = handle(project, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}})
    assert reply["result"]["protocolVersion"] == "2025-03-26" and reply["result"]["capabilities"] == {"tools": {}}
    newer = handle(project, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2099-01-01"}})
    assert newer["result"]["protocolVersion"] == "2025-06-18"
    assert handle(project, {"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert handle(project, {"jsonrpc": "2.0", "id": 2, "method": "ping"})["result"] == {}
    listed = handle(project, {"jsonrpc": "2.0", "id": 3, "method": "tools/list"})["result"]["tools"]
    assert [tool["name"] for tool in listed] == list(TOOLS)
    assert all(tool["inputSchema"]["type"] == "object" and tool["description"] for tool in listed)
    assert handle(project, {"jsonrpc": "2.0", "id": 4, "method": "resources/list"})["error"]["code"] == -32601
    assert handle(project, ["not", "a", "request"])["error"]["code"] == -32600


def test_there_is_no_tool_that_authorizes():
    """Permission to test is a person's to give. No tool here may record it."""
    assert not any("authorize" in name and name != "authorization_status" for name in TOOLS)
    from pathlib import Path

    import kritalon.mcp_server as server

    text = Path(server.__file__).read_text(encoding="utf-8")
    assert "new_authorization" not in text and ".add(" not in text and "mark_verified" not in text


def test_one_message_per_line_and_nothing_else_on_the_channel(project):
    lines = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
        "this is not json",
        "",
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "scan", "arguments": {"target": "toy:fixed", "replays": 1}}}),
    ]
    out = io.StringIO()
    serve(project, io.StringIO("\n".join(lines) + "\n"), out)
    replies = [json.loads(line) for line in out.getvalue().splitlines()]  # every line is one JSON message
    assert [r.get("id") for r in replies] == [1, None, 2] and replies[1]["error"]["code"] == -32700
    text = replies[2]["result"]["content"][0]["text"]
    assert "no verified violations" in text.lower() and "Reports are in kritalon-report/" in text


def test_it_runs_as_a_real_process(project):
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "setup_guide", "arguments": {}}})
    done = subprocess.run(
        [sys.executable, "-m", "kritalon.cli", "mcp"], check=True, input=request + "\n", capture_output=True, text=True,
        encoding="utf-8", timeout=60, cwd=project,
    )  # fmt: skip
    (line,) = done.stdout.splitlines()
    assert json.loads(line)["result"]["content"][0]["text"] == GUIDE


# -- the tools --------------------------------------------------------------------------------


def test_scanning_the_practice_bot_and_reading_the_report(project):
    text, failed = call(project, "scan", target="toy:vulnerable", replays=1)
    assert not failed and "verified violation" in text
    report, failed = call(project, "read_report")
    assert not failed and "verified violations found" in report
    again, failed = call(project, "scan", target="toy:vulnerable", replays=1)
    assert failed and "not empty" in again  # old evidence is never mixed in, and no success is claimed
    assert "did not run" in again and "Reports are in" not in again


def test_a_real_target_is_refused_without_a_persons_authorization(project):
    (project / "kritalon.targets.json").write_text(json.dumps({"targets": {"staging": DESCRIPTION}}), encoding="utf-8")
    text, failed = call(project, "scan", target="http:staging", replays=1, dir="first")
    assert failed and "no authorization" in text.lower() and "NOT RUN" in text and "Reports are in" not in text
    status, failed = call(project, "authorization_status", origin="https://staging.example.com")
    assert not failed and "No authorization on record" in status and "Only a person can authorize" in status


def test_authorization_status_reads_what_a_person_recorded(project):
    record = new_authorization(
        "https://staging.example.com", "Dana Levi", "the support bot", "staging", 7, datetime.now(UTC), allowed_tools=("issue_refund",)
    )
    AuthorizationStore().add(record)
    status, _ = call(project, "authorization_status", origin="https://staging.example.com")
    assert "not verified yet" in status and "Dana Levi" in status and "issue_refund" in status
    assert record.token not in status  # the proof token is never shown


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("read_report", {"path": "../outside.md"}),
        ("read_report", {"path": "C:/Windows/win.ini"}),
        ("read_report", {"path": "/etc/passwd"}),
        ("find_tools", {"path": ".."}),
        ("check_description", {"file": "../kritalon.targets.json"}),
        ("scan", {"target": "toy:fixed", "dir": "../elsewhere"}),
    ],
)
def test_nothing_outside_the_project_is_read_or_written(project, tool, arguments):
    inner = project / "inner"
    inner.mkdir()
    (project / "outside.md").write_text("a secret note", encoding="utf-8")
    text, failed = call(inner, tool, **arguments)
    assert failed and "a secret note" not in text
    assert "outside the project folder" in text or "reads .md and .json" in text
    assert not (project / "elsewhere").exists()


def test_read_report_reads_only_reports(project):
    (project / ".env").write_text("TOKEN=abc", encoding="utf-8")
    text, failed = call(project, "read_report", path=".env")
    assert failed and "abc" not in text


def test_find_tools_lists_candidates_and_skips_marked_ones(project):
    (project / "app").mkdir()
    (project / "app" / "tools.py").write_text(
        """
import kritalon.harness as pp
from agents import function_tool

@pp.action("issue_refund")
def issue_refund(order_id, amount): ...

@function_tool
def lookup_order(order_id): ...

async def send_email(to, body): ...

def format_reply(text): ...

class Billing:
    def delete_account(self, user): ...
""",
        encoding="utf-8",
    )
    (project / "node_modules").mkdir()
    (project / "node_modules" / "x.py").write_text("def delete_everything(): ...", encoding="utf-8")
    (project / "broken.py").write_text("def (", encoding="utf-8")
    text, failed = call(project, "find_tools")
    assert not failed and "1 function(s) already carry @pp.action" in text
    assert "app/tools.py:9  lookup_order(order_id)" in text and "registered as a tool" in text
    assert "send_email(to, body)" in text and "delete_account(user)" in text
    assert "format_reply" not in text and "delete_everything" not in text and "issue_refund(" not in text


DESCRIPTION = {
    "origin": "https://staging.example.com",
    "harness": "sdk",
    "chat": {"path": "/api/chat", "body": {"message": "{message}"}, "reply_pointer": "/reply"},
    "attacker_principal": "customer:alice",
    "principals": {"customer:alice": {"headers": {"Authorization": "Bearer ${ALICE_TOKEN}"}}},
    "tool_safety": "sinks",
}


def test_check_description_says_what_is_wrong(project):
    written_out = {**DESCRIPTION, "principals": {"customer:alice": {"headers": {"Authorization": "Bearer abc123"}}}}
    targets = {
        "good": DESCRIPTION,
        "bad": {**DESCRIPTION, "origin": "staging.example.com"},
        "leaky": written_out,
    }
    (project / "kritalon.targets.json").write_text(json.dumps({"targets": targets}), encoding="utf-8")
    text, failed = call(project, "check_description")
    assert not failed
    assert "bad: PROBLEM:" in text and "good: OK." in text
    assert "it protects nothing" in text and "no task_checks" in text
    assert "a header value is written out" in text and "abc123" not in text
    one, _ = call(project, "check_description", name="missing")
    assert "not in the file" in one


def test_the_guide_matches_the_code(project, capsys):
    """Every command and option the guide tells an assistant to use must exist."""
    assert main(["guide"]) == 0 and capsys.readouterr().out.strip() == GUIDE.strip()
    example = GUIDE.split("```json")[1].split("```")[0]
    from kritalon.targets.http import parse_config

    (name, raw), = json.loads(example)["targets"].items()
    config = parse_config(name, raw)
    assert config.harness == "sdk" and len(config.slots) == 2 and config.slots[1].canary_style == "name"
    import kritalon.harness as pp

    for used in ("wrap", "action", "planted"):
        assert f"pp.{used}" in GUIDE and hasattr(pp, used)


def test_find_tools_does_not_follow_a_link_out_of_the_project(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secrets.py").write_text("def delete_everything(): ...", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("def send_email(to): ...", encoding="utf-8")
    try:
        (project / "linked").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("this machine does not allow making links")
    text, failed = call(project, "find_tools")
    assert not failed and "send_email" in text and "delete_everything" not in text


def test_read_report_refuses_a_huge_file(project):
    from kritalon import mcp_server

    big = project / "huge.md"
    big.write_bytes(b"x" * (mcp_server._MAX_REPORT_BYTES + 1))
    text, failed = call(project, "read_report", path="huge.md")
    assert failed and "larger than" in text


# -- first_scan: the developer's own bot, from its chat address ---------------------------------


@pytest.fixture
def example_bot(project, monkeypatch):
    """The example bot from examples/, served on a free port, with the harness key set. Returns (url, origin, requests seen)."""
    import importlib.util
    import threading
    from pathlib import Path
    from wsgiref.simple_server import make_server

    import kritalon.harness as pp
    from kritalon.core import authorization as auth

    monkeypatch.setenv(pp.KEY_ENV, "k" * 40)
    monkeypatch.setenv("KRITALON_TARGETS_FILE", str(project / "kritalon.targets.json"))
    monkeypatch.setattr(pp, "_marked_tools", {})
    monkeypatch.setattr(pp, "_read_outside", set())
    auth.forget_checks()
    source = Path(__file__).resolve().parents[1] / "examples" / "support_bot.py"
    spec = importlib.util.spec_from_file_location("support_bot_for_mcp", source)
    example = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(example)
    inner, seen = example.make_app(False), []

    def watching(environ, start_response):
        seen.append(environ["PATH_INFO"])
        return inner(environ, start_response)

    server = make_server("127.0.0.1", 0, watching, handler_class=example._Quiet)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{server.server_address[1]}"
    yield origin + "/chat", origin, seen
    server.shutdown()
    server.server_close()


def test_first_scan_sends_nothing_and_authorizes_nothing_by_itself(example_bot, project):
    """On the command line a person at the keyboard may type their name for a bot on their own
    machine. An assistant is not that person: through this server the same scan is refused."""
    url, origin, seen = example_bot
    text, failed = call(project, "first_scan", url=url)
    assert failed and "no one has authorized" in text and f"kritalon authorize {origin}" in text
    assert seen == [] and AuthorizationStore().find(origin) is None


def test_first_scan_works_the_bot_out_and_scans_it_once_a_person_has_authorized(example_bot, project):
    url, origin, seen = example_bot
    AuthorizationStore().add(
        new_authorization(origin, "Dana Levi", "the example bot", "test", 7, datetime.now(UTC), allowed_tools=("issue_refund",))
    )
    text, failed = call(project, "first_scan", url=url, replays=1)
    assert not failed, text
    assert "Secrets it reads on an ordinary message: staff_code." in text
    assert "Saved what was worked out as target http:quick-127-0-0-1-" in text
    assert "verified violation" in text and "Reports are in kritalon-report/" in text
    report, failed = call(project, "read_report")
    assert not failed and "verified violations found" in report
    saved = json.loads((project / "kritalon.targets.json").read_text(encoding="utf-8"))["targets"]
    (name,) = saved
    assert saved[name]["harness"] == "sdk" and [rule["tool"] for rule in saved[name]["tool_rules"]] == ["issue_refund"]


def test_first_scan_stays_inside_the_project(example_bot, project):
    url, origin, seen = example_bot
    text, failed = call(project, "first_scan", url=url, dir="../elsewhere")
    assert failed and "outside the project folder" in text and seen == []

