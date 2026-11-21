"""`promptproof mcp`: what a coding assistant can and cannot do through it."""

import io
import json
import subprocess
import sys
from datetime import UTC, datetime

import pytest

from promptproof.cli import main
from promptproof.core.authorization import AuthorizationStore, new_authorization
from promptproof.mcp_server import GUIDE, TOOLS, handle, serve


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
    import promptproof.mcp_server as server
    from pathlib import Path

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
    assert "no verified violations" in text.lower() and "Reports are in promptproof-report/" in text


def test_it_runs_as_a_real_process(project):
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "setup_guide", "arguments": {}}})
    done = subprocess.run(
        [sys.executable, "-m", "promptproof.cli", "mcp"], check=True, input=request + "\n", capture_output=True, text=True,
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
    assert "not empty" in again  # old evidence is never mixed in


def test_a_real_target_is_refused_without_a_persons_authorization(project):
    (project / "promptproof.targets.json").write_text(json.dumps({"targets": {"staging": DESCRIPTION}}), encoding="utf-8")
    text, _ = call(project, "scan", target="http:staging", replays=1, dir="first")
    assert "no authorization" in text.lower() and "NOT RUN" in text
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
        ("check_description", {"file": "../promptproof.targets.json"}),
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
import promptproof.harness as pp
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
    (project / "promptproof.targets.json").write_text(json.dumps({"targets": targets}), encoding="utf-8")
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
    from promptproof.targets.http import parse_config

    (name, raw), = json.loads(example)["targets"].items()
    config = parse_config(name, raw)
    assert config.harness == "sdk" and len(config.slots) == 2 and config.slots[1].canary_style == "name"
    import promptproof.harness as pp

    for used in ("wrap", "action", "planted"):
        assert f"pp.{used}" in GUIDE and hasattr(pp, used)
