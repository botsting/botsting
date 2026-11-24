"""Tests added after an independent audit of the documents' claims against the code. Each one pins a
claim that was true but had nothing that would fail if it stopped being true."""

import ast
import asyncio
import json
import socket
import sys
import threading
from pathlib import Path

import httpx

import promptproof.harness as pp
from promptproof.attacks.library import default_attacks
from promptproof.cli import main
from promptproof.core.runner import ScanConfig, run_scan
from promptproof.mcp_server import TOOLS, handle
from promptproof.targets.registry import build_target

SOURCE = Path(pp.__file__).parent


def test_nothing_leaves_the_machine_during_a_scan(tmp_path, monkeypatch, capsys):
    """never-do 10: no connection except to the bot named and the model chosen. Here both are on this
    machine, so every name looked up and every address connected to must be this machine.

    What is watched: the name lookups and connections this process makes through Python's socket
    layer (`getaddrinfo`, `connect`, `connect_ex`), and any other program it starts, of which there
    must be none. A connection made by native code that bypasses that layer would not be seen."""
    import subprocess

    looked_up: list[str] = []
    connected: list[str] = []
    started: list[str] = []
    real_lookup, real_connect, real_connect_ex = socket.getaddrinfo, socket.socket.connect, socket.socket.connect_ex
    real_popen = subprocess.Popen.__init__

    def connect_ex(self, address):
        connected.append(str(address[0]))
        return real_connect_ex(self, address)

    def popen(self, args, *more, **kwargs):
        started.append(str(args))
        return real_popen(self, args, *more, **kwargs)

    def lookup(host, *args, **kwargs):
        looked_up.append(str(host))
        return real_lookup(host, *args, **kwargs)

    def connect(self, address):
        connected.append(str(address[0]))
        return real_connect(self, address)

    monkeypatch.setattr(socket, "getaddrinfo", lookup)
    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    monkeypatch.setattr(subprocess.Popen, "__init__", popen)
    monkeypatch.chdir(tmp_path)
    assert main(["demo", "--live", "--replays", "1", "--no-open"]) == 0
    assert looked_up or connected, "the demo scans over HTTP, so something must have been seen"
    assert started == [], "a scan starts no other program"
    local = {"127.0.0.1", "localhost", "::1"}
    assert set(looked_up) <= local and set(connected) <= local, (set(looked_up), set(connected))


def test_the_harness_needs_nothing_but_the_standard_library():
    """Adding it to a bot must add no dependency."""
    tree = ast.parse((SOURCE / "harness.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= set(sys.stdlib_module_names), imported - set(sys.stdlib_module_names)


def test_no_assistant_tool_can_leave_an_authorization_behind(tmp_path, monkeypatch):
    """never-do 11, by behaviour: call every tool with the kind of arguments an assistant might try,
    and no authorization exists afterwards."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "promptproof.targets.json").write_text(
        json.dumps({"targets": {"bot": {
            "origin": "https://staging.example.com", "harness": "sdk",
            "chat": {"path": "/chat", "body": {"message": "{message}"}, "reply_pointer": "/reply"},
            "attacker_principal": "user", "principals": {"user": {}}, "tool_safety": "sinks",
        }}}),
        encoding="utf-8",
    )  # fmt: skip
    tries = {
        "origin": "https://staging.example.com", "target": "http:bot", "by": "Dana Levi", "authorize": True,
        "scope": "everything", "environment": "production", "name": "bot", "path": ".", "file": "promptproof.targets.json",
        "dir": "out", "offline": False, "replays": 1,
    }  # fmt: skip
    for number, name in enumerate(TOOLS):
        schema = TOOLS[name][1]["properties"]
        arguments = {key: value for key, value in tries.items() if key in schema}
        for extra in ({}, {"by": "Dana Levi", "authorize": True}):  # also with arguments the tool does not declare
            handle(tmp_path, {"jsonrpc": "2.0", "id": number, "method": "tools/call", "params": {"name": name, "arguments": {**arguments, **extra}}})
    assert not (tmp_path / "promptproof.authorizations.json").exists()
    assert not list(tmp_path.rglob("*authorization*"))


def test_every_report_states_the_odds_of_a_chance_match():
    target = build_target("toy:fixed")
    report = asyncio.run(run_scan(target, default_attacks(target), ScanConfig(reproduction_trials=1)))
    assert any("matched by accident is at most about 4 in a thousand million" in item for item in report.limitations)
    from promptproof.report_html import render_html
    from promptproof.report_markdown import render_markdown

    assert "by accident" in render_html(report) and "by accident" in render_markdown(report)


def test_the_egress_trap_runs_as_a_command_and_closes_its_log(tmp_path, monkeypatch, capsys):
    """The documents describe a trap a user can run. This is that command."""
    import time

    from promptproof.egress_trap import check_chain

    stop = threading.Event()
    started = threading.Event()

    def sleep(seconds):
        started.set()
        if stop.wait(10):
            raise KeyboardInterrupt

    monkeypatch.setattr(time, "sleep", sleep)
    log = tmp_path / "run" / "egress-trap.jsonl"
    result: list[int] = []
    thread = threading.Thread(target=lambda: result.append(main(["egress-trap", "--log", str(log), "--allow", "api.example.invalid:443"])))
    thread.start()
    assert started.wait(10)
    port = int(json.loads(log.read_text(encoding="utf-8").splitlines()[0]) and capsys.readouterr().out.split("127.0.0.1:")[1].split(".")[0])
    with httpx.Client(proxy=f"http://127.0.0.1:{port}", timeout=5) as client:
        assert client.get("http://hooks.example.invalid/x").status_code == 403
    stop.set()
    thread.join(10)
    assert result == [0]
    lines = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert check_chain(lines) == ("intact", True) and lines[0]["allow"] == ["api.example.invalid:443"]
    assert "1 outbound attempt(s) recorded, 1 refused" in capsys.readouterr().out
    assert main(["egress-trap", "--log", str(log), "--allow", "not-a-host-and-port"]) == 2


def test_every_report_says_that_an_accepted_call_is_not_proof_of_harm():
    """A reader must not take "accepted" for "the refund happened", nor a zero for "impossible"."""
    from promptproof.core.scan import LIMITATIONS

    first = LIMITATIONS[0]
    assert "attempted and refused by the tool (level 2), or accepted by it (level 3)" in first
    assert "Whether an accepted call changed anything downstream (level 4) is not checked" in first
