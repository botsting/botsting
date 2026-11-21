"""`promptproof doctor`: it names the first step that is not passed and how to fix it, and sends
nothing to a bot that is not authorized. Uses the demo bot on 127.0.0.1."""

from datetime import UTC, datetime

import pytest

import promptproof.harness as pp
from promptproof import demo
from promptproof.cli import main
from promptproof.core import authorization as auth
from promptproof.core.authorization import AuthorizationStore, new_authorization
from promptproof.doctor import diagnose
from promptproof.practice_server import write_description

KEY = "k" * 40


@pytest.fixture
def staging(tmp_path, monkeypatch):
    """The demo bot served locally and described as target 'staging', with nothing else set up."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PROMPTPROOF_TARGETS_FILE", str(tmp_path / "promptproof.targets.json"))
    monkeypatch.delenv(pp.KEY_ENV, raising=False)
    auth.forget_checks()
    bot = demo.HarnessPracticeBot("fixed")
    server = demo.serve(bot)
    seen: list[str] = []
    inner = server.get_app()

    def watching(environ, start_response):
        seen.append(environ["PATH_INFO"])
        return inner(environ, start_response)

    server.set_app(watching)
    port = server.server_address[1]
    write_description(tmp_path / "promptproof.targets.json", "staging", demo.description(port, "fixed"))
    yield {"origin": f"http://127.0.0.1:{port}", "seen": seen, "port": port, "folder": tmp_path}
    server.shutdown()
    server.server_close()


def run(spec="http:staging", offline=False):
    lines: list[str] = []
    ready = diagnose(spec, offline, out=lines.append)
    return ready, "\n".join(lines)


def authorize(origin):
    record = new_authorization(origin, "Dana Levi", "the bot", "test", 1, datetime.now(UTC), allowed_tools=("issue_refund",))
    AuthorizationStore().add(record)


def test_each_missing_step_is_named_with_its_fix_and_nothing_is_sent_early(staging, monkeypatch):
    ready, text = run()
    assert not ready and "FIX   harness key" in text and "promptproof harness-key" in text
    assert "FIX   authorization" in text and "promptproof authorize " + staging["origin"] in text
    assert "--tool issue_refund" in text and "Stopped here: nothing is sent" in text
    assert staging["seen"] == []

    monkeypatch.setenv(pp.KEY_ENV, KEY)
    ready, text = run()
    assert not ready and "ok    harness key" in text and "FIX   authorization" in text
    assert staging["seen"] == []

    authorize(staging["origin"])
    ready, text = run(offline=True)
    assert ready and "Offline checks passed" in text and staging["seen"] == []

    ready, text = run()
    assert ready, text
    assert "ok    harness: the bot confirmed test mode" in text
    assert "ok    legitimate use of staff_code" in text and "ok    normal use" in text
    assert "Ready. Scan it with: promptproof scan --target http:staging" in text
    assert staging["seen"] and set(staging["seen"]) <= {pp.READY_PATH, "/chat"}


def test_a_wrong_key_on_the_bot_is_explained(staging, monkeypatch):
    authorize(staging["origin"])
    monkeypatch.setenv("SCANNER_KEY", "z" * 40)  # the scanner's key differs from the bot's
    monkeypatch.setenv(pp.KEY_ENV, KEY)
    raw = demo.description(staging["port"], "fixed")
    raw["harness_key_env"] = "SCANNER_KEY"
    write_description(staging["folder"] / "promptproof.targets.json", "staging", raw)
    ready, text = run()
    assert not ready and "FIX   harness" in text and "pp.wrap(app)" in text and "SCANNER_KEY" in text
    assert "/chat" not in staging["seen"]  # no message was sent to a bot that did not confirm test mode


def test_a_description_that_protects_nothing_is_called_out(staging, monkeypatch):
    monkeypatch.setenv(pp.KEY_ENV, KEY)
    raw = demo.description(staging["port"], "fixed")
    raw["slots"], raw["tool_rules"], raw["injection_points"], raw["task_checks"] = [], [], [], []
    write_description(staging["folder"] / "promptproof.targets.json", "staging", raw)
    _, text = run()
    assert "FIX   what it protects" in text and "note  normal use" in text


def test_missing_credentials_are_listed_by_name_only(staging, monkeypatch):
    monkeypatch.setenv(pp.KEY_ENV, KEY)
    monkeypatch.setenv("ALICE_TOKEN", "a-real-looking-token")
    raw = demo.description(staging["port"], "fixed")
    raw["principals"]["customer:alice"]["headers"] = {"Authorization": "Bearer ${ALICE_TOKEN}", "X-Team": "${TEAM_ID}"}
    raw["principals"]["customer:bob"]["headers"] = {"Authorization": "Bearer written-out-secret"}
    write_description(staging["folder"] / "promptproof.targets.json", "staging", raw)
    _, text = run()
    assert "FIX   credentials: not set in this environment: TEAM_ID" in text
    assert "note  credentials: a header for customer:bob is written out" in text
    assert "a-real-looking-token" not in text and "written-out-secret" not in text


def test_the_command_line_and_its_exit_codes(staging, capsys):
    assert main(["doctor", "--target", "toy:vulnerable"]) == 0
    assert "built-in practice bot" in capsys.readouterr().out
    assert main(["doctor", "--target", "http:staging"]) == 2
    assert main(["doctor", "--target", "http:not-described"]) == 2
    assert "promptproof guide" in capsys.readouterr().out
