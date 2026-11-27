"""`botsting doctor`: it names the first step that is not passed and how to fix it, and sends
nothing to a bot that is not authorized. Uses the demo bot on 127.0.0.1."""

from datetime import UTC, datetime

import pytest

import botsting.harness as pp
from botsting import demo
from botsting.cli import main
from botsting.core import authorization as auth
from botsting.core.authorization import AuthorizationStore, new_authorization
from botsting.doctor import diagnose
from botsting.practice_server import write_description

KEY = "k" * 40


@pytest.fixture
def staging(tmp_path, monkeypatch):
    """The demo bot served locally and described as target 'staging', with nothing else set up."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("BOTSTING_TARGETS_FILE", str(tmp_path / "botsting.targets.json"))
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
    write_description(tmp_path / "botsting.targets.json", "staging", demo.description(port, "fixed"))
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
    assert not ready and "FIX   harness key" in text and "botsting harness-key" in text
    assert "FIX   authorization" in text and "botsting authorize " + staging["origin"] in text
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
    assert "Ready. Scan it with: botsting scan --target http:staging" in text
    assert staging["seen"] and set(staging["seen"]) <= {pp.READY_PATH, "/chat"}


def test_a_wrong_key_on_the_bot_is_explained(staging, monkeypatch):
    authorize(staging["origin"])
    monkeypatch.setenv("SCANNER_KEY", "z" * 40)  # the scanner's key differs from the bot's
    monkeypatch.setenv(pp.KEY_ENV, KEY)
    raw = demo.description(staging["port"], "fixed")
    raw["harness_key_env"] = "SCANNER_KEY"
    write_description(staging["folder"] / "botsting.targets.json", "staging", raw)
    ready, text = run()
    assert not ready and "FIX   harness" in text and "pp.wrap(app)" in text and "SCANNER_KEY" in text
    assert "/chat" not in staging["seen"]  # no message was sent to a bot that did not confirm test mode


def test_a_description_that_protects_nothing_is_called_out(staging, monkeypatch):
    monkeypatch.setenv(pp.KEY_ENV, KEY)
    raw = demo.description(staging["port"], "fixed")
    raw["slots"], raw["tool_rules"], raw["injection_points"], raw["task_checks"] = [], [], [], []
    write_description(staging["folder"] / "botsting.targets.json", "staging", raw)
    _, text = run()
    assert "FIX   what it protects" in text and "note  normal use" in text


def test_missing_credentials_are_listed_by_name_only(staging, monkeypatch):
    monkeypatch.setenv(pp.KEY_ENV, KEY)
    monkeypatch.setenv("ALICE_TOKEN", "a-real-looking-token")
    raw = demo.description(staging["port"], "fixed")
    raw["principals"]["customer:alice"]["headers"] = {
        "Authorization": "Bearer ${ALICE_TOKEN}",
        "X-Team": "${TEAM_ID}",
        "X-User": "alice",  # says who the test user is; not a credential, so not worth a note
    }
    raw["principals"]["customer:bob"]["headers"] = {"Authorization": "Bearer written-out-secret"}
    write_description(staging["folder"] / "botsting.targets.json", "staging", raw)
    _, text = run()
    assert "FIX   credentials: not set in this environment: TEAM_ID" in text
    assert "note  credentials: a credential for customer:bob is written out" in text
    assert "a-real-looking-token" not in text and "written-out-secret" not in text


def test_the_command_line_and_its_exit_codes(staging, capsys):
    assert main(["doctor", "--target", "toy:vulnerable"]) == 0
    assert "built-in practice bot" in capsys.readouterr().out
    assert main(["doctor", "--target", "http:staging"]) == 2
    assert main(["doctor", "--target", "http:not-described"]) == 2
    assert "botsting guide" in capsys.readouterr().out


def test_production_keys_on_a_test_deployment_stop_it_and_no_value_is_shown(staging, monkeypatch):
    monkeypatch.setenv(pp.KEY_ENV, KEY)
    authorize(staging["origin"])
    secret = "sk_" + "live_" + "Zq7" * 8
    settings = staging["folder"] / "staging.env"
    settings.write_text(f"STRIPE_SECRET_KEY={secret}\nNODE_ENV=test\n", encoding="utf-8")
    lines: list[str] = []
    ready = diagnose("http:staging", out=lines.append, env_files=(str(settings),))
    text = "\n".join(lines)
    assert not ready and "FIX   deployment settings" in text and "STRIPE_SECRET_KEY" in text
    assert secret not in text and "Zq7" not in text
    assert staging["seen"] == []  # nothing was sent to a deployment that may be wired to production

    settings.write_text("STRIPE_SECRET_KEY=" + "sk_" + "test_" + "Zq7" * 8 + "\nNODE_ENV=test\n", encoding="utf-8")
    lines.clear()
    assert diagnose("http:staging", out=lines.append, env_files=(str(settings),))
    assert any("ok    deployment settings" in line for line in lines)
    assert main(["doctor", "--target", "http:staging", "--offline", "--env-file", str(settings)]) == 0


def test_doctor_checks_a_bot_built_in_a_no_code_builder(tmp_path, monkeypatch):
    """The "inputs" harness needs no key and no harness on the bot; the legitimate-use step is the check."""
    import json
    import threading
    from wsgiref.simple_server import WSGIRequestHandler, make_server

    from botsting.presets import build

    class Quiet(WSGIRequestHandler):
        def log_message(self, *args):
            pass

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("BOTSTING_TARGETS_FILE", str(tmp_path / "botsting.targets.json"))
    monkeypatch.setenv("DIFY_APP_KEY", "test-key")
    auth.forget_checks()
    state = {"phrase": "", "declared": True}

    def dify(environ, start_response):
        body = json.loads(environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH") or 0)))
        value = body["inputs"]["pp_reference"] if state["declared"] else ""  # Dify drops undeclared inputs
        if "opening hours" in body["query"]:
            answer = "We are open every day."
        elif state["phrase"] in body["query"]:
            answer = f"The internal reference is {value}."
        else:
            answer = "I can't share that."
        data = json.dumps({"answer": answer, "conversation_id": body["conversation_id"] or "conv-1"}).encode()
        start_response("200 OK", [("Content-Type", "application/json"), ("Content-Length", str(len(data)))])
        return [data]

    server = make_server("127.0.0.1", 0, dify, handler_class=Quiet)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        raw, _, line = build("dify", origin)
        state["phrase"] = line.split('pass phrase "')[1].split('"')[0]
        write_description(tmp_path / "botsting.targets.json", "support", raw)
        record = new_authorization(origin, "Dana Levi", "the bot", "test", 1, datetime.now(UTC))
        AuthorizationStore().add(record)

        ready, text = run("http:support")
        assert not ready and "FIX   normal use" in text  # the REPLACE THIS placeholder was not replaced
        raw["task_checks"][0].update(prompt="What are your opening hours?", expect_substring="open")
        write_description(tmp_path / "botsting.targets.json", "support", raw)
        ready, text = run("http:support")
        assert ready and "harness key" not in text and "ok    legitimate use of pp_reference" in text

        state["declared"] = False  # the owner forgot to declare the variable in the builder
        ready, text = run("http:support")
        assert not ready and "FIX   legitimate use of pp_reference" in text
    finally:
        server.shutdown()
        server.server_close()
