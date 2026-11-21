"""Small real actions under caps: a tool marked `live=Cap(...)` runs for real in a test only when
the bot's code, the deployment, the signed session and the authorization on record all agree,
and only inside every limit. Anything else is recorded and not run.

The "real" tools here append to a list. Nothing leaves this machine.
"""

import asyncio
import json
import threading
from datetime import UTC, datetime

import httpx
import pytest

import promptproof.harness as pp
from promptproof.cli import main
from promptproof.core.authorization import (
    AuthorizationError,
    AuthorizationStore,
    new_authorization,
    require_authorized,
)
from promptproof.targets.http import HttpTarget, TargetConfigError, parse_config

KEY = "k" * 40
TEST_ORDERS = ("T-1", "T-2")
done: list[tuple] = []


@pp.action(
    "issue_refund",
    live=pp.Cap(max={"amount": 10}, only={"order_id": TEST_ORDERS}, total={"amount": 25}, calls=3),
)
def issue_refund(order_id: str, amount: float) -> dict:
    done.append((order_id, amount))
    return {"status": "refunded for real"}


@pp.action("send_email", live=pp.Cap(only={"to": ["qa@example.com"]}, calls=2))
async def send_email(to: str, body: str) -> str:
    done.append((to, body))
    return "sent for real"


@pp.action("delete_account")  # no cap: can never run in a test
def delete_account(user: str) -> str:
    done.append(("deleted", user))
    return "deleted for real"


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.setenv(pp.KEY_ENV, KEY)
    monkeypatch.delenv(pp.LIVE_ENV, raising=False)
    done.clear()
    pp._ledger.clear()
    pp._run_first_seen.clear()


def session(live=("issue_refund", "send_email", "delete_account"), run="run-1"):
    return pp._open(pp.make_session_token(KEY, "s1", {}, live=live, run=run))


def inside(active, function, *args, **kwargs):
    reset = pp._current.set(active)
    try:
        return function(*args, **kwargs)
    finally:
        pp._current.reset(reset)


def switch_on(monkeypatch, tools="issue_refund, send_email, delete_account"):
    monkeypatch.setenv(pp.LIVE_ENV, tools)


# -- every condition is needed ----------------------------------------------------------------


def test_inside_every_limit_and_with_every_switch_on_it_runs_for_real(monkeypatch):
    switch_on(monkeypatch)
    active = session()
    assert inside(active, issue_refund, "T-1", 10) == {"status": "refunded for real"}
    assert done == [("T-1", 10)]
    (call,) = active.calls
    assert call["live"] == "ran" and call["accepted"] is True
    assert call["result"].startswith("[ran for real within the caps]") and "refunded for real" in call["result"]


def test_without_the_deployment_switch_nothing_runs(monkeypatch):
    active = session()
    assert inside(active, issue_refund, "T-1", 5) == {"status": "ok"}  # the stand-in
    assert done == [] and active.calls[0]["live"] == "capped"
    assert pp.LIVE_ENV in active.calls[0]["result"]


def test_the_switch_names_tools_one_by_one(monkeypatch):
    switch_on(monkeypatch, "send_email")
    active = session()
    inside(active, issue_refund, "T-1", 5)
    assert done == []


def test_without_the_scan_asking_nothing_runs(monkeypatch):
    switch_on(monkeypatch)
    active = session(live=())
    inside(active, issue_refund, "T-1", 5)
    assert done == [] and "live" not in active.calls[0]  # an ordinary recorded call
    only_email = session(live=("send_email",))
    inside(only_email, issue_refund, "T-1", 5)
    assert done == []


def test_a_tool_without_a_cap_never_runs_whatever_is_switched_on(monkeypatch):
    switch_on(monkeypatch)
    active = session()
    assert inside(active, delete_account, "bob") == {"status": "ok"}
    assert done == [] and "live" not in active.calls[0]


def test_outside_a_test_session_the_cap_changes_nothing(monkeypatch):
    switch_on(monkeypatch)
    assert issue_refund("REAL-ORDER", 5000) == {"status": "refunded for real"}  # an ordinary customer's refund
    assert done == [("REAL-ORDER", 5000)]


# -- the limits -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("order", "amount", "reason"),
    [
        ("T-1", 10.01, "outside the cap of 0 to 10"),
        ("T-1", 500, "outside the cap of 0 to 10"),
        ("T-1", -5, "outside the cap"),
        ("T-1", "5", "not a number"),
        ("T-1", True, "not a number"),
        ("T-1", float("nan"), "not a number"),
        ("T-1", float("inf"), "not a number"),
        ("T-1", None, "not a number"),
        ("REAL-ORDER", 5, "not one of the values allowed"),
        (None, 5, "not one of the values allowed"),
        (["T-1"], 5, "not one of the values allowed"),
    ],
)
def test_a_call_outside_a_limit_is_recorded_with_the_limit_and_not_run(monkeypatch, order, amount, reason):
    switch_on(monkeypatch)
    active = session()
    assert inside(active, issue_refund, order, amount) == {"status": "ok"}
    assert done == []
    (call,) = active.calls
    assert call["live"] == "capped" and call["accepted"] is True and reason in call["result"]
    assert call["result"].startswith("[not run: ")


def test_arguments_the_function_would_reject_are_never_run(monkeypatch):
    switch_on(monkeypatch)
    active = session()
    inside(active, issue_refund, "T-1", 5, "an extra argument")
    assert done == [] and active.calls[0]["tool"] == "issue_refund"


def test_the_runs_total_and_call_count_hold(monkeypatch):
    switch_on(monkeypatch)
    active = session()
    for amount in (10, 10):
        inside(active, issue_refund, "T-1", amount)
    inside(active, issue_refund, "T-2", 6)  # 26 would pass the total of 25
    assert done == [("T-1", 10), ("T-1", 10)] and "total amount over the cap of 25" in active.calls[2]["result"]
    inside(active, issue_refund, "T-2", 5)  # 25: the third and last real call
    inside(active, issue_refund, "T-2", 0)  # a fourth
    assert done == [("T-1", 10), ("T-1", 10), ("T-2", 5)]
    assert "limit of 3 real call(s)" in active.calls[4]["result"]


def test_limits_are_counted_per_run_and_across_sessions_of_a_run(monkeypatch):
    switch_on(monkeypatch)
    for _ in range(4):  # four conversations of the same run
        inside(session(run="run-A"), issue_refund, "T-1", 1)
    assert len(done) == 3
    inside(session(run="run-B"), issue_refund, "T-1", 1)
    assert len(done) == 4


def test_starting_many_other_runs_never_resets_a_runs_count(monkeypatch):
    """Forgetting a run to make room would hand it a fresh allowance, so a full memory refuses new runs."""
    switch_on(monkeypatch)
    for _ in range(3):
        inside(session(run="run-A"), issue_refund, "T-1", 1)  # run A has used its 3 calls
    for number in range(pp._MAX_RUNS_REMEMBERED + 5):
        inside(session(run=f"other-{number}"), issue_refund, "T-1", 1)
    inside(session(run="run-A"), issue_refund, "T-1", 1)
    assert done.count(("T-1", 1)) == 3 + pp._MAX_RUNS_REMEMBERED - 1  # A stayed at 3; the overflow runs got nothing
    overflow = session(run="one-more")
    inside(overflow, issue_refund, "T-1", 1)
    assert "too many test runs" in overflow.calls[0]["result"]
    # A day later the old runs are forgotten and new ones are counted again.
    monkeypatch.setattr(pp.time, "monotonic", lambda: 10**9)
    before = len(done)
    inside(session(run="next-day"), issue_refund, "T-1", 1)
    assert len(done) == before + 1


def test_many_threads_cannot_push_a_run_past_its_limits(monkeypatch):
    switch_on(monkeypatch)
    start = threading.Barrier(16)

    def attempt():
        start.wait()
        inside(session(run="run-race"), issue_refund, "T-1", 10)

    threads = [threading.Thread(target=attempt) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(done) == 2  # total 25 allows two refunds of 10, whatever the timing


def test_a_tool_that_fails_for_real_is_recorded_and_still_counted(monkeypatch):
    switch_on(monkeypatch)

    @pp.action("charge", live=pp.Cap(max={"amount": 5}, calls=1))
    def charge(amount: float) -> str:
        raise RuntimeError("the payment service said no")

    monkeypatch.setenv(pp.LIVE_ENV, "charge")
    active = session(live=("charge",))
    with pytest.raises(RuntimeError):
        inside(active, charge, 5)
    assert active.calls[0]["live"] == "ran" and "raised RuntimeError" in active.calls[0]["result"]
    inside(active, charge, 5)  # the one real call is used up, even though it failed
    assert active.calls[1]["live"] == "capped"


def test_an_async_tool_follows_the_same_rules(monkeypatch):
    switch_on(monkeypatch)
    active = session()
    assert inside(active, lambda: asyncio.run(send_email("qa@example.com", "hi"))) == "sent for real"
    assert inside(active, lambda: asyncio.run(send_email("ceo@example.com", "hi"))) == {"status": "ok"}
    assert done == [("qa@example.com", "hi")]
    assert [c["live"] for c in active.calls] == ["ran", "capped"]


# -- a cap must be a real limit ----------------------------------------------------------------


@pytest.mark.parametrize(
    "make",
    [
        lambda: pp.Cap(),
        lambda: pp.Cap(total={"amount": 50}),  # a total alone does not limit one call
        lambda: pp.Cap(max={"amount": 10}, calls=0),
        lambda: pp.Cap(max={"amount": 10}, calls=True),
        lambda: pp.Cap(max={"amount": -1}),
        lambda: pp.Cap(max={"amount": "ten"}),
        lambda: pp.Cap(only={"to": []}),
        lambda: pp.Cap(only={"to": "qa@example.com"}),  # a string would allow every substring
    ],
)
def test_a_cap_that_limits_nothing_is_refused(make):
    with pytest.raises(pp.HarnessError):
        make()


def test_a_cap_must_name_real_arguments():
    with pytest.raises(pp.HarnessError, match="not arguments"):

        @pp.action("refund", live=pp.Cap(max={"ammount": 10}))
        def refund(order_id, amount): ...


def test_a_live_session_must_name_its_run():
    with pytest.raises(pp.HarnessError, match="name its run"):
        pp.make_session_token(KEY, "s1", {}, live=("issue_refund",))


# -- the permission on record ------------------------------------------------------------------

ORIGIN = "http://127.0.0.1:8080"
NOW = datetime.now(UTC)


def description(**changes):
    raw = {
        "origin": ORIGIN,
        "harness": "sdk",
        "live_actions": ["issue_refund"],
        "chat": {"path": "/chat", "body": {"message": "{message}"}, "reply_pointer": "/reply"},
        "attacker_principal": "customer:alice",
        "principals": {"customer:alice": {}},
        "tool_safety": "sinks",
    }
    raw.update(changes)
    return parse_config("bot", raw)


def test_real_actions_need_their_own_line_in_the_authorization():
    recorded_only = new_authorization(ORIGIN, "Dana Levi", "the bot", "test", 1, NOW, allowed_tools=("issue_refund",))
    target = HttpTarget(description(), "http:bot", recorded_only)
    with pytest.raises(AuthorizationError, match="--live-tool"):
        require_authorized(target, now=NOW)
    live = new_authorization(
        ORIGIN, "Dana Levi", "the bot", "test", 1, NOW, allowed_tools=("issue_refund",), live_tools=("issue_refund",)
    )
    require_authorized(HttpTarget(description(), "http:bot", live), now=NOW)
    # Without live_actions in the description, a live authorization changes nothing.
    assert HttpTarget(description(live_actions=[]), "http:bot", live).live_actions == ()


def test_a_live_tool_must_also_be_an_allowed_tool():
    with pytest.raises(ValueError, match="must also be named"):
        new_authorization(ORIGIN, "Dana Levi", "the bot", "test", 1, NOW, live_tools=("issue_refund",))


def test_live_actions_need_the_drop_in_harness():
    with pytest.raises(TargetConfigError, match="live_actions needs the drop-in harness"):
        description(harness="endpoint", reset={"path": "/reset"})


def test_the_command_line_records_and_warns(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["authorize", ORIGIN, "--by", "Dana Levi", "--scope", "the bot", "--environment", "test",
                 "--live-tool", "issue_refund"]) == 0  # fmt: skip
    printed = capsys.readouterr().out
    assert "CARRIED OUT FOR REAL" in printed and "Check the caps" in printed
    record = AuthorizationStore().find(ORIGIN)
    assert record.live_tools == ("issue_refund",) and record.allowed_tools == ("issue_refund",)
    # An older file without the field still loads, with nothing live.
    stored = json.loads((tmp_path / "promptproof.authorizations.json").read_text(encoding="utf-8"))
    del stored["authorizations"][0]["live_tools"]
    (tmp_path / "promptproof.authorizations.json").write_text(json.dumps(stored), encoding="utf-8")
    assert AuthorizationStore().find(ORIGIN).live_tools == ()


# -- the scanner and a bot together -------------------------------------------------------------


async def bot(scope, receive, send):
    message = json.loads((await receive())["body"])["message"]
    amount = float(message.split()[-1])
    issue_refund("T-1", amount)
    body = json.dumps({"reply": "Done."}).encode()
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": body})


def test_a_scan_carries_out_a_small_refund_and_only_records_a_large_one(monkeypatch):
    switch_on(monkeypatch)
    tokens = []
    inner = httpx.ASGITransport(app=pp.wrap(bot))

    class Watching(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            tokens.append(json.loads(pp._unb64(request.headers[pp.SESSION_HEADER].split(".")[0])))
            return await inner.handle_async_request(request)

    target = HttpTarget(description(), "http:bot", None, transport=Watching())

    async def talk():
        await target.reset({})
        conversation = await target.open_session("customer:alice")
        return await conversation.send("refund 7"), await conversation.send("refund 5000")

    small, large = asyncio.run(talk())
    assert done == [("T-1", 7.0)]
    assert small.tool_calls[0].result.startswith("[ran for real within the caps]")
    assert large.tool_calls[0].accepted and "outside the cap of 0 to 10" in large.tool_calls[0].result
    # The readiness check asks for nothing live; the messages name the tool and one run.
    assert "live" not in tokens[0] and tokens[1]["live"] == ["issue_refund"]
    assert tokens[1]["run"] == tokens[2]["run"] != ""
