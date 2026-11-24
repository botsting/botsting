"""Milestone 4: nothing is sent outside this process without a named, current, proven authorization.

No test here touches the network: proof fetches go to an httpx.MockTransport.
"""

import asyncio
import json
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from promptproof.cli import main
from promptproof.core import authorization as auth
from promptproof.core.authorization import (
    CHALLENGE_PATH,
    Authorization,
    AuthorizationError,
    AuthorizationStore,
    check_proof,
    is_loopback_origin,
    new_authorization,
    normalize_origin,
    require_authorized,
)
from promptproof.core.models import Attack, Slot, TaskCheck
from promptproof.core.runner import ScanConfig, replay_finding, run_attempt, run_scan
from promptproof.core.stats import make_rate
from promptproof.targets.base import NotAuthorizedError, UnsafeTargetError, require_contained_tools

NOW = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)
ORIGIN = "https://staging.example.com"


@pytest.fixture(autouse=True)
def fresh_checks():
    auth.forget_checks()
    yield
    auth.forget_checks()


def site(body: str | None = None, status: int = 200, redirect_to: str | None = None, size: int = 0):
    """A pretend web site that serves the challenge file. Records every request it gets."""
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if redirect_to is not None:
            return httpx.Response(302, headers={"Location": redirect_to})
        if size:
            return httpx.Response(200, content=b"x" * size, headers={"Content-Type": "text/plain"})
        return httpx.Response(status, text=body or "")

    return httpx.MockTransport(handler), requests


def verified(origin: str = ORIGIN, days: int = 30, now: datetime = NOW) -> Authorization:
    a = new_authorization(origin, "Dana Levi", "the support bot on staging", "staging", days, now)
    return replace(a, verified_at=now.isoformat(timespec="seconds"))


def serve(authorization: Authorization, monkeypatch) -> list[httpx.Request]:
    transport, requests = site(f"# owner's notes\n{authorization.challenge_line()}\n")
    monkeypatch.setattr(auth, "_transport", transport)
    return requests


# -- origins -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("https://Staging.Example.com", "https://staging.example.com"),
        ("https://staging.example.com/", "https://staging.example.com"),
        ("https://staging.example.com:443", "https://staging.example.com"),
        ("https://staging.example.com:8443", "https://staging.example.com:8443"),
        ("http://localhost:8080", "http://localhost:8080"),
        ("http://[::1]:9000", "http://[::1]:9000"),
        ("https://staging.example.com.", "https://staging.example.com"),
    ],
)
def test_origins_are_normalized(given, expected):
    assert normalize_origin(given) == expected


@pytest.mark.parametrize(
    "bad",
    [
        "staging.example.com",
        "ftp://example.com",
        "https://user:pw@example.com",
        "https://example.com/chat",
        "https://example.com?x=1",
        "https://example.com#top",
        "https://",
        "https://example.com:99999",
    ],
)
def test_unusable_origins_are_rejected(bad):
    with pytest.raises(ValueError):
        normalize_origin(bad)


def test_loopback_detection():
    for origin in ("http://localhost", "http://127.0.0.1:5000", "http://[::1]", "http://bot.localhost"):
        assert is_loopback_origin(origin), origin
    for origin in ("https://example.com", "http://10.0.0.5", "http://localhost.example.com", "http://127.0.0.1.nip.io"):
        assert not is_loopback_origin(origin), origin


# -- creating an authorization ---------------------------------------------------------------


def test_new_authorization_records_who_what_where_and_until_when():
    a = new_authorization("https://Staging.Example.com/", "  Dana   Levi ", "support bot", "staging", 30, NOW)
    assert (a.origin, a.authorized_by, a.scope, a.environment) == (ORIGIN, "Dana Levi", "support bot", "staging")
    assert a.expires_at == (NOW + timedelta(days=30)).isoformat(timespec="seconds")
    assert a.verified_at == "" and len(a.token) >= 40
    assert new_authorization(ORIGIN, "Dana", "x", "staging", 30, NOW).token != a.token


@pytest.mark.parametrize(
    "kwargs",
    [
        {"authorized_by": " "},
        {"scope": ""},
        {"environment": "prod"},
        {"days": 0},
        {"days": 91},
        {"origin": "http://staging.example.com"},  # plain http across a network
    ],
)
def test_new_authorization_refuses_incomplete_records(kwargs):
    base = {"origin": ORIGIN, "authorized_by": "Dana", "scope": "bot", "environment": "staging", "days": 30}
    with pytest.raises(ValueError):
        new_authorization(**{**base, **kwargs}, now=NOW)


def test_loopback_may_use_plain_http_and_needs_no_proof():
    a = new_authorization("http://127.0.0.1:8080", "Dana", "local bot", "test", 7, NOW)
    assert not a.needs_proof
    assert check_proof(a).ok


# -- proof of control --------------------------------------------------------------------


def test_proof_found():
    a = verified()
    transport, requests = site(f"{a.challenge_line()}\n")
    result = check_proof(a, transport)
    assert result.ok
    assert [str(r.url) for r in requests] == [ORIGIN + CHALLENGE_PATH]
    assert requests[0].headers["User-Agent"] == "promptproof-authorization-check"


@pytest.mark.parametrize(
    ("site_args", "reason"),
    [
        ({"body": "promptproof-challenge=someone-elses-token"}, "does not contain"),
        ({"body": "", "status": 404}, "HTTP 404"),
        ({"redirect_to": "https://attacker.example/proof.txt"}, "redirect"),
        ({"size": 5000}, "larger than"),
    ],
)
def test_proof_not_found(site_args, reason):
    transport, requests = site(**site_args)
    result = check_proof(verified(), transport)
    assert not result.ok and reason in result.detail
    assert len(requests) == 1, "a redirect is never followed"


def test_token_must_be_a_whole_line():
    a = verified()
    transport, _ = site(f"see {a.challenge_line()} for details")
    assert not check_proof(a, transport).ok


def test_network_failure_is_a_failed_proof_not_a_crash():
    def refuse(request):
        raise httpx.ConnectError("refused")

    result = check_proof(verified(), httpx.MockTransport(refuse))
    assert not result.ok and "ConnectError" in result.detail


# -- the store -----------------------------------------------------------------------------


def test_store_round_trip_and_one_authorization_per_origin(tmp_path):
    store = AuthorizationStore(tmp_path / "auth.json")
    assert store.load() == []
    first = new_authorization(ORIGIN, "Dana", "bot", "staging", 30, NOW)
    store.add(first)
    second = new_authorization(ORIGIN, "Dana", "bot v2", "staging", 30, NOW)
    store.add(second)
    store.add(new_authorization("https://other.example.com", "Dana", "bot", "staging", 30, NOW))
    assert len(store.load()) == 2
    assert store.find("https://STAGING.example.com/") == second
    marked = store.mark_verified(ORIGIN, NOW)
    assert store.find(ORIGIN).verified_at == marked.verified_at == NOW.isoformat(timespec="seconds")
    assert not list(tmp_path.glob(".promptproof-auth-*")), "no temporary files left behind"


def test_unreadable_store_is_an_error(tmp_path):
    path = tmp_path / "auth.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(AuthorizationError):
        AuthorizationStore(path).load()


# -- the gate ------------------------------------------------------------------------------


class Remote:
    """Just enough of a target for the gate."""

    def __init__(self, reach="network", origin=ORIGIN, authorization=None):
        self.reach, self.origin, self.authorization = reach, origin, authorization
        self.tool_safety = "no-tools"


def test_in_process_targets_need_nothing():
    require_authorized(Remote(reach="in-process", origin=None))


def test_a_target_that_does_not_say_where_it_runs_is_refused():
    target = Remote()
    del target.reach
    with pytest.raises(AuthorizationError, match="does not declare where it runs"):
        require_authorized(target)
    with pytest.raises(AuthorizationError):
        require_authorized(Remote(reach="cloud"))


def test_network_target_without_authorization_is_refused():
    with pytest.raises(AuthorizationError, match="no authorization"):
        require_authorized(Remote())
    with pytest.raises(AuthorizationError, match="which origin"):
        require_authorized(Remote(origin=None, authorization=verified()))


def test_authorization_for_another_origin_does_not_count(monkeypatch):
    other = verified("https://other.example.com")
    serve(other, monkeypatch)
    with pytest.raises(AuthorizationError, match="not https://staging.example.com"):
        require_authorized(Remote(authorization=other))
    # Not even a different port on the same host.
    with pytest.raises(AuthorizationError):
        require_authorized(Remote(origin=ORIGIN + ":8443", authorization=verified()))


def test_expired_authorization_is_refused(monkeypatch):
    a = verified()
    serve(a, monkeypatch)
    require_authorized(Remote(authorization=a), now=NOW + timedelta(days=29))
    with pytest.raises(AuthorizationError, match="expired"):
        require_authorized(Remote(authorization=a), now=NOW + timedelta(days=30))


def test_unverified_authorization_is_refused(monkeypatch):
    a = replace(verified(), verified_at="")
    serve(a, monkeypatch)  # even with the proof in place, it has to have been verified first
    with pytest.raises(AuthorizationError, match="has not been verified"):
        require_authorized(Remote(authorization=a), now=NOW)


def confirm(a: Authorization, fresh: bool = False) -> None:
    asyncio.run(auth.confirm_proof(a, fresh=fresh))


def test_the_offline_gate_never_fetches_anything(monkeypatch):
    a = verified()
    requests = serve(a, monkeypatch)
    assert require_authorized(Remote(authorization=a), now=NOW) == a, "returns what still needs a proof check"
    assert requests == []


def test_proof_is_remembered_for_a_while_and_fetched_again_when_asked(monkeypatch):
    a = verified()
    requests = serve(a, monkeypatch)
    confirm(a)
    confirm(a)
    assert len(requests) == 1, "checked once, then remembered for a while"
    confirm(a, fresh=True)
    assert len(requests) == 2, "a fresh check ignores what was remembered"
    transport, _ = site("taken down", status=404)
    monkeypatch.setattr(auth, "_transport", transport)
    with pytest.raises(AuthorizationError, match="no longer in place"):
        confirm(a, fresh=True)
    with pytest.raises(AuthorizationError):
        confirm(a)  # a failed check is not remembered as a success


def test_proof_is_checked_again_after_the_interval(monkeypatch):
    a = verified()
    requests = serve(a, monkeypatch)
    clock = {"t": 1000.0}
    monkeypatch.setattr(auth.time, "monotonic", lambda: clock["t"])
    confirm(a)
    clock["t"] += auth.RECHECK_SECONDS - 1
    confirm(a)
    assert len(requests) == 1
    clock["t"] += 2
    confirm(a)
    assert len(requests) == 2


def test_proof_request_asks_caches_not_to_answer_and_needs_plain_text(monkeypatch):
    a = verified()
    requests = serve(a, monkeypatch)
    confirm(a, fresh=True)
    assert requests[0].headers["Cache-Control"] == "no-cache"

    def html(request):
        return httpx.Response(200, content=a.challenge_line().encode(), headers={"Content-Type": "text/html"})

    result = check_proof(a, httpx.MockTransport(html))
    assert not result.ok and "text/plain" in result.detail


def test_loopback_needs_a_record_but_no_proof(monkeypatch):
    transport, requests = site("")
    monkeypatch.setattr(auth, "_transport", transport)
    local = "http://127.0.0.1:8080"
    with pytest.raises(AuthorizationError, match="no authorization"):
        require_authorized(Remote(reach="loopback", origin=local))
    record = new_authorization(local, "Dana", "local copy of the bot", "test", 7, NOW)
    require_authorized(Remote(reach="loopback", origin=local, authorization=record), now=NOW)
    assert requests == []
    with pytest.raises(AuthorizationError, match="is not"):
        require_authorized(Remote(reach="loopback", origin=ORIGIN, authorization=verified()))


def test_the_tool_safety_gate_includes_the_authorization_gate():
    with pytest.raises(NotAuthorizedError):
        require_contained_tools(Remote())
    assert issubclass(NotAuthorizedError, UnsafeTargetError)


# -- end to end: nothing is sent to an unauthorized target -----------------------------------

SLOT = Slot("secret", "instruction_secret", "A planted secret", "the secret", ("staff:dana",), "staff:dana", "What is the secret?")
TASK = TaskCheck("hello", "customer:alice", "Hello", "welcome")
ATTACK = Attack("probe:secret", "test", "Probe", "secret", ("give it",))


class NetworkBot:
    """Behaves like a bot across a network, but runs in memory and counts what it is sent."""

    spec = "fake-network"
    attacker_principal = "customer:alice"
    tool_safety = "no-tools"
    reach = "network"
    origin = ORIGIN

    def __init__(self, authorization: Authorization | None) -> None:
        self.authorization = authorization
        self.sent: list[str] = []
        self._secret = ""

    async def describe(self) -> Mapping[str, str]:
        return {"target": "fake-network"}

    def slots(self) -> Sequence[Slot]:
        return (SLOT,)

    def task_checks(self) -> Sequence[TaskCheck]:
        return (TASK,)

    async def reset(self, fixtures, content=None) -> None:
        self._secret = fixtures["secret"]

    async def open_session(self, principal: str):
        bot = self

        class Session:
            async def send(self, text: str) -> str:
                bot.sent.append(text)
                if principal == "staff:dana":
                    return f"The secret is {bot._secret}"
                return "welcome" if text == "Hello" else "no"

        return Session()


def test_scan_of_an_unauthorized_network_target_sends_nothing():
    bot = NetworkBot(None)
    with pytest.raises(NotAuthorizedError):
        asyncio.run(run_scan(bot, [ATTACK]))
    assert bot.sent == []


def test_scan_of_an_authorized_network_target_runs(monkeypatch):
    a = verified(now=datetime.now(UTC))
    serve(a, monkeypatch)
    bot = NetworkBot(a)
    report = asyncio.run(run_scan(bot, [ATTACK]))
    assert report.status == "no_verified_violations" and bot.sent


def proof_until(monkeypatch, still_there) -> dict[str, int]:
    """Make the proof disappear once `still_there()` turns false. Counts the fetches."""
    calls = {"n": 0}
    real = auth.check_proof_async

    async def check(authorization, transport=None):
        calls["n"] += 1
        if still_there():
            return await real(authorization, transport)
        return auth.ProofResult(False, "taken down")

    monkeypatch.setattr(auth, "check_proof_async", check)
    monkeypatch.setattr(auth, "RECHECK_SECONDS", 0.0)  # fetch before every operation
    return calls


def test_proof_taken_down_right_after_the_start_stops_the_scan_before_anything_is_sent(monkeypatch):
    a = verified(now=datetime.now(UTC))
    serve(a, monkeypatch)
    calls = proof_until(monkeypatch, lambda: calls["n"] <= 1)
    bot = NetworkBot(a)
    report = asyncio.run(run_scan(bot, [ATTACK, replace(ATTACK, id="probe2:secret")]))
    assert report.stopped_early.startswith("authorization no longer valid")
    assert report.status == "inconclusive"
    assert bot.sent == [], "nothing was sent after the proof went away"
    assert report.attempts_run == 0


def test_proof_taken_down_partway_keeps_what_was_found(monkeypatch):
    a = verified(now=datetime.now(UTC))
    serve(a, monkeypatch)
    bot = NetworkBot(a)
    proof_until(monkeypatch, lambda: "give it" not in bot.sent)
    report = asyncio.run(run_scan(bot, [ATTACK, replace(ATTACK, id="probe2:secret")]))
    assert report.stopped_early.startswith("authorization no longer valid")
    assert bot.sent.count("give it") == 1, "the first attempt ran, nothing after the proof went away"
    assert report.status == "inconclusive"


def test_every_scan_starts_with_a_fresh_proof_check(monkeypatch):
    """Review: a second scan in the same process trusted the first scan's check."""
    a = verified(now=datetime.now(UTC))
    requests = serve(a, monkeypatch)
    first = NetworkBot(a)
    assert asyncio.run(run_scan(first, [ATTACK])).status == "no_verified_violations"
    fetched = len(requests)
    transport, _ = site("taken down", status=404)
    monkeypatch.setattr(auth, "_transport", transport)
    second = NetworkBot(a)
    with pytest.raises(NotAuthorizedError, match="no longer in place"):
        asyncio.run(run_scan(second, [ATTACK]))
    assert second.sent == []
    assert fetched >= 1


def test_expiry_during_a_scan_stops_it_before_the_next_operation(monkeypatch):
    """Review: an authorization that expired mid-scan still allowed the next message."""
    local = "http://127.0.0.1:8080"
    record = new_authorization(local, "Dana", "local bot", "test", 1, datetime.now(UTC))
    bot = NetworkBot(record)
    bot.reach, bot.origin = "loopback", local

    def expire_after_first_message(now=None):
        if bot.sent:
            raise AuthorizationError(f"the authorization for {local} expired at {record.expires_at}")
        return None

    from promptproof.targets import base

    monkeypatch.setattr(base, "require_authorized", lambda target, now=None: expire_after_first_message(now))
    two_turns = Attack("two:secret", "test", "Two", "secret", ("first", "second"))
    report = asyncio.run(run_scan(bot, [two_turns]))
    assert report.stopped_early.startswith("authorization no longer valid") and "expired" in report.stopped_early
    assert len(bot.sent) == 1, "the message after the expiry was never sent"


def test_a_slow_proof_fetch_obeys_the_scan_time_limit(monkeypatch):
    """Review: the opening proof fetch ran before the meter started, so it ignored the time limit."""
    import time as real_time

    a = verified(now=datetime.now(UTC))
    serve(a, monkeypatch)

    async def slow(authorization, transport=None):
        await asyncio.sleep(2)
        return auth.ProofResult(True, "eventually")

    monkeypatch.setattr(auth, "check_proof_async", slow)
    bot = NetworkBot(a)
    started = real_time.monotonic()
    report = asyncio.run(run_scan(bot, [ATTACK], ScanConfig(max_seconds=0.2)))
    assert real_time.monotonic() - started < 1.5
    assert report.stopped_early.startswith("time limit")
    assert report.status == "inconclusive" and bot.sent == []


def test_cancel_during_the_proof_fetch_is_honoured(monkeypatch):
    a = verified(now=datetime.now(UTC))
    serve(a, monkeypatch)
    state = {"cancel": False}

    async def slow(authorization, transport=None):
        state["cancel"] = True
        await asyncio.sleep(2)
        return auth.ProofResult(True, "eventually")

    monkeypatch.setattr(auth, "check_proof_async", slow)
    bot = NetworkBot(a)
    report = asyncio.run(run_scan(bot, [ATTACK], ScanConfig(cancelled=lambda: state["cancel"])))
    assert report.stopped_early == "cancelled" and bot.sent == []


def test_replay_against_an_unauthorized_network_target_sends_nothing():
    from promptproof.core.models import EvidenceLevel, Finding

    finding = Finding(
        id="F1", attack_id="probe:secret", technique="test", title="Probe", slot_id="secret",
        level=EvidenceLevel.DISCLOSED, encoding="plain", scope="single-turn", attacker_principal="customer:alice",
        authorized=("staff:dana",), frozen_turns=("give it",), transcript=(), discovery=make_rate(1, 1),
        reproduction=make_rate(1, 1),
    )  # fmt: skip
    bot = NetworkBot(None)
    result = asyncio.run(replay_finding(bot, finding, 2))
    assert bot.sent == []
    assert result.rate.trials == 0 and "no authorization" in result.problems[0]


def test_single_attempt_against_an_unauthorized_target_sends_nothing():
    bot = NetworkBot(None)
    attempt = asyncio.run(run_attempt(bot, ATTACK))
    assert bot.sent == [] and attempt.transcript == ()
    assert attempt.error and "stopped early" in attempt.error


# -- the command line -----------------------------------------------------------------------


def test_authorize_create_verify_list(tmp_path, capsys, monkeypatch):
    store = str(tmp_path / "auth.json")
    args = ["authorize", ORIGIN, "--by", "Dana Levi", "--scope", "support bot", "--environment", "staging", "--store", store]
    assert main(args) == 0
    printed = capsys.readouterr().out
    token_line = next(line.strip() for line in printed.splitlines() if line.strip().startswith("promptproof-challenge="))
    assert ORIGIN + CHALLENGE_PATH in printed

    transport, _ = site("nothing here")
    monkeypatch.setattr(auth, "_transport", transport)
    assert main(["authorize", "--verify", ORIGIN, "--store", store]) == 2
    assert "Not verified" in capsys.readouterr().err

    transport, _ = site(token_line + "\n")
    monkeypatch.setattr(auth, "_transport", transport)
    assert main(["authorize", "--verify", ORIGIN, "--store", store]) == 0
    assert "Verified" in capsys.readouterr().out
    assert json.loads((tmp_path / "auth.json").read_text(encoding="utf-8"))["authorizations"][0]["verified_at"]

    assert main(["authorize", "--list", "--store", store]) == 0
    listed = capsys.readouterr().out
    assert "verified" in listed and "Dana Levi" in listed


def test_authorize_refuses_incomplete_input(tmp_path, capsys):
    store = str(tmp_path / "auth.json")
    assert main(["authorize", ORIGIN, "--by", "Dana", "--store", store]) == 2
    assert "also give --scope, --environment" in capsys.readouterr().err
    assert main(["authorize", "http://staging.example.com", "--by", "D", "--scope", "s", "--environment", "staging", "--store", store]) == 2
    assert main(["authorize", "--verify", "https://unknown.example.com", "--store", store]) == 2
    assert not (tmp_path / "auth.json").exists()


def test_authorize_production_warns(tmp_path, capsys):
    store = str(tmp_path / "auth.json")
    assert main(["authorize", ORIGIN, "--by", "D", "--scope", "s", "--environment", "production", "--store", store]) == 0
    assert "production system" in capsys.readouterr().out


# -- scope beyond the origin ---------------------------------------------------------------

from promptproof.core.models import InjectionPoint, ToolRule

RULE = ToolRule("refund", "issue_refund", "Refunds at staff request", "a refund", ("staff:dana",), "staff:dana", "Refund 5")
POINT = InjectionPoint("note", "Order note", "staff:dana", "Summarize", "order", "hi", ("send_email",), "send an email")


class ToolBot(Remote):
    def __init__(self, authorization, agent_id="", tenant=""):
        super().__init__(authorization=authorization)
        self.agent_id, self.tenant = agent_id, tenant

    def tool_rules(self):
        return (RULE,)

    def injection_points(self):
        return (POINT,)


def scoped(**kwargs) -> Authorization:
    a = new_authorization(ORIGIN, "Dana", "bot", "staging", 30, NOW, **kwargs)
    return replace(a, verified_at=NOW.isoformat(timespec="seconds"))


def test_every_tool_the_target_can_exercise_must_be_named(monkeypatch):
    for allowed, missing in (((), "issue_refund, send_email"), (("issue_refund",), "send_email")):
        a = scoped(allowed_tools=allowed)
        serve(a, monkeypatch)
        with pytest.raises(AuthorizationError, match=f"does not name the tool\(s\) {missing}"):
            require_authorized(ToolBot(a), now=NOW)
    a = scoped(allowed_tools=("issue_refund", "send_email", "issue_refund"))
    assert a.allowed_tools == ("issue_refund", "send_email")
    serve(a, monkeypatch)
    require_authorized(ToolBot(a), now=NOW)


def test_agent_and_tenant_must_match_when_the_target_names_them(monkeypatch):
    tools = ("issue_refund", "send_email")
    a = scoped(allowed_tools=tools, agent_id="support-bot", tenant="acme-staging")
    serve(a, monkeypatch)
    require_authorized(ToolBot(a, agent_id="support-bot", tenant="acme-staging"), now=NOW)
    # Review: a limit the target gives no way to check is not a limit.
    with pytest.raises(AuthorizationError, match="does not say which agent_id"):
        require_authorized(ToolBot(a), now=NOW)
    with pytest.raises(AuthorizationError, match="does not say which tenant"):
        require_authorized(ToolBot(a, agent_id="support-bot"), now=NOW)
    origin_only = scoped(allowed_tools=tools)
    require_authorized(ToolBot(origin_only), now=NOW)  # no limit set, nothing named: the origin decides
    with pytest.raises(AuthorizationError, match="agent_id is 'sales-bot'"):
        require_authorized(ToolBot(a, agent_id="sales-bot", tenant="acme-staging"), now=NOW)
    with pytest.raises(AuthorizationError, match="tenant is 'acme-prod'"):
        require_authorized(ToolBot(a, agent_id="support-bot", tenant="acme-prod"), now=NOW)
    unscoped = scoped(allowed_tools=tools)
    serve(unscoped, monkeypatch)
    with pytest.raises(AuthorizationError, match="covers 'nothing'"):
        require_authorized(ToolBot(unscoped, agent_id="support-bot"), now=NOW)


def test_scope_survives_the_store_and_the_command_line(tmp_path, capsys):
    store_path = tmp_path / "auth.json"
    assert main([
        "authorize", ORIGIN, "--by", "Dana", "--scope", "bot", "--environment", "staging",
        "--tool", "issue_refund", "--tool", "send_email", "--agent", "support-bot", "--tenant", "acme-staging",
        "--store", str(store_path),
    ]) == 0  # fmt: skip
    printed = capsys.readouterr().out
    assert "tools that may be exercised: issue_refund, send_email" in printed
    loaded = AuthorizationStore(store_path).find(ORIGIN)
    assert loaded.allowed_tools == ("issue_refund", "send_email")
    assert (loaded.agent_id, loaded.tenant) == ("support-bot", "acme-staging")


# -- the report records the permission, never the token ------------------------------------


def test_report_records_who_authorized_the_scan_but_not_the_token(monkeypatch):
    from promptproof.core.models import ScanReport
    from promptproof.report_html import render_html
    from promptproof.report_markdown import render_markdown

    a = verified(now=datetime.now(UTC))
    serve(a, monkeypatch)
    report = asyncio.run(run_scan(NetworkBot(a), [ATTACK]))
    assert report.authorization["origin"] == ORIGIN
    assert report.authorization["authorized_by"] == "Dana Levi"
    assert report.authorization["reach"] == "network"
    everything = json.dumps(report.to_dict()) + render_markdown(report) + render_html(report)
    assert a.token not in everything, "the proof token must never be copied into a report"
    assert ScanReport.from_dict(json.loads(json.dumps(report.to_dict()))).authorization == report.authorization


def test_in_process_scan_records_only_where_it_ran():
    from promptproof.attacks.library import default_attacks
    from promptproof.targets.registry import build_target

    target = build_target("toy:fixed")
    report = asyncio.run(run_scan(target, default_attacks(target)))
    assert report.authorization == {"reach": "in-process"}


# -- the review's origin and record cases -----------------------------------------------------


@pytest.mark.parametrize("bad", ["https://example.com:0", "https://@example.com", "https://:@example.com"])
def test_more_unusable_origins(bad):
    with pytest.raises(ValueError):
        normalize_origin(bad)


def test_one_spelling_per_origin():
    assert normalize_origin("https://bücher.example") == normalize_origin("https://xn--bcher-kva.example")
    assert normalize_origin("https://bücher.example") == "https://xn--bcher-kva.example"
    assert normalize_origin("http://[0:0:0:0:0:0:0:1]:8080") == normalize_origin("http://[::1]:8080") == "http://[::1]:8080"
    assert normalize_origin("https://STAGING.example.com:443/") == "https://staging.example.com"


def write_store(tmp_path, **changes) -> AuthorizationStore:
    good = new_authorization("http://127.0.0.1:8080", "Dana", "local bot", "test", 7, NOW)
    record = {**auth.asdict(good), **changes}
    path = tmp_path / "auth.json"
    path.write_text(json.dumps({"authorizations": [record]}), encoding="utf-8")
    return AuthorizationStore(path)


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"authorized_by": "  "}, "does not name the person"),
        ({"scope": ""}, "does not say what may be tested"),
        ({"environment": "garbage"}, "environment must be one of"),
        ({"expires_at": "9999-01-01T00:00:00+00:00"}, "at most 90 days"),
        ({"expires_at": "2099-01-01T00:00:00"}, "time zone"),
        ({"created_at": "2026-12-31T00:00:00+00:00"}, "expires before it was created"),
        ({"origin": "http://127.0.0.1:8080/"}, "canonical"),
        ({"token": "short"}, "too short"),
        ({"allowed_tools": "issue_refund"}, "must be a list"),
        ({"authorized_by": 7}, "must be text"),
    ],
)
def test_records_read_back_from_the_file_are_validated(tmp_path, changes, reason):
    """Review: records loaded from the file skipped every check the factory made."""
    with pytest.raises(AuthorizationError, match=reason):
        write_store(tmp_path, **changes).load()


def test_a_hand_made_record_is_validated_at_the_gate_too():
    bad = replace(new_authorization("http://127.0.0.1:8080", "Dana", "x", "test", 7, NOW), environment="garbage")
    with pytest.raises(AuthorizationError, match="environment"):
        require_authorized(Remote(reach="loopback", origin="http://127.0.0.1:8080", authorization=bad), now=NOW)


def test_a_network_target_cannot_claim_a_loopback_origin():
    record = new_authorization("http://127.0.0.1:8080", "Dana", "x", "test", 7, NOW)
    with pytest.raises(AuthorizationError, match="across a network"):
        require_authorized(Remote(reach="network", origin="http://127.0.0.1:8080", authorization=record), now=NOW)


def test_a_proof_answered_from_a_cache_is_not_accepted():
    a = verified()

    def cached(age: str):
        def handler(request):
            return httpx.Response(200, text=a.challenge_line(), headers={"Age": age})

        return httpx.MockTransport(handler)

    assert check_proof(a, cached("0")).ok
    for age in ("86400", "1", "soon"):
        result = check_proof(a, cached(age))
        assert not result.ok and "cache" in result.detail, age


# -- the reviewer's last three, found before its provider stopped it --------------------------


def test_a_reused_meter_checks_the_new_targets_permission(monkeypatch):
    from promptproof.core.runner import Meter

    a = verified(now=datetime.now(UTC))
    serve(a, monkeypatch)
    meter = Meter()
    allowed = NetworkBot(a)
    asyncio.run(run_attempt(allowed, ATTACK, meter))
    assert allowed.sent
    stranger = NetworkBot(None)  # no authorization at all
    attempt = asyncio.run(run_attempt(stranger, ATTACK, meter))
    assert stranger.sent == [] and attempt.error and "stopped early" in attempt.error


def test_expiry_while_the_proof_is_being_fetched_stops_the_operation(monkeypatch):
    from promptproof.targets import base

    a = verified(now=datetime.now(UTC))
    serve(a, monkeypatch)
    state = {"expired": False}
    real = base.require_authorized

    def expires_once_fetched(target, now=None):
        if state["expired"]:
            raise AuthorizationError("the authorization expired")
        return real(target, now)

    async def fetch_then_expire(authorization, fresh=False):
        state["expired"] = True

    monkeypatch.setattr(base, "require_authorized", expires_once_fetched)
    monkeypatch.setattr(base, "confirm_proof", fetch_then_expire)
    with pytest.raises(NotAuthorizedError, match="expired"):
        asyncio.run(base.confirm_permitted(NetworkBot(a), fresh=True))


def test_a_record_dated_in_the_future_is_refused(monkeypatch):
    later = NOW + timedelta(days=3650)
    a = verified(now=later)
    serve(a, monkeypatch)
    with pytest.raises(AuthorizationError, match="in the future"):
        require_authorized(Remote(authorization=a), now=NOW)
    require_authorized(Remote(authorization=verified(now=NOW + timedelta(minutes=2))), now=NOW)  # small clock skew
