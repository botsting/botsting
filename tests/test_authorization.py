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
            return httpx.Response(200, content=b"x" * size)
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


def test_proof_is_checked_again_when_the_gate_is_used(monkeypatch):
    a = verified()
    requests = serve(a, monkeypatch)
    require_authorized(Remote(authorization=a), now=NOW)
    require_authorized(Remote(authorization=a), now=NOW)
    assert len(requests) == 1, "checked once, then remembered for a while"
    transport, _ = site("taken down", status=404)
    monkeypatch.setattr(auth, "_transport", transport)
    auth.forget_checks()  # as if the recheck interval had passed
    with pytest.raises(AuthorizationError, match="no longer in place"):
        require_authorized(Remote(authorization=a), now=NOW)


def test_proof_is_checked_again_after_the_interval(monkeypatch):
    a = verified()
    requests = serve(a, monkeypatch)
    clock = {"t": 1000.0}
    monkeypatch.setattr(auth.time, "monotonic", lambda: clock["t"])
    require_authorized(Remote(authorization=a), now=NOW)
    clock["t"] += auth.RECHECK_SECONDS - 1
    require_authorized(Remote(authorization=a), now=NOW)
    assert len(requests) == 1
    clock["t"] += 2
    require_authorized(Remote(authorization=a), now=NOW)
    assert len(requests) == 2


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


def test_proof_taken_down_mid_scan_stops_it_and_keeps_the_report(monkeypatch):
    a = verified(now=datetime.now(UTC))
    serve(a, monkeypatch)
    bot = NetworkBot(a)
    calls = {"n": 0}
    real_check = auth.check_proof

    def proof_disappears_after_the_first_check(authorization, transport=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return real_check(authorization, transport)
        return auth.ProofResult(False, "taken down")

    monkeypatch.setattr(auth, "check_proof", proof_disappears_after_the_first_check)
    monkeypatch.setattr(auth, "RECHECK_SECONDS", 0.0)  # check on every use of the gate
    report = asyncio.run(run_scan(bot, [ATTACK, replace(ATTACK, id="probe2:secret")]))
    assert calls["n"] == 2, "checked when the scan was validated, then failed at the next use of the gate"
    assert report.stopped_early.startswith("authorization no longer valid")
    assert report.status == "inconclusive"
    assert bot.sent == [], "nothing was sent after the proof went away"
    assert report.attempts_run == 0


def test_proof_taken_down_between_attempts_keeps_what_was_found(monkeypatch):
    a = verified(now=datetime.now(UTC))
    serve(a, monkeypatch)
    monkeypatch.setattr(auth, "RECHECK_SECONDS", 0.0)
    real_check = auth.check_proof
    calls = {"n": 0}

    def gone_from_the_fourth_check(authorization, transport=None):
        # 1: validation, 2: preflight, 3: first attempt, 4: second attempt
        calls["n"] += 1
        return real_check(authorization, transport) if calls["n"] < 4 else auth.ProofResult(False, "taken down")

    monkeypatch.setattr(auth, "check_proof", gone_from_the_fourth_check)
    bot = NetworkBot(a)
    report = asyncio.run(run_scan(bot, [ATTACK, replace(ATTACK, id="probe2:secret")]))
    assert report.stopped_early.startswith("authorization no longer valid")
    assert "give it" in bot.sent, "the first attempt ran"
    assert bot.sent.count("give it") == 1, "the second did not"
    assert report.status == "inconclusive"


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

from promptproof.core.models import InjectionPoint, ToolRule  # noqa: E402

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
    require_authorized(ToolBot(a), now=NOW)  # a target that names neither is covered by the origin
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
