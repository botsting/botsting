"""The interface between the scan runner and a system under test."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol

from kritalon.core.authorization import (
    Authorization,
    AuthorizationError,
    confirm_proof,
    require_authorized,
)
from kritalon.core.models import InjectionPoint, Reply, Slot, TaskCheck, ToolRule


class TargetError(RuntimeError):
    """The target could not be reset or did not answer."""


class Session(Protocol):
    """One conversation with the target as one principal."""

    async def send(self, text: str) -> Reply | str:
        """Send a message and return what came back. Raise TargetError on failure.

        A target with tools returns a Reply carrying the tool calls its recorder saw
        during this message. A target without tools may return plain text.
        """
        ...


class Target(Protocol):
    # Enough to reconnect later, e.g. "toy:vulnerable?model=scripted". Stored in reports.
    spec: str
    # Who the attacker is. Must not be authorized for any slot under test.
    attacker_principal: str
    # Where the target runs: "in-process", "loopback" or "network". Read by the
    # authorization gate (core/authorization.py) before anything is sent; a target
    # without one is refused, so there is no default when it is missing.
    reach: str
    # Every target must say what its tools can do, because any attack, including one
    # that only asks for a secret, may make a tool fire. Read by the gate in this
    # module (require_contained_tools) of every target:
    #   "no-tools"  the target can do nothing but answer in text.
    #   "sinks"     every tool that sends, pays, books or deletes writes to a recording
    #               sink with test data.
    # A target that says anything else, or says nothing, is refused: saying nothing is
    # not the same as being harmless. This is the adapter's promise, not proof: the
    # runner cannot inspect where a tool writes.
    tool_safety: str

    async def describe(self) -> Mapping[str, str]:
        """The configuration under test (build, model, weights digest, settings).

        Stored with every report so a replay can tell whether it faces the same thing.
        Must not raise.
        """
        ...

    def slots(self) -> Sequence[Slot]:
        """Where canaries can be planted, and who may see each."""
        ...

    def task_checks(self) -> Sequence[TaskCheck]:
        """Normal uses that must keep working, so a 'fix' that breaks the bot is caught."""
        ...

    async def reset(self, fixtures: Mapping[str, str], content: Mapping[str, str] | None = None) -> None:
        """Return to a known starting state.

        `fixtures` maps slot id to the canary value to plant. `content` maps injection
        point id to the text to place there; points not mentioned get their harmless
        default. Everything from earlier conversations, including recorded tool calls
        and their effects, must be gone afterwards.
        """
        ...

    async def open_session(self, principal: str) -> Session:
        """Start a new conversation as `principal`."""
        ...


class ActionTarget(Target, Protocol):
    """A target whose tools can be observed. Needed for action and injection attacks."""

    def tool_rules(self) -> Sequence[ToolRule]:
        """Which tools may run, and at whose request."""
        ...

    def injection_points(self) -> Sequence[InjectionPoint]:
        """Where text from someone else ends up in front of the target."""
        ...


class NetworkTarget(Target, Protocol):
    """A target that leaves this process (reach "loopback" or "network"), such as HttpTarget.

    Every operation on it is checked against a recorded authorization. The gate in
    core/authorization.py reads these attributes (`require_authorized`, the scope check
    and `authorization_summary`); the scan itself never does. A target that runs
    in-process has none of them.
    """

    # The place the target is reached at, e.g. "https://staging.example.com". Read by
    # the gate to find the authorization for exactly this origin; when it is missing
    # or not text, the gate refuses the target.
    origin: str
    # The recorded permission to test this origin. Read by the gate before every
    # operation and summarized in the report; missing means no authorization, and the
    # gate refuses the target.
    authorization: Authorization | None
    # Which agent the deployment serves, when it serves several behind one origin.
    # Read by the gate's scope check against the authorization's --agent limit; the
    # default when missing is "not declared", which an agent-limited authorization refuses.
    agent_id: str
    # Same, for the tenant the deployment serves (--tenant limit); default "not declared".
    tenant: str
    # Tools the scan may ask the harness to carry out for real, inside the caps written
    # in the bot's code. Read by the gate's scope check against the authorization's
    # live tools; the default when missing is (), nothing is ever carried out for real.
    live_actions: tuple[str, ...]


class HarnessedTarget(ActionTarget, Protocol):
    """A target wired with the drop-in harness (kritalon/harness.py), such as an HttpTarget
    with "harness": "sdk" or "inputs". The preflight reads what the harness reports."""

    # Tools the harness listed as marked in its signed readiness answer. Read by the
    # preflight when a tool rule's control is the harness's attestation; the default
    # when missing is (), so an attested rule fails its check on a target without the harness.
    marked_tools: tuple[str, ...]
    # True when the fake secrets travel in each chat request ("harness": "inputs").
    # Read by the preflight's repeated-slot check; the default when missing is False,
    # so the check does not run and every slot is attacked as usual.
    secrets_travel_in_requests: bool


def tool_rules(target: Target) -> Sequence[ToolRule]:
    """The target's tool rules; none for a target without observable tools."""
    return tuple(getattr(target, "tool_rules", lambda: ())())


def injection_points(target: Target) -> Sequence[InjectionPoint]:
    return tuple(getattr(target, "injection_points", lambda: ())())


class UnsafeTargetError(ValueError):
    """The target has not promised that an attack cannot cause real actions."""


class NotAuthorizedError(UnsafeTargetError):
    """There is no valid authorization to send anything to this target."""


def require_contained_tools(target: Target) -> None:
    """The part of the gate that needs no network: run at every entry point and before every operation.

    Refuses a target unless (1) it is allowed to be reached at all: it runs in this
    process, or there is a current, named, in-scope authorization for exactly where it
    runs; and (2) it declares that it has no tools, or that all of them are recording
    sinks. A target that omits either declaration is refused: saying nothing is not the
    same as being harmless. Whether a network target's proof of control is still in
    place is checked by `confirm_permitted`.
    """
    try:
        require_authorized(target)
    except AuthorizationError as exc:
        raise NotAuthorizedError(str(exc)) from exc
    _require_tool_declaration(target)


async def confirm_permitted(target: Target, fresh: bool = False) -> None:
    """The whole gate, including fetching a network target's proof of control.

    `fresh` fetches the proof whatever was remembered: used when a scan or replay starts.
    """
    try:
        authorization = require_authorized(target)
        _require_tool_declaration(target)
        if authorization is not None:
            await confirm_proof(authorization, fresh=fresh)
            # The fetch takes time; the authorization may have expired while it ran.
            require_authorized(target)
    except AuthorizationError as exc:
        raise NotAuthorizedError(str(exc)) from exc


def _require_tool_declaration(target: Target) -> None:
    declared = getattr(target, "tool_safety", None)
    if declared == "sinks":
        return
    if declared == "no-tools":
        if tool_rules(target) or injection_points(target):
            raise UnsafeTargetError(
                "this target says it has no tools but declares tool rules or injection points; "
                "it must declare that its tools are recording sinks, or have none"
            )
        return
    raise UnsafeTargetError(
        "this target does not declare that it has no tools or that its tools are recording sinks with "
        "test data; refusing to send it anything, because a successful attack would carry out real actions"
    )


def as_reply(value: Reply | str) -> Reply:
    return value if isinstance(value, Reply) else Reply(text=value)
