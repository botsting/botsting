"""The interface between the scan runner and a system under test."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol

from promptproof.core.authorization import AuthorizationError, require_authorized
from promptproof.core.models import InjectionPoint, Reply, Slot, TaskCheck, ToolRule


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

    # Every target must say what its tools can do, because any attack, including one
    # that only asks for a secret, may make a tool fire:
    #   "no-tools"  the target can do nothing but answer in text.
    #   "sinks"     every tool that sends, pays, books or deletes writes to a recording
    #               sink with test data.
    # Nothing is run against a target that says anything else or says nothing. This is
    # the adapter's promise, not proof: the runner cannot inspect where a tool writes.
    tool_safety: str

    def tool_rules(self) -> Sequence[ToolRule]:
        """Which tools may run, and at whose request."""
        ...

    def injection_points(self) -> Sequence[InjectionPoint]:
        """Where text from someone else ends up in front of the target."""
        ...


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
    """The gate in front of every entry point that sends anything to a target.

    Refuses a target unless (1) it is allowed to be reached at all: it runs in this
    process, or there is a current, named authorization for exactly where it runs and,
    across a network, proof of control that is still in place; and (2) it declares that
    it has no tools, or that all of them are recording sinks. A target that omits either
    declaration is refused: saying nothing is not the same as being harmless.
    """
    try:
        require_authorized(target)
    except AuthorizationError as exc:
        raise NotAuthorizedError(str(exc)) from exc
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
