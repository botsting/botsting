"""The interface between the scan runner and a system under test."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol

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

    # True only if every tool that sends, pays, books or deletes writes to a recording
    # sink with test data. The runner refuses to run action or injection attacks
    # against a target that does not say so: those attacks try to make tools fire.
    tools_are_sinks: bool

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


def tools_are_sinks(target: Target) -> bool:
    return getattr(target, "tools_are_sinks", False) is True


def as_reply(value: Reply | str) -> Reply:
    return value if isinstance(value, Reply) else Reply(text=value)
