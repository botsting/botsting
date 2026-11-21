"""The interface between the scan runner and a system under test."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol

from promptproof.core.models import Slot, TaskCheck


class TargetError(RuntimeError):
    """The target could not be reset or did not answer."""


class Session(Protocol):
    """One conversation with the target as one principal."""

    async def send(self, text: str) -> str:
        """Send a message and return the target's reply. Raise TargetError on failure."""
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

    async def reset(self, fixtures: Mapping[str, str]) -> None:
        """Return to a known starting state with `fixtures` (slot id to canary value) planted.

        Everything from earlier conversations must be gone afterwards.
        """
        ...

    async def open_session(self, principal: str) -> Session:
        """Start a new conversation as `principal`."""
        ...
