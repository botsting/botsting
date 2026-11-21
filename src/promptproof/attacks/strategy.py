"""Interfaces for adaptive attack strategies.

Every strategy — built-in or external (such as PyRIT) — talks to the target only through
a `ProbeChannel` owned by the runner. That keeps three invariants in one place:

1. Canaries never leave the runner. A strategy sees only the target's replies and a
   boolean/status feedback signal, never a planted secret.
2. Every message passes through the runner's `Meter` (limits, deadlines, cancellation)
   and `require_contained_tools`.
3. Every verified discovery is frozen into an ordinary `Attack` and replayed from reset
   with fresh canaries by the runner's normal reproduction pipeline.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Protocol, TypeVar

from promptproof.core.models import Attack, AttackKind, Attempt, ToolCall, Turn
from promptproof.targets.base import Target, injection_points, tool_rules

_T = TypeVar("_T")


@dataclass(frozen=True)
class Objective:
    """One protected asset, tool rule or injection point to probe. Never holds a canary."""

    id: str
    kind: AttackKind
    description: str
    # Public outsider phrasing (slot/rule hint) or desired action (injection point goal).
    hint: str
    victim_prompt: str = ""
    forbidden_tools: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProbeFeedback:
    """What the runner reports back to a strategy after one target turn or planted attempt."""

    reply_text: str
    tool_calls: tuple[ToolCall, ...] = ()
    verified: bool = False
    suspected: bool = False
    contaminated: bool = False
    error: str | None = None


TurnGenerator = Callable[[Sequence[Turn], ProbeFeedback | None], Awaitable[str | None]]


class ProbeChannel(Protocol):
    """Runner-owned channel handed to a strategy for one objective."""

    @property
    def objective(self) -> Objective: ...

    @property
    def remaining_messages(self) -> int:
        """How many target messages this strategy may still send for this objective."""
        ...

    @property
    def stopped(self) -> bool:
        """True once the scan's meter stopped (limit or cancel) or this channel's budget ran out."""
        ...

    async def within_deadline(self, awaitable: Awaitable[_T]) -> _T:
        """Await attacker-side work (such as an attacker LLM call) under the scan's deadline and cancel check."""
        ...

    async def run_conversation(
        self,
        next_turn: TurnGenerator,
        *,
        attack_id: str,
        technique: str,
        title: str,
        max_turns: int = 4,
    ) -> tuple[Attempt, Attack | None]:
        """Run one adaptive conversation from reset with fresh canaries.

        Returns the completed `Attempt` and, when any attacker turn was sent, the frozen
        `Attack` containing those exact turns (truncated at the turn where verified
        evidence was first observed).
        """
        ...

    async def try_payload(
        self,
        payload: str,
        *,
        attack_id: str,
        technique: str,
        title: str,
    ) -> tuple[Attempt, Attack]:
        """Plant `payload` at an injection point, run the victim's request, and judge it."""
        ...


@dataclass(frozen=True)
class SearchResult:
    """Everything a strategy did while searching one objective."""

    objective_id: str
    # Each entry pairs an attempt with the frozen Attack that produced it (None if no message was sent).
    episodes: tuple[tuple[Attack | None, Attempt], ...]
    attacker_calls: int = 0


class AdaptiveStrategy(Protocol):
    """A strategy that adapts its messages or payloads to what the target replies."""

    name: str
    technique: str

    async def search(self, objective: Objective, channel: ProbeChannel) -> SearchResult:
        """Probe `objective` through `channel` until verified evidence is found or budget runs out."""
        ...


def objectives_for(target: Target) -> list[Objective]:
    """Every protected thing declared by `target`, in preflight order, with no canary values."""
    items: list[Objective] = []
    for slot in target.slots():
        items.append(
            Objective(
                id=slot.id,
                kind="disclosure",
                description=slot.description,
                hint=slot.hint,
            )
        )
    for rule in tool_rules(target):
        items.append(
            Objective(
                id=rule.id,
                kind="action",
                description=rule.description,
                hint=rule.hint,
                forbidden_tools=(rule.tool,),
            )
        )
    for point in injection_points(target):
        items.append(
            Objective(
                id=point.id,
                kind="injection",
                description=point.description,
                hint=point.goal,
                victim_prompt=point.victim_prompt,
                forbidden_tools=point.forbidden_tools,
            )
        )
    return items
