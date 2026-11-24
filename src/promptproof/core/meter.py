"""The limits a scan obeys, and the waiting that stops when a limit is passed.

`ScanConfig` says what a scan may spend and who ran it; `Meter` counts the spending,
refuses the next message once a limit is passed, and waits for the target only while
time and permission last. `run_to_completion` runs the whole thing without waiting on
operations that were asked to stop and ignored the request.
"""

from __future__ import annotations

import asyncio
import math
import time
from collections.abc import Awaitable, Callable, Coroutine, Mapping
from dataclasses import dataclass, field
from typing import TypeVar

from promptproof.core.models import INDEPENDENCE_LEVELS, Independence, Reply
from promptproof.targets.base import NotAuthorizedError, Session, Target, as_reply, confirm_permitted

_T = TypeVar("_T")
_CANCEL_POLL_SECONDS = 0.05
# How long an operation that was asked to stop is given to unwind before it is abandoned.
_ABANDON_GRACE_SECONDS = 0.25


@dataclass(frozen=True)
class ScanConfig:
    discovery_runs: int = 1  # attempts per attack while searching
    reproduction_trials: int = 5  # replays of each attack that worked
    # Limits on what a scan may spend. Reaching one stops the scan, which then reports
    # itself as stopped early; it never reports the untested remainder as fine.
    max_messages: int = 5000
    max_tool_calls: int = 500
    max_seconds: float = 3600.0
    # Optional caps on target messages sent during discovery only (leaving preflight and
    # reproduction replays untouched), used for equal-budget comparisons between strategies.
    discovery_message_budget: int | None = None
    discovery_budget_per_objective: int | None = None
    # Polled before every message. Returning True stops the scan the same way.
    cancelled: Callable[[], bool] | None = field(default=None, compare=False)
    # Audit metadata recorded in the report.
    tester: str = ""
    independence: Independence = "self"

    def __post_init__(self) -> None:
        if self.discovery_runs < 1 or self.reproduction_trials < 1:
            raise ValueError("discovery_runs and reproduction_trials must be at least 1")
        if self.max_messages < 1 or self.max_tool_calls < 0 or not math.isfinite(self.max_seconds) or self.max_seconds <= 0:
            raise ValueError("limits must be positive (max_tool_calls may be 0)")
        if self.discovery_message_budget is not None and self.discovery_message_budget < 1:
            raise ValueError("discovery_message_budget must be at least 1")
        if self.discovery_budget_per_objective is not None and self.discovery_budget_per_objective < 1:
            raise ValueError("discovery_budget_per_objective must be at least 1")
        if not isinstance(self.tester, str):
            raise ValueError("tester must be text")
        if self.independence not in INDEPENDENCE_LEVELS:
            raise ValueError(f"independence must be one of {', '.join(INDEPENDENCE_LEVELS)}")


class _Stop(Exception):
    """A limit was reached or the scan was cancelled. Carries the reason."""


class Meter:
    """Counts what a scan spends and refuses the next message once a limit is passed.

    A limit on tool calls cannot stop the calls one message triggers; it stops the scan
    before the next message. That is why tools must be sinks before any of this runs.
    """

    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()
        self.messages = 0
        self.tool_calls = 0
        self.stop_reason = ""
        self._started = time.monotonic()
        # Checks permission to reach the target; installed by `guard`.
        self._guard: Callable[[bool], Awaitable[None]] | None = None

    def poll(self, about_to_send: bool = False) -> str:
        """Note a reason to stop, if there is one, and return it. Never raises.

        Called before every message, and again after every reply and before the final
        status, so a cancel or a deadline that arrives during the last message of a scan
        is not lost.
        """
        config = self.config
        if not self.stop_reason:
            if config.cancelled is not None and config.cancelled():
                self.stop_reason = "cancelled"
            elif about_to_send and self.messages >= config.max_messages:
                self.stop_reason = f"message limit of {config.max_messages} reached"
            elif about_to_send and self.tool_calls > config.max_tool_calls:
                self.stop_reason = f"tool-call limit of {config.max_tool_calls} passed"
            elif time.monotonic() - self._started >= config.max_seconds:
                self.stop_reason = f"time limit of {config.max_seconds:g} seconds reached"
        return self.stop_reason

    def check(self) -> None:
        if self.poll(about_to_send=True):
            raise _Stop(self.stop_reason)

    def guard(self, target: Target) -> None:
        """From now on, check permission to reach `target` before every operation on it.

        Always replaces the previous check: a meter that is reused for another target must
        never go on checking the first target's permission.
        """
        self._guard = lambda fresh: confirm_permitted(target, fresh)

    async def start(self, target: Target) -> None:
        """At the start of a scan or replay: fetch the proof of control afresh, within the limits.

        Raises NotAuthorizedError if permission is missing, so nothing starts. A limit or a
        cancel that arrives during the check is recorded as the reason the scan stopped.
        """
        self.guard(target)
        try:
            await self.within_deadline(confirm_permitted(target, True), gated=False)
        except _Stop:
            pass

    async def within_deadline(self, awaitable: Awaitable[object], gated: bool = True) -> object:
        """Await something from the target, but not past the time limit, and only while permitted.

        Without this a target that never answers would hold the scan forever: the limit
        would only be looked at between messages, and there would be no next message.
        Permission is checked first: an authorization that expired or whose proof was
        taken down since the last operation stops the scan here, before anything is sent.
        """

        def drop() -> None:
            close = getattr(awaitable, "close", None)
            if close is not None:
                close()

        if self.poll():  # cancelled or out of time: do not start anything new
            drop()
            raise _Stop(self.stop_reason)
        if gated and self._guard is not None:
            try:
                await self.within_deadline(self._guard(False), gated=False)
            except NotAuthorizedError as exc:
                drop()
                self.stop_reason = self.stop_reason or f"authorization no longer valid: {exc}"
                raise _Stop(self.stop_reason) from exc
            except _Stop:
                drop()
                raise
        config = self.config
        task = asyncio.ensure_future(awaitable)
        reason = ""
        try:
            while not reason:
                remaining = config.max_seconds - (time.monotonic() - self._started)
                if remaining <= 0:
                    reason = f"time limit of {config.max_seconds:g} seconds reached while waiting for the target"
                    break
                # Wait in short slices so a cancel is noticed while the target is still thinking.
                done, _ = await asyncio.wait({task}, timeout=min(remaining, _CANCEL_POLL_SECONDS))
                if done:
                    return task.result()
                if config.cancelled is not None and config.cancelled():
                    reason = "cancelled"
        except BaseException:
            task.cancel()
            raise
        # Ask the pending operation to stop, give it a moment to unwind, then stop waiting
        # whether or not it has. Cancellation in asyncio is cooperative: a target adapter
        # that catches the request and carries on cannot be forced to stop from here. It is
        # left behind, the report says so, and `run_to_completion` does not wait for it
        # either. None of this can undo what the target has already done on its side.
        task.cancel()
        await asyncio.wait({task}, timeout=_ABANDON_GRACE_SECONDS)
        if task.done():
            if not task.cancelled():
                task.exception()  # retrieved so it is not reported as never looked at
        else:
            task._log_destroy_pending = False  # type: ignore[attr-defined]
            reason += "; the target did not stop when asked and was left running"
        self.stop_reason = self.stop_reason or reason
        raise _Stop(self.stop_reason)

    async def reset(self, target: Target, fixtures: Mapping[str, str], content: Mapping[str, str] | None = None) -> None:
        # Targets without injection points may take the fixtures alone.
        await self.within_deadline(target.reset(fixtures) if content is None else target.reset(fixtures, content))

    async def open(self, target: Target, principal: str) -> Session:
        return await self.within_deadline(target.open_session(principal))  # type: ignore[return-value]

    async def send(self, session: Session, text: str) -> Reply:
        self.check()
        self.messages += 1
        reply = as_reply(await self.within_deadline(session.send(text)))  # type: ignore[arg-type]
        self.tool_calls += len(reply.tool_calls)
        self.poll()
        return reply


def run_to_completion(main: Coroutine[object, object, _T]) -> _T:
    """Run a scan or replay to its result, like `asyncio.run`, without waiting on what it abandoned.

    `asyncio.run` finishes by cancelling every task still pending and waiting for all
    of them, with no limit. A target operation that ignored cancellation would then
    hold the process open after the scan had already given up on it, which would
    defeat both the time limit and Ctrl+C. Here leftover tasks get the same short
    grace period and are then dropped with the event loop.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(main)
    finally:
        leftover = [task for task in asyncio.all_tasks(loop) if not task.done()]
        for task in leftover:
            task.cancel()
        if leftover:
            loop.run_until_complete(asyncio.wait(leftover, timeout=_ABANDON_GRACE_SECONDS))
            for task in leftover:
                if not task.done():
                    task._log_destroy_pending = False  # type: ignore[attr-defined]
        # Async generators still open (a streaming adapter, say) get to run their cleanup,
        # under the same limit so that a stuck one cannot hold the process either.
        try:
            loop.run_until_complete(asyncio.wait_for(loop.shutdown_asyncgens(), timeout=_ABANDON_GRACE_SECONDS))
        except (TimeoutError, RuntimeError):
            pass
        loop.close()
