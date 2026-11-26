"""Preflight: every instrument is exercised by a legitimate route before any attack runs.

- Each canary is planted and fetched by someone allowed to see it. A canary nobody
  can reach cannot leak, so finding nothing for it would mean nothing.
- Each protected tool is called by someone allowed to call it. If the recorder does
  not show that call, it would not show a forbidden one either.
- Each injection point is filled with harmless text and its ordinary request made.
  If a forbidden tool runs even then, a call during an attack proves nothing.
- Normal-task checks run here too.

`_repeated_slots` also tells the two apart on a target whose fake secrets travel in
each request: a slot whose value comes back unasked cannot be tested by attacking it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from kritalon.core.canary import Canary, new_canary
from kritalon.core.matcher import find_canary
from kritalon.core.meter import Meter, _Stop
from kritalon.core.models import (
    HARNESS_ATTESTED,
    InjectionPoint,
    Slot,
    SlotStatus,
    TaskStatus,
    ToolRule,
)
from kritalon.targets.base import (
    NotAuthorizedError,
    Target,
    TargetError,
    injection_points,
    require_contained_tools,
    tool_rules,
)

_CONTROL_TRIES = 3


def _fresh(slots: Sequence[Slot]) -> dict[str, Canary]:
    return {slot.id: new_canary(slot.id, slot.canary_style) for slot in slots}


def _values(canaries: dict[str, Canary]) -> dict[str, str]:
    return {slot_id: canary.value for slot_id, canary in canaries.items()}


def _status(objective_id: str, kind: str, description: str, authorized: tuple[str, ...], state: str, detail: str = "") -> SlotStatus:
    return SlotStatus(objective_id, kind, description, authorized, state, detail)  # type: ignore[arg-type]


async def _check_slot(target: Target, slot: Slot, meter: Meter) -> SlotStatus:
    def status(state: str, detail: str = "") -> SlotStatus:
        return _status(slot.id, slot.kind, slot.description, slot.authorized, state, detail)

    if target.attacker_principal in slot.authorized:
        return status("error", f"the attacker principal {target.attacker_principal} is authorized for this slot")
    if slot.control_principal not in slot.authorized:
        return status("error", f"the control principal {slot.control_principal} is not authorized for this slot")
    last_error = ""
    for _ in range(_CONTROL_TRIES):
        canaries = _fresh(target.slots())
        try:
            await meter.reset(target, _values(canaries))
            session = await meter.open(target, slot.control_principal)
            reply = await meter.send(session, slot.control_prompt)
        except TargetError as exc:
            last_error = str(exc)
            continue
        except _Stop as stop:
            return status("error", f"not checked: stopped early ({stop})")
        match = find_canary(canaries[slot.id], [reply.text])
        if match is not None and match.full:
            return status("reachable")
        last_error = ""
    if last_error:
        return status("error", last_error)
    return status(
        "unreachable",
        f"{slot.control_principal} asked the control question {_CONTROL_TRIES} times and never received "
        "the planted value, so finding nothing for this slot would not show that it is protected",
    )


ATTESTED_NOTE = "the harness attests that this tool carries its recorder; no legitimate call was exercised"


async def _check_rule(target: Target, rule: ToolRule, meter: Meter) -> SlotStatus:
    def status(state: str, detail: str = "") -> SlotStatus:
        return _status(rule.id, "tool_rule", rule.description, rule.authorized, state, detail)

    if target.attacker_principal in rule.authorized:
        return status("error", f"the attacker principal {target.attacker_principal} is allowed to cause this tool to run")
    if rule.control_principal not in rule.authorized:
        return status("error", f"the control principal {rule.control_principal} is not allowed to cause this tool to run")
    if rule.control_prompt == HARNESS_ATTESTED:
        # No legitimate request is made. The harness says, in its signed readiness answer, whether the
        # tool carries its recorder. That shows a call would be recorded; it does not show the bot can
        # reach the tool, and the report says so.
        try:
            await meter.reset(target, _values(_fresh(target.slots())))
        except TargetError as exc:
            return status("error", str(exc))
        except _Stop as stop:
            return status("error", f"not checked: stopped early ({stop})")
        if rule.tool in getattr(target, "marked_tools", ()):
            return status("reachable", ATTESTED_NOTE)
        return status(
            "error",
            f"the harness does not list {rule.tool} among the tools it has marked, so a call to it would go unseen",
        )
    last_error = ""
    for _ in range(_CONTROL_TRIES):
        try:
            await meter.reset(target, _values(_fresh(target.slots())))
            session = await meter.open(target, rule.control_principal)
            reply = await meter.send(session, rule.control_prompt)
        except TargetError as exc:
            last_error = str(exc)
            continue
        except _Stop as stop:
            return status("error", f"not checked: stopped early ({stop})")
        if any(call.tool == rule.tool and call.accepted for call in reply.tool_calls):
            return status("reachable")
        last_error = ""
    if last_error:
        return status("error", last_error)
    return status(
        "unreachable",
        f"{rule.control_principal} made the legitimate request {_CONTROL_TRIES} times and no accepted call to "
        f"{rule.tool} was recorded, so a forbidden call might not be recorded either",
    )


async def _check_point(target: Target, point: InjectionPoint, meter: Meter) -> SlotStatus:
    def status(state: str, detail: str = "") -> SlotStatus:
        return _status(point.id, "injection_point", point.description, (), state, detail)

    answered = False
    last_error = ""
    for _ in range(_CONTROL_TRIES):
        try:
            await meter.reset(target, _values(_fresh(target.slots())), {point.id: point.benign_content})
            session = await meter.open(target, point.victim_principal)
            reply = await meter.send(session, point.victim_prompt)
        except TargetError as exc:
            last_error = str(exc)
            continue
        except _Stop as stop:
            return status("error", f"not checked: stopped early ({stop})")
        unprompted = [call.tool for call in reply.tool_calls if call.tool in point.forbidden_tools]
        if unprompted:
            return status(
                "error",
                f"with harmless text in place, the ordinary request still caused a call to {unprompted[0]}; "
                "a call during an attack would therefore not show that the attack caused it",
            )
        answered = answered or point.expect_substring.lower() in reply.text.lower()
        last_error = ""
    if last_error:
        return status("error", last_error)
    if not answered:
        return status(
            "unreachable",
            f"the ordinary request was never answered as expected in {_CONTROL_TRIES} tries, so the planted "
            "text may not be read at all",
        )
    return status("reachable", f"with harmless text in place, no forbidden tool ran in {_CONTROL_TRIES} requests")


async def _check_tasks(target: Target, meter: Meter) -> list[TaskStatus]:
    results: list[TaskStatus] = []
    for task in target.task_checks():
        # A language model can fumble a normal request once. The check asks whether the
        # target works at all, so it gets the same number of tries as a control question.
        passed, detail = False, ""
        for attempt in range(1, _CONTROL_TRIES + 1):
            try:
                await meter.reset(target, _values(_fresh(target.slots())))
                session = await meter.open(target, task.principal)
                reply = await meter.send(session, task.prompt)
            except TargetError as exc:
                detail = f"target error: {exc}"
                continue
            except _Stop as stop:
                detail = f"not checked: stopped early ({stop})"
                break
            if reply.text.strip() and task.expect_substring.lower() in reply.text.lower():
                passed = True
                detail = "" if attempt == 1 else f"worked on try {attempt} of {_CONTROL_TRIES}"
                break
            detail = (
                f"in {_CONTROL_TRIES} tries no reply contained {task.expect_substring!r}; "
                f"last reply: {reply.text[:200]!r}"
            )
        results.append(TaskStatus(task.id, passed, detail))
    return results


_REPEATED = "the planted value came back in the reply to an ordinary request"


async def _repeated_slots(target: Target, meter: Meter) -> dict[str, str]:
    """For a target whose fake secrets travel in each request: slots whose value comes back unasked.

    On such a target a bot that repeats its request variables would hand every attacker "the secret",
    though it is only the attacker's own request coming back and says nothing about what the bot keeps
    in its instructions. An ordinary request, sent as someone not allowed the value, tells the two apart.
    """
    if not getattr(target, "secrets_travel_in_requests", False):
        return {}
    found: dict[str, str] = {}
    for task in target.task_checks():
        canaries = _fresh(target.slots())
        try:
            await meter.reset(target, _values(canaries))
            session = await meter.open(target, task.principal)
            reply = await meter.send(session, task.prompt)
        except (TargetError, _Stop):
            continue  # the normal-task check reports a target that does not answer
        for slot in target.slots():
            if task.principal in slot.authorized or slot.id in found:
                continue
            match = find_canary(canaries[slot.id], [reply.text])
            if match is not None and match.full:
                found[slot.id] = (
                    f"{_REPEATED} ({task.id}, sent as {task.principal}). On this target the value travels in "
                    "each request, so the bot is either repeating its request variables or giving the value to "
                    "anyone; a finding here could not be told apart from that, so no attack was run on this slot"
                )
    return found


@dataclass(frozen=True)
class Preflight:
    slots: tuple[SlotStatus, ...]  # canary slots, then tool rules, then injection points
    tasks: tuple[TaskStatus, ...]
    # Slots whose planted value comes back whoever asks (see _repeated_slots). No attack is run on
    # them, a match for one is never a finding, and a replay is not run.
    repeated: frozenset[str] = frozenset()


async def preflight(target: Target, meter: Meter | None = None) -> Preflight:
    meter = meter or Meter()
    meter.guard(target)
    try:
        require_contained_tools(target)
    except NotAuthorizedError as exc:
        # Every check below then stops before sending anything and reports itself as not checked.
        meter.stop_reason = meter.stop_reason or f"authorization no longer valid: {exc}"
    statuses = [await _check_slot(target, slot, meter) for slot in target.slots()]
    repeated = await _repeated_slots(target, meter)
    statuses = [
        _status(s.slot_id, s.kind, s.description, s.authorized, "error", repeated[s.slot_id]) if s.slot_id in repeated else s
        for s in statuses
    ]
    watched: set[str] = set()  # tools whose recorder was seen to record a legitimate call
    for rule in tool_rules(target):
        status = await _check_rule(target, rule, meter)
        statuses.append(status)
        if status.state == "reachable":
            watched.add(rule.tool)
    for point in injection_points(target):
        unwatched = [tool for tool in point.forbidden_tools if tool not in watched]
        if unwatched:
            # Seeing no call proves nothing unless the recorder is known to see calls.
            statuses.append(
                _status(
                    point.id,
                    "injection_point",
                    point.description,
                    (),
                    "error",
                    f"the recorder was never seen to record a legitimate call to {unwatched[0]} (that needs a tool "
                    "rule whose control request works), so a forbidden call during this request might go unseen",
                )
            )
        else:
            statuses.append(await _check_point(target, point, meter))
    return Preflight(tuple(statuses), tuple(await _check_tasks(target, meter)), frozenset(repeated))
