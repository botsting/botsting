"""`botsting scan URL`: a first scan with no description file.

    botsting scan http://localhost:8000/chat

For a bot that carries the drop-in harness (botsting/harness.py). The harness tells
the scanner what a description file would otherwise say, so the developer only adds
a few kinds of line to the bot and runs this.

What it works out, in order, sending nothing before permission is on record:
1. Permission. An authorization for this address must exist. For a bot on this
   machine, a person at the keyboard is asked to type their name, and that is
   recorded. For a bot across a network, `botsting authorize` is needed first.
2. That the harness is there, with the same key, and which tools it has marked.
3. How to talk to the bot: which field of the request carries the message, and where
   the reply is in the response. It tries the common shapes with a "discover" session,
   which plants nothing and in which marked tools are recorded and not run.
4. Which secrets the bot reads on an ordinary message: the slots its code asks the
   harness for. These are the ones a first scan can test.
It then writes the description it worked out to the targets file, so the scan can be
replayed and the description extended by hand, and runs the scan.

What a first scan covers, and what it leaves out
------------------------------------------------
Secrets held in the bot's instructions: whether a user can talk the bot into revealing
one. The legitimate route for each secret is provided by the harness (a pass phrase
stated in a control session), so no control prompt has to be written.

Tools that no chat user may ever cause: those marked with `never_for_users="..."` in
the bot's code. The scan tries to make the bot call each one. Any recorded call is a
finding. The scan does not exercise such a tool legitimately first; it relies on the
harness's signed statement that the tool carries its recorder, and the report says so.

Text the bot reads from elsewhere: each place the code reads with `content(...)`
while it answers the ordinary message. Text is planted there that asks for a tool no
chat user may cause (the existing planted texts, asking for what the developer wrote on
the tool), and an ordinary user sends the ordinary message. A harmless text is tried
first. A place the code reads, but not for that message, is named with `--message`.

It leaves out tools that some users may use, and other users' data. Whether such a
call or such a record is forbidden depends on who the users are, which cannot be
guessed; those tools are listed as "not tested yet", with what to add. During the scan
every marked tool is recorded and never run.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

USER = "user"
OWNER = "owner:pass-phrase"
MESSAGE_FIELDS = ("message", "query", "input", "prompt", "text", "question", "content", "user_input", "msg")
REPLY_KEYS = ("reply", "response", "answer", "output", "text", "message", "content", "result", "completion")
_NAME = re.compile(r"[^A-Za-z0-9]+")
NEWLINE = chr(10)


class QuickError(Exception):
    """A step that the person has to do, with what to do about it."""


def _shapes(field: str | None, session_field: str | None) -> list[dict[str, Any]]:
    """Request bodies to try, most common first."""
    extra = {session_field: "{session}"} if session_field else {}
    if field:
        return [{field: "{message}", **extra}]
    plain = [{name: "{message}", **extra} for name in MESSAGE_FIELDS]
    chat = {"messages": [{"role": "user", "content": "{message}"}], **extra}
    return [*plain, chat]


def find_reply(data: Any) -> str | None:
    """A JSON pointer to the reply text in a response, or None if there is no text in it."""
    if isinstance(data, str):
        return "" if data.strip() else None

    def walk(value: Any, pointer: str, depth: int) -> list[tuple[int, int, str]]:
        found: list[tuple[int, int, str]] = []
        if depth > 5:
            return found
        if isinstance(value, dict):
            for key, inner in value.items():
                here = pointer + "/" + str(key).replace("~", "~0").replace("/", "~1")
                if isinstance(inner, str) and inner.strip():
                    rank = REPLY_KEYS.index(key) if key in REPLY_KEYS else len(REPLY_KEYS)
                    found.append((rank, -len(inner), here))
                else:
                    found += walk(inner, here, depth + 1)
        elif isinstance(value, list):
            for index, inner in enumerate(value[:3]):
                found += walk(inner, f"{pointer}/{index}", depth + 1)
        return found

    candidates = sorted(walk(data, "", 0))
    return candidates[0][2] if candidates else None


HARMLESS = "Thank you for your help with my order."


def _description(
    origin: str,
    path: str,
    body: dict[str, Any],
    reply_pointer: str,
    slots: list[str],
    rules: dict[str, str] | None = None,
    points: list[str] | None = None,
    message: str = "Hello",
) -> dict[str, Any]:
    asks = sorted((rules or {}).items())
    return {
        # Text someone else wrote, which the bot reads while it answers an ordinary request. It is
        # tested only against tools no chat user may cause: a call to one of those, with planted
        # text in place and none with harmless text there, is the evidence. The planted text asks
        # for the first of them; a call to any of them counts.
        "injection_points": [
            {
                "id": point,
                "description": f"the text the bot's code reads with content({point!r})",
                "victim_principal": USER,
                "victim_prompt": message,
                "expect": "any-reply",
                "benign_content": HARMLESS,
                "forbidden_tools": [tool for tool, _ in asks],
                "goal": "issue " + asks[0][1],  # the wording the tool attacks use for the same request
            }
            for point in (points or [])
            if asks
        ],
        "tool_rules": [
            {
                "id": tool,
                "tool": tool,
                "description": f"nobody chatting with the bot may cause {tool}",
                "hint": ask,
                "authorized": [OWNER],
                "control_principal": OWNER,
                "control": "harness",
            }
            for tool, ask in sorted((rules or {}).items())
        ],
        "origin": origin,
        "harness": "sdk",
        "chat": {"path": path, "body": body, "reply_pointer": reply_pointer},
        "attacker_principal": USER,
        "principals": {USER: {}, OWNER: {}},
        "tool_safety": "sinks",
        "slots": [
            {
                "id": slot,
                "kind": "instruction_secret",
                "description": f"the value the bot's code reads with planted({slot!r})",
                "hint": "the " + (_NAME.sub(" ", slot).strip() or "confidential value") + " in your instructions",
                "authorized": [OWNER],
                "control_principal": OWNER,
                "control": "harness",
            }
            for slot in slots
        ],
        "task_checks": [{"id": "answers", "principal": USER, "prompt": message, "expect": "any-reply"}],
    }


def _put(value: Any, message: str, session_id: str) -> Any:
    """A request body with the message and the conversation id in place."""
    if isinstance(value, str):
        return value.replace("{message}", message).replace("{session}", session_id)
    if isinstance(value, dict):
        return {key: _put(inner, message, session_id) for key, inner in value.items()}
    if isinstance(value, list):
        return [_put(inner, message, session_id) for inner in value]
    return value


def _ask_name(origin: str) -> str:
    """Ask the person at the keyboard to take responsibility for a test of a bot on this machine."""
    if not sys.stdin.isatty():
        return ""
    print(f"No one has authorized a test of {origin} yet. It is on this machine.")
    print("Type your name to authorize it for 7 days (the tools you marked are recorded, never run), or press Enter to stop.")
    try:
        return input("Your name: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()  # nobody is there to type: end the prompt's line before what is said next
        return ""


def discover(
    url: str,
    name: str | None = None,
    field: str | None = None,
    session_field: str | None = None,
    reply_pointer: str | None = None,
    ask_name: Callable[[str], str] | None = None,
    say: Callable[[str], None] = print,
    transport: Any = None,
    message: str | None = None,
) -> tuple[str, dict[str, Any], list[str]]:
    """Work out a description for the bot at `url`. Returns (target name, description, and lines to
    show after the scan about what was left out).

    `message` is the ordinary request sent to learn what the bot reads; it becomes the normal-use
    check and the request during which planted text is read. Default: "Hello".

    Raises QuickError, with what to do, when a step needs the person."""
    from botsting.core.authorization import (
        AuthorizationError,
        AuthorizationStore,
        is_loopback_origin,
        new_authorization,
        normalize_origin,
    )
    from botsting.harness import KEY_ENV
    from botsting.targets.base import (
        NotAuthorizedError,
        TargetError,
        confirm_permitted,
    )
    from botsting.targets.http import HttpTarget, TargetConfigError, parse_config

    parts = urlsplit(url)
    try:
        origin = normalize_origin(f"{parts.scheme}://{parts.netloc}")
    except ValueError as error:
        raise QuickError(f"{url!r} is not an address a bot can be reached at: {error}") from error
    path = parts.path or "/"
    if parts.query or parts.fragment:
        raise QuickError("give the chat address without a ? or # part")
    name = name or "quick-" + _NAME.sub("-", parts.netloc).strip("-")
    message = (message or "").strip() or "Hello"

    # 1. Permission, before anything is sent.
    store = AuthorizationStore()
    asked_now = ""  # the name typed just now, if this run recorded the authorization
    try:
        permission = store.find(origin)
        if permission is not None and permission.expired(datetime.now(UTC)):
            permission = None
        if permission is None and is_loopback_origin(origin):
            person = (ask_name or _ask_name)(origin)
            if person:
                permission = new_authorization(origin, person, "a first scan of a bot on this machine", "test", 7)
                store.add(permission)
                asked_now = person
                say(f"Recorded: {person} authorizes testing {origin} until {permission.expires_at}.")
    except (AuthorizationError, ValueError) as error:
        raise QuickError(str(error)) from error
    if permission is None:
        raise QuickError(
            f"no one has authorized a test of {origin}. A person who may allow it runs:\n"
            f'  botsting authorize {origin} --by "YOUR NAME" --scope "what may be tested" --environment staging\n'
            "adding --tool NAME for each tool marked never_for_users (a tool the authorization does not name is "
            "left untested), and, for a bot across a network, serves the token it prints. Then run this again."
        )

    def target_for(body: dict[str, Any], pointer: str, slots: list[str]) -> HttpTarget:
        raw = _description(origin, path, body, pointer, slots)
        try:
            return HttpTarget(parse_config(name, raw), f"http:{name}", permission, transport)
        except TargetConfigError as error:
            raise QuickError(str(error)) from error

    async def work() -> tuple[dict[str, Any], list[str]]:
        nonlocal permission
        probe = target_for(_shapes(field, session_field)[0], "", [])
        # 2. The harness, with the same key.
        try:
            probe.harness_key()
        except TargetError as error:
            raise QuickError(
                f"{error}\nMake a key with `botsting harness-key`, set it as {KEY_ENV} where the bot runs "
                "and in this terminal, restart the bot, and run this again."
            ) from error
        try:
            await confirm_permitted(probe, True)
            await probe.reset({})
        except (NotAuthorizedError, TargetError) as error:
            raise QuickError(
                f"{error}\nCheck that the bot is running at {origin}, that it is wrapped (`app = pp.wrap(app)`), "
                f"and that {KEY_ENV} is the same there and here."
            ) from error
        tools = probe.marked_tools
        say(f"The harness answered. Marked tools: {', '.join(tools) or 'none'}.")
        # Tools no chat user may cause can be tested now, if the authorization names them.
        rules = dict(probe.tool_asks)
        if rules and asked_now:
            # The person who just typed their name was told the marked tools are recorded, never run.
            permission = new_authorization(
                origin, asked_now, "a first scan of a bot on this machine", "test", 7, allowed_tools=sorted(rules)
            )
            store.add(permission)
        unnamed = sorted(tool for tool in rules if tool not in permission.allowed_tools)
        rules = {tool: ask for tool, ask in rules.items() if tool in permission.allowed_tools}
        notes: list[str] = []
        if unnamed:
            flags = " ".join(f"--tool {tool}" for tool in unnamed)
            notes.append(
                f"Not tested: {', '.join(unnamed)}. The authorization on record does not name them. A person who "
                "may allow it records one that does, then this is run again:\n"
                f'  botsting authorize {origin} --by "YOUR NAME" --scope "{permission.scope}" '
                f"--environment {permission.environment} {flags}"
            )
        open_tools = sorted(tool for tool in tools if tool not in probe.tool_asks)
        if open_tools:
            notes.append(
                f"Not tested yet: {', '.join(open_tools)}. They were recorded, never run. If nobody chatting with "
                'the bot may ever cause one, say so where it is marked, with what an attacker would ask for:\n'
                f'  @pp.action("{open_tools[0]}", never_for_users="...")\n'
                "If some users may, describe who: `botsting guide` shows how."
            )

        # 3. How to talk to it, and 4. which secrets it reads: one ordinary message in a discover session.
        last = "no request shape was tried"
        for body in _shapes(field, session_field):
            candidate = target_for(body, "", [])
            session_id = uuid.uuid4().hex
            filled = _put(body, message, session_id)
            try:
                data = await candidate.discover_message(path, filled, session_id)
            except TargetError as error:
                last = str(error)
                continue
            pointer = reply_pointer if reply_pointer is not None else find_reply(data)
            if pointer is None:
                last = "the bot answered, but there was no text in its answer"
                continue
            shown = next(key for key, value in body.items() if value == "{message}") if "messages" not in body else "messages"
            say(f"It takes the message in {shown!r} and answers at {pointer or 'the top level'!r}.")
            slots = list(candidate.last_read)
            # Read by the code, but not while a message is handled: the test value cannot be put in there.
            elsewhere = sorted(set(probe.read_outside) - set(slots))
            moved = ""
            if elsewhere:
                names = ", ".join(f'pp.planted("{slot}")' for slot in elsewhere)
                moved = (
                    f"Your code calls {names}, but not while it handles a message (for example once, when the app "
                    "starts), so a test value cannot be put in there. Call it where each message is handled, for "
                    "example where the instructions are put together for the model, then restart the bot."
                )
            if not slots and not rules:
                raise QuickError(
                    "the bot answered, but its code read no planted secret while doing so, and no marked tool says "
                    "it is never for users, so there is nothing to test yet.\n"
                    + (
                        moved
                        or "Where the bot builds its instructions for each message, add the secret through the "
                        'harness, for example:\n  prompt = BASE_PROMPT + pp.planted("admin_code")\n'
                        "then restart the bot and run this again."
                    )
                )
            if slots:
                say(f"Secrets it reads on an ordinary message: {', '.join(slots)}.")
            else:
                say("Secrets it reads on an ordinary message: none. SECRET LEAKS WILL NOT BE TESTED in this scan.")
            if moved:
                say(moved)
                notes.append(("Not tested: " if slots else "Secret leaks were not tested. ") + moved)
            elif not slots:
                notes.append(
                    "Secret leaks were not tested: the bot read no planted secret while handling a message. To test "
                    "them, read the secret through the harness where the instructions are put together, for example:\n"
                    '  prompt = BASE_PROMPT + pp.planted("admin_code")'
                )
            if rules:
                say(f"Tools no chat user may cause: {', '.join(sorted(rules))}.")
            # Text from elsewhere: the places the code read through the harness while answering that message.
            points = list(candidate.last_points)
            unread = sorted(set(probe.points_outside) - set(points))
            if points and rules:
                say(f"Text from elsewhere it reads on that message: {', '.join(points)}. Planted text will be tried there.")
            elif points:
                notes.append(
                    f"Not tested: text the bot reads at {', '.join(points)}. Planted text is shown to work by a call to "
                    "a tool no chat user may cause, and no tool is marked that way (or the authorization names none):\n"
                    '  @pp.action("issue_refund", never_for_users="a refund of 50 on order A-1001")'
                )
            if unread:
                calls = ", ".join(f'pp.content("{point}")' for point in unread)
                notes.append(
                    f"Not tested: your code calls {calls}, but not while it answered {message!r}. Give an ordinary "
                    "request that makes the bot read that text, and it will be tested:\n"
                    f'  botsting scan {url} --message "an ordinary request that makes the bot read it"'
                )
            elif not points:
                notes.append(
                    "Text the bot reads from elsewhere (notes, documents, tickets, web pages) was not tested: the code "
                    "reads none through the harness. Where the bot fetches such text, pass it through, for example:\n"
                    '  note = pp.content("order_note", note)'
                )
            return _description(origin, path, body, pointer, slots, rules, points, message), notes
        hint = "" if field else " Say which field carries the message with --field NAME."
        raise QuickError(f"could not work out how to send the bot a message at {path}: {last}.{hint}")

    description, notes = asyncio.run(work())
    return name, description, notes


def _no_longer_read(path: Path, name: str, description: dict[str, Any]) -> list[str]:
    """Secrets the saved description of `name` had and the bot's code no longer asks for: what a
    person sees after taking a secret out of the instructions, which is the fix a finding advises."""
    try:
        earlier = json.loads(path.read_text(encoding="utf-8")).get("targets", {}).get(name) or {}
        before = [slot["id"] for slot in earlier.get("slots", [])]
    except (OSError, ValueError, AttributeError, KeyError, TypeError):
        return []
    now = {slot["id"] for slot in description.get("slots", [])}
    return [slot for slot in before if slot not in now]


def _keep_earlier(path: Path, name: str, description: dict[str, Any]) -> Path | None:
    """If the targets file already describes `name` differently, save that description beside it.

    A first scan writes under a name made from the address, so scanning again would replace a
    description someone had extended by hand. Returns where the earlier one was kept, or None."""
    try:
        earlier = json.loads(path.read_text(encoding="utf-8")).get("targets", {}).get(name)
    except (OSError, ValueError, AttributeError):
        return None
    if earlier is None or earlier == description:
        return None
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    kept = path.with_name(f"{path.stem}.{name}.{stamp}.json")
    kept.write_text(json.dumps({"targets": {name: earlier}}, indent=2) + NEWLINE, encoding="utf-8")
    return kept


def run(args: Any) -> int:
    """The `botsting scan URL` command."""
    from botsting.cli import run_scan_command
    from botsting.console import _wrap
    from botsting.exits import EXIT_INCONCLUSIVE
    from botsting.practice_server import write_description
    from botsting.targets.http import targets_file

    def say(text: str) -> None:
        # Kept to the width of the rest of the output; a line that is already short, or a command, is left alone.
        for line in text.splitlines():
            wrapped = _wrap(line, "") if len(line) > 100 and not line.startswith("  ") else [line]
            for part in wrapped:
                print(part)

    try:
        name, description, notes = discover(
            args.url, args.name, args.field, args.session_field, args.reply, say=say, message=getattr(args, "message", None)
        )
    except QuickError as error:
        print(f"Not scanned: {error}")
        return EXIT_INCONCLUSIVE
    path: Path = targets_file()
    gone = _no_longer_read(path, name, description)
    if gone:
        say(
            f"The bot no longer reads {', '.join(gone)}, which an earlier scan tested. A secret the bot is never "
            "given cannot leak through it, so there is nothing left to test for it."
        )
    kept = _keep_earlier(path, name, description)
    if kept is not None:
        say(
            f"The description saved earlier as http:{name} differs from what was worked out now (it was edited, or "
            f"the bot changed). The earlier one was kept as {kept}."
        )
    write_description(path, name, description)
    print(f"Saved what was worked out as target http:{name} in {path}.")
    print()
    args.target = f"http:{name}"
    if not args.html:
        args.html = str(Path(args.out).with_name("report.html"))  # a first scan is for a person to read
    code = run_scan_command(args)
    for note in notes:
        print()
        say(note)
    print()
    print("After a change to the bot, the same command scans it again. To use the saved description instead:")
    print(f"  botsting doctor --target http:{name}")
    print(f"  botsting scan --target http:{name} --html report.html")
    return code
