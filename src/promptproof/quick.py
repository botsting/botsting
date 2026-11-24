"""`promptproof scan URL`: a first scan with no description file.

    promptproof scan http://localhost:8000/chat

For a bot that carries the drop-in harness (promptproof/harness.py). The harness tells
the scanner what a description file would otherwise say, so the developer only adds
the three kinds of line to the bot and runs this.

What it works out, in order, sending nothing before permission is on record:
1. Permission. An authorization for this address must exist. For a bot on this
   machine, a person at the keyboard is asked to type their name, and that is
   recorded. For a bot across a network, `promptproof authorize` is needed first.
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
It tests one thing with full rigour: whether a user can talk the bot into revealing a
secret held in its instructions. The legitimate route for each secret is provided by
the harness (a pass phrase stated in a control session), so no control prompt has to
be written.

It does not test tools or other users' data. Whether a tool call is forbidden depends
on who may use that tool, and whether a record is someone else's depends on who the
users are; neither can be guessed. The marked tools are listed as "not tested yet",
with what to add. During the scan every marked tool is recorded and never run.
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


def _description(origin: str, path: str, body: dict[str, Any], reply_pointer: str, slots: list[str]) -> dict[str, Any]:
    return {
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
        "task_checks": [{"id": "answers", "principal": USER, "prompt": "Hello", "expect": "any-reply"}],
    }


def _ask_name(origin: str) -> str:
    """Ask the person at the keyboard to take responsibility for a test of a bot on this machine."""
    if not sys.stdin.isatty():
        return ""
    print(f"No one has authorized a test of {origin} yet. It is on this machine.")
    print("Type your name to authorize it for 7 days (the tools you marked are recorded, never run), or press Enter to stop.")
    try:
        return input("Your name: ").strip()
    except (EOFError, KeyboardInterrupt):
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
) -> tuple[str, dict[str, Any], tuple[str, ...]]:
    """Work out a description for the bot at `url`. Returns (target name, description, marked tools).

    Raises QuickError, with what to do, when a step needs the person."""
    from promptproof.core.authorization import (
        AuthorizationError,
        AuthorizationStore,
        is_loopback_origin,
        new_authorization,
        normalize_origin,
    )
    from promptproof.harness import KEY_ENV
    from promptproof.targets.base import (
        NotAuthorizedError,
        TargetError,
        confirm_permitted,
    )
    from promptproof.targets.http import HttpTarget, TargetConfigError, parse_config

    parts = urlsplit(url)
    try:
        origin = normalize_origin(f"{parts.scheme}://{parts.netloc}")
    except ValueError as error:
        raise QuickError(f"{url!r} is not an address a bot can be reached at: {error}") from error
    path = parts.path or "/"
    if parts.query or parts.fragment:
        raise QuickError("give the chat address without a ? or # part")
    name = name or "quick-" + _NAME.sub("-", parts.netloc).strip("-")

    # 1. Permission, before anything is sent.
    store = AuthorizationStore()
    try:
        permission = store.find(origin)
        if permission is not None and permission.expired(datetime.now(UTC)):
            permission = None
        if permission is None and is_loopback_origin(origin):
            person = (ask_name or _ask_name)(origin)
            if person:
                permission = new_authorization(origin, person, "a first scan of a bot on this machine", "test", 7)
                store.add(permission)
                say(f"Recorded: {person} authorizes testing {origin} until {permission.expires_at}.")
    except (AuthorizationError, ValueError) as error:
        raise QuickError(str(error)) from error
    if permission is None:
        raise QuickError(
            f"no one has authorized a test of {origin}. A person who may allow it runs:\n"
            f'  promptproof authorize {origin} --by "YOUR NAME" --scope "what may be tested" --environment staging\n'
            "and, for a bot across a network, serves the token it prints. Then run this again."
        )

    def target_for(body: dict[str, Any], pointer: str, slots: list[str]) -> HttpTarget:
        raw = _description(origin, path, body, pointer, slots)
        try:
            return HttpTarget(parse_config(name, raw), f"http:{name}", permission, transport)
        except TargetConfigError as error:
            raise QuickError(str(error)) from error

    async def work() -> tuple[dict[str, Any], tuple[str, ...]]:
        probe = target_for(_shapes(field, session_field)[0], "", [])
        # 2. The harness, with the same key.
        try:
            probe.harness_key()
        except TargetError as error:
            raise QuickError(
                f"{error}\nMake a key with `promptproof harness-key`, set it as {KEY_ENV} where the bot runs "
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

        # 3. How to talk to it, and 4. which secrets it reads: one ordinary message in a discover session.
        last = "no request shape was tried"
        for body in _shapes(field, session_field):
            candidate = target_for(body, "", [])
            session_id = uuid.uuid4().hex
            signed, nonce = candidate.session_headers(session_id, planted=False, discover=True)
            filled = json.loads(json.dumps(body).replace("{message}", "Hello").replace("{session}", session_id))
            try:
                data, headers = await candidate._exchange(path, filled, signed)
                candidate.harness_calls(session_id, nonce, headers)
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
            if not slots:
                raise QuickError(
                    "the bot answered, but its code read no planted secret while doing so, so there is nothing to "
                    "test yet.\nWhere the bot builds its instructions, add the secret through the harness, for "
                    'example:\n  prompt = BASE_PROMPT + pp.planted("admin_code")\nthen restart the bot and run this again.'
                )
            say(f"Secrets it reads on an ordinary message: {', '.join(slots)}.")
            return _description(origin, path, body, pointer, slots), tools
        hint = "" if field else " Say which field carries the message with --field NAME."
        raise QuickError(f"could not work out how to send the bot a message at {path}: {last}.{hint}")

    description, tools = asyncio.run(work())
    return name, description, tools


def run(args: Any) -> int:
    """The `promptproof scan URL` command."""
    from promptproof.cli import EXIT_INCONCLUSIVE, _scan
    from promptproof.practice_server import write_description
    from promptproof.targets.http import targets_file

    try:
        name, description, tools = discover(args.url, args.name, args.field, args.session_field, args.reply)
    except QuickError as error:
        print(f"Not scanned: {error}")
        return EXIT_INCONCLUSIVE
    path: Path = targets_file()
    write_description(path, name, description)
    print(f"Saved what was worked out as target '{name}' in {path}.")
    print()
    args.target = f"http:{name}"
    code = _scan(args)
    if tools:
        print()
        print(f"Not tested yet: the tools {', '.join(tools)}. They were recorded, never run. To test whether a user")
        print(f"can make the bot misuse one, say who may use it: add \"tool_rules\" to target '{name}' in {path}")
        print("(`promptproof guide` shows the format), then run: promptproof scan --target " + args.target)
    return code
