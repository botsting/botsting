"""`kritalon mcp`: let a developer's coding assistant set Kritalon up and run it.

This is a Model Context Protocol server over standard input and output. A coding
assistant (Claude Code, Cursor and others) that is connected to it can:

    setup_guide            read how to wire a bot for testing, step by step
    find_tools             list functions in the project that look like risky tools
    check_description      check a target description and say what is wrong with it
    authorization_status   see whether a person has authorized testing an origin
    doctor                 check the whole setup step by step and learn what to fix next
    first_scan             scan a bot that carries the drop-in harness, from its chat address alone
    scan                   run a scan of a described target and get the result and where the reports are
    read_report            read a finished report

    claude mcp add kritalon -- kritalon mcp

What it will not do
-------------------
It never creates or changes an authorization. Permission to test is a person taking
responsibility by name, so it is recorded by a person running `kritalon authorize`
in a terminal. Without one, `scan` is refused for anything but the built-in practice
bots, exactly as on the command line. `first_scan` never asks anyone to type a name,
as the command does for a bot on the developer's own machine: an assistant is not a
person at a keyboard, so it sends nothing until that authorization is on record.

It never edits the project. `find_tools` and `check_description` only read; the
assistant proposes the changes and the developer approves them in their own editor.

It reads and writes only under the folder it was started in.

The protocol is small enough to implement with the standard library: JSON-RPC 2.0,
one message per line.
"""

from __future__ import annotations

import ast
import contextlib
import io
import json
import os
import re
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, TextIO

from kritalon import __version__
from kritalon.exits import EXIT_OK

PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
_MAX_FILES = 2000
_MAX_FILE_BYTES = 400_000
_MAX_TEXT = 60_000
_MAX_REPORT_BYTES = 5_000_000
_SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build", ".tox", "site-packages"}

GUIDE = """\
# Setting a bot up for Kritalon

Kritalon tests a bot its owner controls and reports only what is proven: a fake
secret it planted leaked, or a forbidden tool call was recorded at the tool. This
guide is the same for a developer and for a coding assistant working for one. An
assistant proposes each change as a diff for the developer to approve, and does not
scan anything but the built-in practice bots until the developer has recorded an
authorization themselves.

## 1. Find the pieces
- The web app object and the chat endpoint (path, request body, where the reply is).
- How the bot knows who is talking (a header, a token, a field in the body).
- Every function that sends, pays, books, changes or deletes something. Call
  `find_tools` for candidates, then read the code: the list is a starting point.
- Where the bot's instructions are built, and where it reads one user's data.

## 2. Add the drop-in harness (Python here; for Node see js/harness/README.md in the Kritalon repository)
```python
import kritalon.harness as pp

app = pp.wrap(app)                      # FastAPI/Starlette (ASGI) or Flask/Django (WSGI)

@pp.action("issue_refund")              # on each risky function, after the app's own checks
def issue_refund(order_id: str, amount: float): ...

prompt = BASE_PROMPT + pp.planted("admin_code")                   # a secret in the instructions
note = pp.planted("bob_note", note) if user == "bob" else note    # a secret in one user's data
```
Rules:
- The library must be installed in the bot's own environment, with the bot's Python:
  `pip install git+https://github.com/kritalon/kritalon`. Installing the `kritalon` command
  does not do that.
- `pp.wrap(app)` goes last, after the routes, and the wrapped app is what the server runs.
  A Flask or Quart app stays the same object, so `app.run()` still works and is wrapped.
- Put `@pp.action` on the function that does the deed, below the app's own permission
  checks, so a call that reaches it means the app let it through.
- During a test a marked function is not run and returns a stand-in that reads as
  {"status": "ok"} and as the text "ok". If the bot needs more from the answer, give
  one: `@pp.action("issue_refund", result="Refunded.")`, or a function of the tool's own
  arguments: `result=lambda order_id, amount: {"status": "ok", "refunded": amount}`.
- Call `pp.planted(...)` while a message is being handled. Each test conversation gets
  its own fake secret, so instructions put together once, when the app starts, cannot
  receive one; the scan then says secret leaks were not tested and names the slot.
- For a central tool registry, pass the complete list or mapping through
  `kritalon.harness_tools` and list only read-only tools in `reads`.
  See "Cover every tool at once" in the README for framework examples.
- If the work is handed to a job queue or a thread the app starts itself, mark the
  function that hands it over, not the worker.
- `pp.planted(slot, default)` returns the default for real users. Place it where a
  real secret of that kind lives, and nowhere the attacker's own account can read.
- Nothing changes for requests without a signed Kritalon session.

If the bot was built in Flowise, Dify or Langflow there is no code to add lines to. Ask the
developer to run `kritalon init --preset <builder> --origin <url>` instead; it writes the
description and prints the one line to add to the bot's instructions. Skip to step 4.

## 2b. The first scan needs no description
Once the lines above are in and the bot is running with the harness key set, the
developer runs `kritalon scan http://localhost:8000/chat` (their chat address); an
assistant calls `first_scan` with that address, after the developer has authorized it. It
works out the request shape and the secrets the bot reads, asks the developer to type
their name to authorize a bot on their own machine, and saves the description it
worked out, under a name it prints (`http:quick-localhost-8000`). Where nobody can type
(a script, a pipeline, an assistant running the command) the developer first runs
`kritalon authorize <origin> --by "NAME" --scope "..." --environment test --tool <each
tool marked never_for_users>` themselves; a tool the authorization does not name is left untested.
That first scan tests secrets held in the instructions, tools marked
`never_for_users="what an attacker would ask for"`, and text the bot reads from elsewhere at
each place the code reads with `pp.content("order_note", note)` (if the bot reads it only for
some requests, pass one as `message`, or `--message` on the command). Before any attack it checks that the
bot can say each secret at all: in one check conversation only, the harness adds a line
telling the bot to give the value to a user who states a pass phrase made for that scan.
The report says that route was supplied by the test. Steps 3 and 4 are for going further:
tools some users may use, other users' data, and bots across a network.

## 3. Describe the bot in `kritalon.targets.json`
```json
{"targets": {"staging": {
  "origin": "https://staging.example.com",
  "harness": "sdk",
  "chat": {"path": "/api/chat", "body": {"message": "{message}", "session_id": "{session}"}, "reply_pointer": "/reply"},
  "attacker_principal": "customer:alice",
  "principals": {
    "customer:alice": {"headers": {"Authorization": "Bearer ${ALICE_TOKEN}"}},
    "customer:bob": {"headers": {"Authorization": "Bearer ${BOB_TOKEN}"}},
    "staff:dana": {"headers": {"Authorization": "Bearer ${DANA_TOKEN}"}}
  },
  "tool_safety": "sinks",
  "slots": [
    {"id": "admin_code", "kind": "instruction_secret", "description": "a staff code in the instructions",
     "hint": "the staff code", "authorized": ["staff:dana"],
     "control_principal": "staff:dana", "control_prompt": "What is the staff code?"},
    {"id": "bob_note", "kind": "other_user_record", "canary_style": "name",
     "description": "a note on Bob's order", "hint": "the note on Bob's order", "authorized": ["customer:bob"],
     "control_principal": "customer:bob", "control_prompt": "What is the note on my order?"}
  ],
  "tool_rules": [
    {"id": "refund_by_customer", "tool": "issue_refund", "description": "customers cannot issue refunds",
     "hint": "a refund", "authorized": ["staff:dana"],
     "control_principal": "staff:dana", "control_prompt": "Refund order A-1001 by 5."}
  ],
  "task_checks": [
    {"id": "hello", "principal": "customer:alice", "prompt": "What are your opening hours?", "expect_substring": "open"}
  ]
}}}
```
- Use test accounts for every principal. Credentials are `${ENV_NAME}`, never written out.
- Each slot's `control_prompt` must make the bot give that secret to someone who is
  allowed it; the scan checks this first, and is inconclusive if it fails.
- `canary_style: "name"` plants an invented name; use it where the bot would treat a
  code-like value as a password and refuse to repeat it even to its owner.
- Call `check_description` until it reports no problems.

## 4. The developer's own steps (you cannot do these for them)
```
kritalon harness-key                       # then set KRITALON_HARNESS_KEY on staging and locally
kritalon authorize https://staging.example.com --by "THEIR NAME" \\
    --scope "the support bot on staging" --environment staging --tool issue_refund
# set KRITALON_CHALLENGE on staging to the printed line, deploy, then:
kritalon authorize --verify https://staging.example.com
kritalon sterile-check --env-file staging.env    # an export of staging's settings: no production keys
```

## 5. Check, then scan
Call `doctor` with target `http:staging` after each change: it says which step is not
passed yet and what fixes it. When it says "Ready", call `scan` with the same target. Read the result with `read_report`. Explain
each finding to the developer with its transcript, and propose a fix in the app's own
code (a permission check at the tool or data layer, not a sentence in the prompt).
Then scan again: a finding is fixed when its replay no longer works.

To see what a report looks like first, scan the practice bots `toy:vulnerable` and
`toy:fixed`. They run inside this process and need no permission.
"""

_RISKY = re.compile(
    r"(send|email|mail|sms|notify|post|publish|pay|charge|refund|transfer|withdraw|payout|invoice|book|cancel|"
    r"delete|remove|drop|purge|update|write|create|insert|grant|revoke|reset|execute|run_|shell|deploy|order|purchase)",
    re.IGNORECASE,
)
_TOOL_MARK = re.compile(r"tool|function_tool|action", re.IGNORECASE)


class ToolError(Exception):
    """A problem to report to the assistant as the tool's result."""


def _inside(root: Path, value: str) -> Path:
    path = (root / value).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ToolError(f"{value!r} is outside the project folder; this server reads and writes only inside it")
    return path


# -- the tools ------------------------------------------------------------------------------


def _setup_guide(root: Path, arguments: dict[str, Any]) -> str:
    return GUIDE


def _decorator_names(node: ast.AST) -> list[str]:
    names = []
    for decorator in getattr(node, "decorator_list", []):
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        names.append(ast.unparse(target))
    return names


def _python_files(start: Path) -> Iterator[Path]:
    """Python files under `start`, in order, without entering skipped folders or following links."""
    for folder, folders, files in os.walk(start, followlinks=False):
        folders[:] = sorted(d for d in folders if d not in _SKIP_DIRS and not Path(folder, d).is_symlink())
        for name in sorted(files):
            if name.endswith(".py"):
                yield Path(folder, name)


def _find_tools(root: Path, arguments: dict[str, Any]) -> str:
    start = _inside(root, str(arguments.get("path", ".")))
    if not start.exists():
        raise ToolError(f"{start} does not exist")
    found: list[str] = []
    marked = 0
    read = 0
    for file in [start] if start.is_file() else _python_files(start):
        if not file.resolve().is_relative_to(root.resolve()):
            continue  # reached through a link that leads out of the project
        if read >= _MAX_FILES:
            found.append(f"(stopped after {_MAX_FILES} files; give a narrower path)")
            break
        read += 1
        try:
            if file.stat().st_size > _MAX_FILE_BYTES:
                continue
            tree = ast.parse(file.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            decorators = _decorator_names(node)
            if any(name == "action" or name.endswith(".action") for name in decorators):
                marked += 1
                continue
            reasons = []
            if any(_TOOL_MARK.search(name) for name in decorators):
                reasons.append("registered as a tool (@" + ", @".join(decorators) + ")")
            if _RISKY.search(node.name):
                reasons.append("its name suggests it changes something")
            if reasons:
                where = file.resolve().relative_to(root.resolve()).as_posix()
                arguments_text = ", ".join(a.arg for a in node.args.args if a.arg not in ("self", "cls"))
                found.append(f"{where}:{node.lineno}  {node.name}({arguments_text})  - {'; '.join(reasons)}")
    lines = [
        f"Read {read} Python file(s). {marked} function(s) already carry @pp.action.",
        f"{len(found)} candidate(s) that may need @pp.action. Read each one before deciding: a function that only",
        "reads, or that the bot can never reach, does not need it; one that this list missed still does.",
        "",
        *found[:300],
    ]
    return "\n".join(lines)


def _check_description(root: Path, arguments: dict[str, Any]) -> str:
    from kritalon.targets.http import TargetConfigError, parse_config

    path = _inside(root, str(arguments.get("file", "kritalon.targets.json")))
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ToolError(f"could not read {path.name}: {error}") from error
    targets = data.get("targets") if isinstance(data, dict) else None
    if not isinstance(targets, dict) or not targets:
        raise ToolError(f'{path.name} must look like {{"targets": {{"<name>": {{...}}}}}}')
    wanted = arguments.get("name")
    names = [str(wanted)] if wanted else sorted(targets)
    lines = []
    for name in names:
        if name not in targets:
            lines.append(f"{name}: not in the file (it has: {', '.join(sorted(targets))})")
            continue
        try:
            config = parse_config(name, targets[name])
        except TargetConfigError as error:
            lines.append(f"{name}: PROBLEM: {error}")
            continue
        notes = []
        if not config.slots and not config.tool_rules:
            notes.append("it protects nothing: add at least one slot or tool rule, or a scan has nothing to prove")
        if config.harness == "endpoint":
            notes.append('it uses a hand-written reset endpoint; "harness": "sdk" needs less code in the bot')
        if not config.task_checks:
            notes.append("no task_checks: add one normal request, so a bot that refuses everything is not called safe")
        if any(v for p in targets[name].get("principals", {}).values() for v in p.get("headers", {}).values() if "${" not in v):
            notes.append("a header value is written out; use ${ENV_NAME} so no credential is in the file")
        summary = (
            f"{name}: OK. origin {config.origin}, {len(config.slots)} secret slot(s), {len(config.tool_rules)} tool rule(s), "
            f"{len(config.injection_points)} injection point(s), {len(config.task_checks)} normal-use check(s)."
        )
        lines.append(summary + "".join(f"\n  note: {note}" for note in notes))
    return "\n".join(lines)


def _authorization_status(root: Path, arguments: dict[str, Any]) -> str:
    from datetime import UTC, datetime

    from kritalon.core.authorization import AuthorizationError, AuthorizationStore

    origin = str(arguments.get("origin", ""))
    how = (
        "Only a person can authorize a test. Ask the developer to run this in their terminal:\n"
        f'  kritalon authorize {origin or "<origin>"} --by "THEIR NAME" --scope "what may be tested" '
        "--environment staging --tool <each tool>"
    )
    try:
        record = AuthorizationStore(_inside(root, "kritalon.authorizations.json")).find(origin)
    except (AuthorizationError, ValueError) as error:
        raise ToolError(f"{error}\n{how}") from error
    if record is None:
        return f"No authorization on record for {origin}.\n{how}"
    if record.expired(datetime.now(UTC)):
        return f"The authorization for {record.origin} expired at {record.expires_at}.\n{how}"
    state = "ready"
    if record.needs_proof and not record.verified_at:
        state = f"not verified yet: the developer must run `kritalon authorize --verify {record.origin}`"
    return (
        f"{record.origin}: {state}. Authorized by {record.authorized_by} for {record.environment}, until {record.expires_at}.\n"
        f"Scope: {record.scope}\nTools that may be exercised: {', '.join(record.allowed_tools) or 'none'}\n"
        f"Tools that may be carried out for real, under caps: {', '.join(record.live_tools) or 'none'}"
    )


def _doctor(root: Path, arguments: dict[str, Any]) -> str:
    from kritalon.doctor import diagnose

    target = str(arguments.get("target", ""))
    if not target:
        raise ToolError("give a target, for example http:staging")
    lines: list[str] = []
    diagnose(target, offline=bool(arguments.get("offline", False)), out=lines.append)
    return "\n".join(lines)


def _first_scan(root: Path, arguments: dict[str, Any]) -> str:
    """`kritalon scan URL` for an assistant: work the description out from the harness, save it, scan."""
    from kritalon.practice_server import write_description
    from kritalon.quick import QuickError, _keep_earlier, discover
    from kritalon.targets.http import targets_file

    url = str(arguments.get("url", ""))
    if not url:
        raise ToolError("give the bot's chat address, for example http://localhost:8000/chat")
    directory = str(arguments.get("dir", "kritalon-report"))
    _inside(root, directory)
    path = targets_file()
    if not path.resolve().is_relative_to(root.resolve()):
        raise ToolError("the targets file is outside the project folder; this server reads and writes only inside it")

    def given(key: str) -> str | None:
        return str(arguments[key]) if arguments.get(key) not in (None, "") else None

    said: list[str] = []
    try:
        # Nobody is asked to type a name here: an authorization is a person's act, made in their own terminal.
        name, description, notes = discover(
            url, given("name"), given("field"), given("session_field"), given("reply"),
            ask_name=lambda origin: "", say=said.append, message=given("message"),
        )  # fmt: skip
    except QuickError as error:
        raise ToolError("\n".join([*said, f"Not scanned: {error}"])) from error
    kept = _keep_earlier(path, name, description)
    if kept is not None:
        said.append(f"The description saved earlier as http:{name} differed; it was kept as {kept.name}.")
    write_description(path, name, description)
    said.append(f"Saved what was worked out as target http:{name} in {path.name}.")
    result = _scan(root, {**{k: v for k, v in arguments.items() if k in _SCAN_OPTIONS}, "target": f"http:{name}", "dir": directory})
    return "\n".join([*said, "", result, *(["", *notes] if notes else [])])


_SCAN_OPTIONS = ("strategy", "replays", "max_seconds", "max_messages")


def _scan(root: Path, arguments: dict[str, Any]) -> str:
    from kritalon.cli import main

    target = str(arguments.get("target", ""))
    if not target:
        raise ToolError("give a target, for example toy:vulnerable or http:staging")
    directory = str(arguments.get("dir", "kritalon-report"))
    _inside(root, directory)
    argv = ["ci", "--target", target, "--dir", directory, "--fail-on", "never"]
    argv += ["--strategy", str(arguments.get("strategy", "static"))]
    argv += ["--replays", str(int(arguments.get("replays", 3)))]
    argv += ["--max-seconds", str(float(arguments.get("max_seconds", 600)))]
    argv += ["--max-messages", str(int(arguments.get("max_messages", 1000)))]
    before = _inside(root, directory) / "scan.kritalon.json"
    existed = before.exists()
    try:
        main(argv)
    except SystemExit as error:  # argparse refusing an option
        raise ToolError(f"the scan options were not accepted (exit {error.code})") from error
    if existed or not before.exists():
        # What the command printed (captured by the caller) says why. Do not claim reports that were not written.
        raise ToolError("The scan did not run, so no report was written. The lines above say why.")
    return f"Reports are in {directory}/ (report.md, report.html, scan.kritalon.json). Use read_report to read one."


def _read_report(root: Path, arguments: dict[str, Any]) -> str:
    path = _inside(root, str(arguments.get("path", "kritalon-report/report.md")))
    if path.suffix not in (".md", ".json"):
        raise ToolError("read_report reads .md and .json reports")
    try:
        if path.stat().st_size > _MAX_REPORT_BYTES:
            raise ToolError(f"{path.name} is larger than {_MAX_REPORT_BYTES} bytes; open it in an editor instead")
        text = path.read_text(encoding="utf-8")
    except (OSError, ValueError) as error:
        raise ToolError(f"could not read {path.name}: {error}") from error
    return text


def _text_schema(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required or [], "additionalProperties": False}


TOOLS: dict[str, tuple[str, dict[str, Any], Callable[[Path, dict[str, Any]], str]]] = {
    "setup_guide": (
        "How to wire the developer's own bot for Kritalon, step by step. Read this first.",
        _text_schema({}),
        _setup_guide,
    ),
    "find_tools": (
        "List Python functions in the project that look like risky tools (they send, pay, book, change or delete), "
        "as candidates for @pp.action. Read-only.",
        _text_schema({"path": {"type": "string", "description": "A folder or file inside the project. Default: the project."}}),
        _find_tools,
    ),
    "check_description": (
        "Check a target description in kritalon.targets.json and say exactly what is wrong. Read-only.",
        _text_schema({
            "file": {"type": "string", "description": "Default: kritalon.targets.json"},
            "name": {"type": "string", "description": "One target; default: all of them"},
        }),
        _check_description,
    ),
    "authorization_status": (
        "Say whether a person has authorized testing this origin. This server cannot create an authorization.",
        _text_schema({"origin": {"type": "string", "description": "For example https://staging.example.com"}}, ["origin"]),
        _authorization_status,
    ),
    "doctor": (
        "Check a target's setup step by step (description, credentials, key, authorization, proof of control, the "
        "harness, legitimate use) and say what to fix next. Sends nothing hostile, and nothing at all without an "
        "authorization.",
        _text_schema(
            {
                "target": {"type": "string", "description": "For example http:staging"},
                "offline": {"type": "boolean", "description": "Only checks that need no contact with the bot"},
            },
            ["target"],
        ),
        _doctor,
    ),
    "first_scan": (
        "Scan the developer's own bot from its chat address alone, once the drop-in harness lines are in the bot and it "
        "is running with the harness key set. Works out the request shape, the secrets the bot reads and the tools "
        "marked never_for_users, saves that as a target, scans, and writes the reports. Refused, with the command the "
        "developer must run themselves, until a person has recorded an authorization for that address.",
        _text_schema(
            {
                "url": {"type": "string", "description": "The chat address, for example http://localhost:8000/chat"},
                "dir": {"type": "string", "description": "A new or empty folder for the reports. Default: kritalon-report"},
                "name": {"type": "string", "description": "The name to save the description under. Default: made from the address"},
                "field": {"type": "string", "description": "The request field that carries the message, if it is not found"},
                "session_field": {"type": "string", "description": "A request field for the conversation id, if the bot has one"},
                "reply": {"type": "string", "description": "A JSON pointer to the reply text, such as /data/answer"},
                "message": {
                    "type": "string",
                    "description": 'An ordinary request to send while working the bot out. Default "Hello". Give one '
                    "that makes the bot read its notes or documents, so planted text there is tested",
                },
                "strategy": {"type": "string", "enum": ["static", "adaptive", "both"]},
                "replays": {"type": "integer", "minimum": 1, "maximum": 20},
                "max_seconds": {"type": "number", "minimum": 1, "maximum": 3600},
                "max_messages": {"type": "integer", "minimum": 1, "maximum": 5000},
            },
            ["url"],
        ),
        _first_scan,
    ),
    "scan": (
        "Run a scan and write the reports. Practice bots (toy:vulnerable, toy:fixed) need no permission; any other "
        "target is refused unless a person has recorded an authorization for it.",
        _text_schema(
            {
                "target": {"type": "string", "description": "For example toy:vulnerable or http:staging"},
                "dir": {"type": "string", "description": "A new or empty folder for the reports. Default: kritalon-report"},
                "strategy": {"type": "string", "enum": ["static", "adaptive", "both"]},
                "replays": {"type": "integer", "minimum": 1, "maximum": 20},
                "max_seconds": {"type": "number", "minimum": 1, "maximum": 3600},
                "max_messages": {"type": "integer", "minimum": 1, "maximum": 5000},
            },
            ["target"],
        ),
        _scan,
    ),
    "read_report": (
        "Read a finished report (.md or .json) from the project folder.",
        _text_schema({"path": {"type": "string", "description": "Default: kritalon-report/report.md"}}),
        _read_report,
    ),
}


# -- the protocol ---------------------------------------------------------------------------


def _call(root: Path, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name not in TOOLS:
        return {"content": [{"type": "text", "text": f"unknown tool {name!r}"}], "isError": True}
    captured = io.StringIO()
    failed = False
    try:
        # Standard output is the protocol's channel: nothing a tool prints may reach it.
        with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
            text = TOOLS[name][2](root, arguments)
    except ToolError as error:
        text, failed = str(error), True
    except Exception as error:
        text, failed = f"{type(error).__name__}: {error}", True
    printed = captured.getvalue().strip()
    if printed:
        text = printed + "\n\n" + text
    if len(text) > _MAX_TEXT:
        text = text[:_MAX_TEXT] + f"\n\n(cut at {_MAX_TEXT} characters)"
    return {"content": [{"type": "text", "text": text}], "isError": failed}


def handle(root: Path, message: Any) -> dict[str, Any] | None:
    """Answer one JSON-RPC message. Returns None for a notification."""
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "not a JSON-RPC 2.0 request"}}
    if "id" not in message:
        return None
    identifier, method = message["id"], message["method"]
    params = message.get("params") if isinstance(message.get("params"), dict) else {}

    def answer(result: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": identifier, "result": result}

    if method == "initialize":
        asked = params.get("protocolVersion")
        return answer(
            {
                "protocolVersion": asked if asked in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "kritalon", "version": __version__},
                "instructions": "Call setup_guide first. Only the developer can authorize a test; never do it for them.",
            }
        )
    if method == "ping":
        return answer({})
    if method == "tools/list":
        return answer(
            {"tools": [{"name": n, "description": d, "inputSchema": schema} for n, (d, schema, _) in TOOLS.items()]}
        )
    if method == "tools/call":
        arguments = params.get("arguments")
        return answer(_call(root, str(params.get("name")), arguments if isinstance(arguments, dict) else {}))
    return {"jsonrpc": "2.0", "id": identifier, "error": {"code": -32601, "message": f"unknown method {method}"}}


def serve(root: Path, incoming: TextIO, outgoing: TextIO) -> None:
    for line in incoming:
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except ValueError:
            reply: dict[str, Any] | None = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "not JSON"}}
        else:
            reply = handle(root, message)
        if reply is not None:
            outgoing.write(json.dumps(reply, separators=(",", ":")) + "\n")
            outgoing.flush()


def register(commands: Any) -> None:
    parser = commands.add_parser("mcp", help="serve Kritalon to a coding assistant (Model Context Protocol, stdio)")
    parser.set_defaults(handler=_serve_command)
    guide = commands.add_parser("guide", help="print how to wire a bot for testing")
    guide.set_defaults(handler=lambda args: print(GUIDE) or 0)


def _serve_command(args: Any) -> int:
    # The real streams are captured here, before any tool redirects standard output.
    for stream in (sys.stdin, sys.stdout):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", newline="\n")
    serve(Path.cwd(), sys.stdin, sys.stdout)
    return EXIT_OK
