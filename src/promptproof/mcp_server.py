"""`promptproof mcp`: let a developer's coding assistant set Promptproof up and run it.

This is a Model Context Protocol server over standard input and output. A coding
assistant (Claude Code, Cursor and others) that is connected to it can:

    setup_guide            read how to wire a bot for testing, step by step
    find_tools             list functions in the project that look like risky tools
    check_description      check a target description and say what is wrong with it
    authorization_status   see whether a person has authorized testing an origin
    doctor                 check the whole setup step by step and learn what to fix next
    scan                   run a scan and get the result and where the reports are
    read_report            read a finished report

    claude mcp add promptproof -- promptproof mcp

What it will not do
-------------------
It never creates or changes an authorization. Permission to test is a person taking
responsibility by name, so it is recorded by a person running `promptproof authorize`
in a terminal. Without one, `scan` is refused for anything but the built-in practice
bots, exactly as on the command line.

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

from promptproof import __version__

PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
_MAX_FILES = 2000
_MAX_FILE_BYTES = 400_000
_MAX_TEXT = 60_000
_MAX_REPORT_BYTES = 5_000_000
_SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build", ".tox", "site-packages"}

GUIDE = """\
# Setting a bot up for Promptproof

Promptproof tests a bot its owner controls and reports only what is proven: a fake
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

## 2. Add the drop-in harness (Python here; for Node see js/harness/README.md in the Promptproof repository)
```python
import promptproof.harness as pp

app = pp.wrap(app)                      # FastAPI/Starlette (ASGI) or Flask/Django (WSGI)

@pp.action("issue_refund")              # on each risky function, after the app's own checks
def issue_refund(order_id: str, amount: float): ...

prompt = BASE_PROMPT + pp.planted("admin_code")                   # a secret in the instructions
note = pp.planted("bob_note", note) if user == "bob" else note    # a secret in one user's data
```
Rules:
- Put `@pp.action` on the function that does the deed, below the app's own permission
  checks, so a call that reaches it means the app let it through.
- During a test a marked function is not run and returns a stand-in that reads as
  {"status": "ok"} and as the text "ok". If the bot needs more from the answer, give
  one: `@pp.action("issue_refund", result="Refunded.")`.
- For a central tool registry, pass the complete list or mapping through
  `promptproof.harness_tools` and list only read-only tools in `reads`.
  See "Cover every tool at once" in the README for framework examples.
- If the work is handed to a job queue or a thread the app starts itself, mark the
  function that hands it over, not the worker.
- `pp.planted(slot, default)` returns the default for real users. Place it where a
  real secret of that kind lives, and nowhere the attacker's own account can read.
- Nothing changes for requests without a signed Promptproof session.

If the bot was built in Flowise, Dify or Langflow there is no code to add lines to. Ask the
developer to run `promptproof init --preset <builder> --origin <url>` instead; it writes the
description and prints the one line to add to the bot's instructions. Skip to step 4.

## 2b. The first scan needs no description
Once the lines above are in and the bot is running with the harness key set, the
developer runs `promptproof scan http://localhost:8000/chat` (their chat address). It
works out the request shape and the secrets the bot reads, asks the developer to type
their name to authorize a bot on their own machine, and saves the description it
worked out. That first scan tests secrets held in the instructions. Steps 3 and 4 are
for going further: tools, other users' data, and bots across a network.

## 3. Describe the bot in `promptproof.targets.json`
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
promptproof harness-key                       # then set PROMPTPROOF_HARNESS_KEY on staging and locally
promptproof authorize https://staging.example.com --by "THEIR NAME" \\
    --scope "the support bot on staging" --environment staging --tool issue_refund
# set PROMPTPROOF_CHALLENGE on staging to the printed line, deploy, then:
promptproof authorize --verify https://staging.example.com
promptproof sterile-check --env-file staging.env    # an export of staging's settings: no production keys
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
    from promptproof.targets.http import TargetConfigError, parse_config

    path = _inside(root, str(arguments.get("file", "promptproof.targets.json")))
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

    from promptproof.core.authorization import AuthorizationError, AuthorizationStore

    origin = str(arguments.get("origin", ""))
    how = (
        "Only a person can authorize a test. Ask the developer to run this in their terminal:\n"
        f'  promptproof authorize {origin or "<origin>"} --by "THEIR NAME" --scope "what may be tested" '
        "--environment staging --tool <each tool>"
    )
    try:
        record = AuthorizationStore(_inside(root, "promptproof.authorizations.json")).find(origin)
    except (AuthorizationError, ValueError) as error:
        raise ToolError(f"{error}\n{how}") from error
    if record is None:
        return f"No authorization on record for {origin}.\n{how}"
    if record.expired(datetime.now(UTC)):
        return f"The authorization for {record.origin} expired at {record.expires_at}.\n{how}"
    state = "ready"
    if record.needs_proof and not record.verified_at:
        state = f"not verified yet: the developer must run `promptproof authorize --verify {record.origin}`"
    return (
        f"{record.origin}: {state}. Authorized by {record.authorized_by} for {record.environment}, until {record.expires_at}.\n"
        f"Scope: {record.scope}\nTools that may be exercised: {', '.join(record.allowed_tools) or 'none'}\n"
        f"Tools that may be carried out for real, under caps: {', '.join(record.live_tools) or 'none'}"
    )


def _doctor(root: Path, arguments: dict[str, Any]) -> str:
    from promptproof.doctor import diagnose

    target = str(arguments.get("target", ""))
    if not target:
        raise ToolError("give a target, for example http:staging")
    lines: list[str] = []
    diagnose(target, offline=bool(arguments.get("offline", False)), out=lines.append)
    return "\n".join(lines)


def _scan(root: Path, arguments: dict[str, Any]) -> str:
    from promptproof.cli import main

    target = str(arguments.get("target", ""))
    if not target:
        raise ToolError("give a target, for example toy:vulnerable or http:staging")
    directory = str(arguments.get("dir", "promptproof-report"))
    _inside(root, directory)
    argv = ["ci", "--target", target, "--dir", directory, "--fail-on", "never"]
    argv += ["--strategy", str(arguments.get("strategy", "static"))]
    argv += ["--replays", str(int(arguments.get("replays", 3)))]
    argv += ["--max-seconds", str(float(arguments.get("max_seconds", 600)))]
    argv += ["--max-messages", str(int(arguments.get("max_messages", 1000)))]
    before = _inside(root, directory) / "scan.promptproof.json"
    existed = before.exists()
    try:
        main(argv)
    except SystemExit as error:  # argparse refusing an option
        raise ToolError(f"the scan options were not accepted (exit {error.code})") from error
    if existed or not before.exists():
        # What the command printed (captured by the caller) says why. Do not claim reports that were not written.
        raise ToolError("The scan did not run, so no report was written. The lines above say why.")
    return f"Reports are in {directory}/ (report.md, report.html, scan.promptproof.json). Use read_report to read one."


def _read_report(root: Path, arguments: dict[str, Any]) -> str:
    path = _inside(root, str(arguments.get("path", "promptproof-report/report.md")))
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
        "How to wire the developer's own bot for Promptproof, step by step. Read this first.",
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
        "Check a target description in promptproof.targets.json and say exactly what is wrong. Read-only.",
        _text_schema({
            "file": {"type": "string", "description": "Default: promptproof.targets.json"},
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
    "scan": (
        "Run a scan and write the reports. Practice bots (toy:vulnerable, toy:fixed) need no permission; any other "
        "target is refused unless a person has recorded an authorization for it.",
        _text_schema(
            {
                "target": {"type": "string", "description": "For example toy:vulnerable or http:staging"},
                "dir": {"type": "string", "description": "A new or empty folder for the reports. Default: promptproof-report"},
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
        _text_schema({"path": {"type": "string", "description": "Default: promptproof-report/report.md"}}),
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
    except Exception as error:  # noqa: BLE001 - a tool must never take the server down
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
                "serverInfo": {"name": "promptproof", "version": __version__},
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
    parser = commands.add_parser("mcp", help="serve Promptproof to a coding assistant (Model Context Protocol, stdio)")
    parser.set_defaults(handler=_serve_command)
    guide = commands.add_parser("guide", help="print how to wire a bot for testing")
    guide.set_defaults(handler=lambda args: print(GUIDE) or 0)


def _serve_command(args: Any) -> int:
    # The real streams are captured here, before any tool redirects standard output.
    for stream in (sys.stdin, sys.stdout):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", newline="\n")
    serve(Path.cwd(), sys.stdin, sys.stdout)
    return 0
