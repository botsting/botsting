"""`botsting conclusion`: send a finished report to BotSting and get our conclusion back.

    botsting conclusion                         # the report of the last scan, reports/scan.botsting.json
    botsting conclusion path/to/scan.botsting.json
    botsting conclusion --without-conversations
    botsting conclusion --remove 202611-...     # have a report you sent removed

A scan itself sends nothing anywhere. A report leaves your machine only when you ask for
that, in one of two ways. You run this command: it shows what is being sent and where,
and sends it; running it is the request, so it does not ask again. Or, at the end of a
scan run at a terminal, you are shown the same and asked ("Send it? [Y/n]", where Enter
means yes); in a script, a pipeline or an assistant that question is never asked and
nothing is sent. Setting `BOTSTING_NO_CONCLUSION` stops the question.

What you get back: what the result means, which finding to deal with first, what the
scan did not test, and whether something that went wrong was a fault in BotSting and
not in your bot. What we get: a real report to learn from, which is how the tool
improves.

What is sent
------------
The report file, with two changes made before it leaves:

- The name of the person who authorized the test, and of the tester, are removed.
- With `--without-conversations`, every conversation is removed as well: the messages,
  the bot's replies, the planted text and the arguments of recorded tool calls. The
  counts, the titles of the findings and the error messages stay.

The secrets in a report are fake ones made for the test. The conversations do contain
your bot's real replies, which can include its instructions. The report also names the
address the bot was tested at.

It is sent over HTTPS to api.botsting.com and kept privately until you ask for it to be
removed. Each report gets a reference; `botsting conclusion --remove REFERENCE`, or the
page https://botsting.com/delete, removes it. The service does not keep your network
address.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import platform
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from botsting import __version__
from botsting.exits import EXIT_FAILED, EXIT_OK

CONCLUSION_URL = "https://api.botsting.com/conclusion"
URL_ENV = "BOTSTING_CONCLUSION_URL"  # for a test, or for someone who runs their own copy of the service
OFF_ENV = "BOTSTING_NO_CONCLUSION"  # set to anything: a scan never asks whether to send its report
PRIVACY = "https://botsting.com/privacy"
MAX_BYTES = 2_000_000
REMOVED = "(removed before sending)"
_STATUSES = ("violations_verified", "no_verified_violations", "inconclusive")
_REFERENCE = re.compile(r"\d{6}-[0-9a-f]{32}")


class ConclusionError(Exception):
    """Why nothing was sent, or why no conclusion came back."""


def load(path: Path) -> dict[str, Any]:
    """The report at `path`, if it is one of ours."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ConclusionError(f"could not read {path}: {error.strerror or error}") from error
    except ValueError as error:
        raise ConclusionError(f"{path} is not a JSON report") from error
    wanted = ("tool_version", "status", "slots", "findings", "attacks_run")
    if not isinstance(data, dict) or any(key not in data for key in wanted) or data.get("status") not in _STATUSES:
        raise ConclusionError(f"{path} is not a BotSting scan report (the file a scan writes as scan.botsting.json)")
    return data


def prepare(report: dict[str, Any], conversations: bool = True) -> dict[str, Any]:
    """The report as it will be sent: names removed, and the conversations too unless they are wanted."""
    out = copy.deepcopy(report)
    if isinstance(out.get("authorization"), dict) and out["authorization"].get("authorized_by"):
        out["authorization"]["authorized_by"] = REMOVED
    if out.get("tester"):
        out["tester"] = REMOVED
    if not conversations:
        for item in [*out.get("findings", []), *out.get("suspected", [])]:
            if not isinstance(item, dict):
                continue
            for key in ("transcript", "frozen_turns"):
                if key in item:
                    item[key] = []
            if item.get("payload"):
                item["payload"] = REMOVED
            # Which tool was called stays, since that is the finding. What it was called with goes.
            item["tool_calls"] = [{**call, "arguments": [], "result": ""} for call in item.get("tool_calls", []) if isinstance(call, dict)]
    return out


def envelope(report: dict[str, Any], conversations: bool) -> dict[str, Any]:
    return {
        "format": 1,
        "client": {"tool_version": __version__, "python": platform.python_version(), "system": platform.system()},
        "conversations": conversations,
        "report": prepare(report, conversations),
    }


def body_of(report: dict[str, Any], conversations: bool) -> bytes:
    """The bytes that would be sent. Raises if they are over the limit."""
    body = json.dumps(envelope(report, conversations), separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_BYTES:
        raise ConclusionError(
            f"the report is {len(body) / 1_000_000:.1f} MB and the limit is {MAX_BYTES / 1_000_000:.0f} MB"
            + ("" if not conversations else "; try --without-conversations")
        )
    return body


def endpoint() -> str:
    """Where the report goes. Only an https address, or one on this machine, is accepted."""
    url = os.environ.get(URL_ENV, "").strip() or CONCLUSION_URL
    parts = urlsplit(url)
    local = parts.hostname in ("127.0.0.1", "localhost", "::1")
    if parts.scheme != "https" and not (parts.scheme == "http" and local):
        raise ConclusionError(f"{URL_ENV} must be an https address")
    return url


def removal_address(url: str) -> str:
    """The service's address for removing a report: beside the one that takes them."""
    return url.rsplit("/", 1)[0] + "/delete"


def describe(path: Path, body: bytes, report: dict[str, Any], conversations: bool, url: str) -> list[str]:
    """What the person is shown before anything is sent."""
    findings = len(report.get("findings", []))
    origin = (report.get("target_config") or {}).get("origin") or report.get("target", "")
    lines = [
        f"This will send the report {path} ({len(body) / 1000:.0f} KB) to {url}.",
        "",
        f"  It contains: the verdict ({report['status'].replace('_', ' ')}), {findings} finding(s), what was tested,",
        f"  any errors, and the address the bot was tested at ({origin}).",
    ]
    if conversations:
        lines += [
            "  It includes the conversations: the test messages and your bot's replies, which can include its",
            "  instructions. To leave them out, use --without-conversations.",
        ]
    else:
        lines.append("  The conversations are left out: no messages, no replies, no planted text, no tool arguments.")
    lines += [
        "  The secrets in it are fake ones made for the test. The names of who authorized and ran it are removed.",
        "",
        f"  We keep it privately, to improve BotSting, until you ask us to remove it. {PRIVACY}",
    ]
    return lines


def _post(url: str, payload: bytes, transport: Any) -> tuple[int, Any]:
    import httpx

    try:
        with httpx.Client(transport=transport, timeout=30, follow_redirects=False) as client:
            response = client.post(url, content=payload, headers={"Content-Type": "application/json", "User-Agent": f"botsting/{__version__}"})
    except httpx.HTTPError as error:
        raise ConclusionError(f"could not reach {urlsplit(url).netloc}: {error}. Nothing may have been received; it is safe to try again.") from error
    try:
        answer = response.json()
    except ValueError:
        answer = None
    return response.status_code, answer


def _why(status: int, answer: Any) -> str:
    return answer["error"] if isinstance(answer, dict) and isinstance(answer.get("error"), str) else f"HTTP {status}"


def send(payload: bytes, url: str, transport: Any = None) -> dict[str, Any]:
    status, answer = _post(url, payload, transport)
    if status == 429:
        raise ConclusionError("too many reports were sent from this address in a short time; try again in a few minutes")
    if status == 413:
        raise ConclusionError("the service says the report is too large; try --without-conversations")
    if status != 200 or not isinstance(answer, dict) or not isinstance(answer.get("text"), str):
        raise ConclusionError(f"the service did not return a conclusion ({_why(status, answer)})")
    return answer


def remove(reference: str, url: str, transport: Any = None) -> str:
    """Ask the service to remove the report with this reference. Returns what it answered."""
    reference = reference.strip().lower()
    if not _REFERENCE.fullmatch(reference):
        raise ConclusionError("that is not a report reference; it looks like 202611- followed by 32 letters and digits")
    status, answer = _post(removal_address(url), json.dumps({"id": reference}).encode("utf-8"), transport)
    if status == 429:
        raise ConclusionError("too many requests from this address in a short time; try again in a few minutes")
    if status != 200 or not isinstance(answer, dict) or not isinstance(answer.get("text"), str):
        raise ConclusionError(f"the service did not confirm the removal ({_why(status, answer)})")
    return answer["text"].strip()


def _someone_is_there() -> bool:
    """Input and output are both a terminal, so a person can read the question and answer it."""
    return sys.stdin.isatty() and sys.stdout.isatty()


def _answer(question: str) -> str:
    try:
        return input(question).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return "n"


def _show(answer: dict[str, Any], path: Path) -> None:
    text = _plain(answer["text"]).strip()
    print()
    print(text)
    saved = path.with_name("conclusion.txt")
    try:
        saved.write_text(text + "\n", encoding="utf-8")
        print()
        print(f"Saved as {saved.resolve()}")
    except OSError:
        pass
    reference = answer.get("id")
    if isinstance(reference, str) and _REFERENCE.fullmatch(reference):
        print(f"To have this report removed later: botsting conclusion --remove {reference}")


def _plain(text: str) -> str:
    """What came back, without characters that could move the cursor or recolour the terminal."""
    return "".join(ch for ch in text if ch in "\n\t" or (ch >= " " and ch != "\x7f"))


def run(args: argparse.Namespace, transport: Any = None) -> int:
    if getattr(args, "remove", None):
        try:
            print(remove(args.remove, endpoint(), transport))
        except ConclusionError as error:
            print(f"Not removed: {error}")
            return EXIT_FAILED
        return EXIT_OK
    path = Path(args.report)
    conversations = not args.without_conversations
    try:
        report = load(path)
        url = endpoint()
        body = body_of(report, conversations)
        for line in describe(path, body, report, conversations, url):
            print(line)
        print()
        print("Sending it now.")  # running this command is the request; it does not ask a second time
    except ConclusionError as error:
        print(f"Not sent: {error}")
        return EXIT_FAILED
    try:
        answer = send(body, url, transport)
    except ConclusionError as error:
        print(f"No conclusion: {error}")
        return EXIT_FAILED
    _show(answer, path)
    return EXIT_OK


def offer(path: Path, transport: Any = None) -> bool:
    """At the end of a scan someone ran at a terminal: ask whether to send the report for our
    conclusion. Enter means yes. Returns whether it was sent.

    It never asks, and so never sends, where nobody is there to answer: when input or output is
    not a terminal, in a pipeline (`CI`), or when `BOTSTING_NO_CONCLUSION` is set. It never changes
    how the scan ended, and nothing it runs into is allowed to stop the command."""
    if os.environ.get(OFF_ENV) or os.environ.get("CI"):
        return False
    try:
        if not _someone_is_there():
            return False
        report = load(path)
        url = endpoint()
        body = body_of(report, True)
        print()
        print("Want BotSting's conclusion on this result? It says what to fix first, what was not tested, and")
        print("whether anything that went wrong was a fault in BotSting and not in your bot.")
        print()
        for line in describe(path, body, report, True, url):
            print(line)
        print()
        reply = _answer("Send it? [Y/n], or w to send it without the conversations: ")
        if reply in ("w", "without"):
            body = body_of(report, False)
        elif reply not in ("", "y", "yes"):
            print(f"Nothing was sent. (To get it later: botsting conclusion {path}. To stop this question: set {OFF_ENV}=1.)")
            return False
        _show(send(body, url, transport), path)
        return True
    except ConclusionError as error:
        print(f"Nothing came back: {error}")
    except Exception as error:  # an offer must never turn a finished scan into a crash
        print(f"Nothing was sent ({type(error).__name__}).")
    return False


def register(commands: Any) -> None:
    parser = commands.add_parser(
        "conclusion",
        help="send a finished report to BotSting, showing you what is sent, and get our conclusion back",
        description="Send a finished report to BotSting and get our conclusion back. It shows what is being sent, then sends it.",
    )
    parser.add_argument("report", nargs="?", default="reports/scan.botsting.json", help="the JSON report of a scan (default: reports/scan.botsting.json)")
    parser.add_argument("--without-conversations", action="store_true", help="leave out every message, reply, planted text and tool argument")
    parser.add_argument("--yes", action="store_true", help="not needed: the command sends without asking (kept so older scripts still run)")
    parser.add_argument("--remove", metavar="REFERENCE", help="remove a report you sent earlier; the reference was printed with its conclusion")
    parser.set_defaults(handler=run)
