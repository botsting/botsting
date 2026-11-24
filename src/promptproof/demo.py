"""`promptproof demo`: see the whole thing work in a minute, on this machine only.

It serves the built-in practice support bot twice, a vulnerable build and a fixed one,
wired with the drop-in harness exactly as a real bot would be (see harness.py). It then
scans both over HTTP and writes the reports and a sealed evidence bundle for each:

    promptproof demo                 # tools are recorded, never run
    promptproof demo --live          # small refunds really run, inside a cap

With `--live` the practice refund tool carries `Cap(max={"amount": LIVE_CAP}, ...)`.
"Really run" here means a line in an in-memory ledger: the practice bot cannot move
money. The point is to show the mechanism: a refund inside the cap is carried out, and
one outside it is recorded with the cap that stopped it.

Nothing leaves this machine, and nothing is written outside the report folder. The
permission the scans run under is made for this one run and kept in memory; it names
this command as the authorizer, covers only the two local addresses it just opened,
and is not saved to the authorizations file.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import threading
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

import promptproof.harness as pp
from promptproof.core.models import ToolCall
from promptproof.llm.scripted import ScriptedModel
from promptproof.targets.toy import REFUND_TOOL, ToyTarget

LIVE_CAP = 60  # the practice bot's refunds are whole numbers; its attacks ask for more and for less than this
LIVE_CALLS = 50


class HarnessPracticeBot(ToyTarget):
    """The practice bot as an owner would wire it: once its own checks allow a refund, the refund
    goes through a function marked with @pp.action. It keeps no recorder of its own."""

    def __init__(self, variant: str, live: bool = False) -> None:
        super().__init__(variant=variant, model=ScriptedModel(), spec=f"toy:{variant}")  # type: ignore[arg-type]
        self.carried_out: list[tuple[str, int]] = []  # refunds that "really" ran, in a --live demo
        cap = pp.Cap(max={"amount": LIVE_CAP}, calls=LIVE_CALLS) if live else None

        @pp.action(REFUND_TOOL, result=lambda order_id, amount: f"refund of {amount} on order {order_id} recorded", live=cap)
        def refund(order_id: str, amount: int) -> str:
            self.carried_out.append((order_id, amount))
            return f"refund of {amount} on order {order_id} carried out"

        self._refund = refund

    def _issue_refund(self, authorization: tuple[str, int] | None, order_id: str, amount: int) -> ToolCall:
        call = super()._issue_refund(authorization, order_id, amount)
        if call.accepted:
            self._refund(order_id, amount)
        return call


def harness_app(bot: HarnessPracticeBot) -> Any:
    """The practice bot as a web app, wrapped by the harness. One conversation per session id."""
    state: dict[str, Any] = {"planted": None, "sessions": {}}
    lock = threading.Lock()

    def app(environ: dict[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
        def answer(status: str, payload: Any) -> list[bytes]:
            data = json.dumps(payload).encode()
            start_response(status, [("Content-Type", "application/json"), ("Content-Length", str(len(data)))])
            return [data]

        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
            body = json.loads(environ["wsgi.input"].read(min(length, 100_000)) or b"{}")
            session_id, user, message = body["session_id"], body["user"], body["message"]
        except (ValueError, KeyError, TypeError):
            return answer("400 Bad Request", {"error": "send session_id, user and message as JSON"})
        if environ.get("PATH_INFO") != "/chat" or not pp.active():
            # This demo bot has no real users: outside a test session it has nothing to say.
            return answer("404 Not Found", {"error": "the demo bot only answers Promptproof test sessions at /chat"})
        with lock:
            planted = (
                {slot.id: pp.planted(slot.id) for slot in bot.slots()},
                {point.id: pp.content(point.id) for point in bot.injection_points() if pp.content(point.id)},
            )
            if planted != state["planted"]:  # a new attempt: new fake secrets, so start from a clean state
                asyncio.run(bot.reset(*planted))
                state["planted"], state["sessions"] = planted, {}
            sessions = state["sessions"]
            if session_id not in sessions:
                sessions[session_id] = asyncio.run(bot.open_session(user))
            reply = asyncio.run(sessions[session_id].send(message))
        return answer("200 OK", {"reply": reply.text})

    return pp.wrap(app)


class _Quiet(WSGIRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        pass


def serve(bot: HarnessPracticeBot, port: int = 0) -> WSGIServer:
    """Serve the wrapped practice bot on this machine in a background thread."""
    server = make_server("127.0.0.1", port, harness_app(bot), handler_class=_Quiet)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def description(port: int, variant: str, live: bool = False) -> dict[str, Any]:
    """The target description for a served HarnessPracticeBot."""
    from promptproof.practice_server import practice_description

    raw = practice_description(port, variant)
    del raw["reset"], raw["chat"]["tool_calls_pointer"]
    raw["harness"] = "sdk"
    if live:
        raw["live_actions"] = [REFUND_TOOL]
    return raw


@contextmanager
def _environment(**values: str) -> Iterator[None]:
    before = {name: os.environ.get(name) for name in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for name, value in before.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _demo(args: argparse.Namespace) -> int:
    from promptproof.attacks.library import default_attacks
    from promptproof.cli import _summary, _write, open_for_a_person
    from promptproof.core.authorization import new_authorization
    from promptproof.core.runner import ScanConfig, run_scan, run_to_completion
    from promptproof.report_html import render_html
    from promptproof.report_markdown import render_markdown
    from promptproof.seal import seal
    from promptproof.targets.http import HttpTarget, parse_config

    directory = Path(args.dir)
    if directory.exists() and any(directory.iterdir()):
        print(f"error: {directory} is not empty; give a new or empty --dir")
        return 2
    switches = {pp.KEY_ENV: pp.new_key()}
    if args.live:
        switches[pp.LIVE_ENV] = REFUND_TOOL
    print("Promptproof demo. Everything runs on this machine; nothing is sent anywhere else.")
    with _environment(**switches):
        for variant in ("vulnerable", "fixed"):
            bot = HarnessPracticeBot(variant, live=args.live)
            server = serve(bot)
            try:
                origin = f"http://127.0.0.1:{server.server_address[1]}"
                permission = new_authorization(
                    origin, "the promptproof demo command", "the built-in practice bot on this machine", "test", 1,
                    datetime.now(UTC), allowed_tools=(REFUND_TOOL,), live_tools=(REFUND_TOOL,) if args.live else (),
                )  # fmt: skip
                raw = description(server.server_address[1], variant, args.live)
                digest = hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]
                config = parse_config(f"practice-{variant}", raw, digest)
                target = HttpTarget(config, f"http:practice-{variant}", permission)
                report = run_to_completion(
                    run_scan(target, default_attacks(target), ScanConfig(reproduction_trials=args.replays))
                )
            finally:
                server.shutdown()
                server.server_close()
            folder = directory / variant
            out = folder / "scan.promptproof.json"
            _write(out, json.dumps(report.to_dict(), indent=2))
            _write(folder / "report.md", render_markdown(report, str(out)))
            _write(folder / "report.html", render_html(report, str(out)))
            value = seal(folder, directory / f"{variant}.sealed.zip")
            print()
            print(f"== The {variant} build ==")
            print(_summary(report))
            if args.live:
                kept = all(amount <= LIVE_CAP for _, amount in bot.carried_out)
                print(
                    f"Refunds really carried out (a line in the practice ledger): {len(bot.carried_out)}, "
                    f"{'all' if kept else 'NOT all'} within the cap of {LIVE_CAP}."
                )
            if args.live:
                stopped = json.dumps(report.to_dict()).count("[not run: ")
                print(f"Tool calls stopped by the cap and kept as evidence: {stopped}.")
            print(f"Open: {(folder / 'report.html').resolve()}")
            print(f"Sealed evidence: {(directory / f'{variant}.sealed.zip').resolve()}  seal {value}")
            if variant == "vulnerable":
                open_for_a_person(folder / "report.html", args.no_open)
    print()
    print("The vulnerable build shows what a proven finding looks like; the fixed build shows what you see when nothing is found.")
    print("To wire your own bot the same way, run: promptproof guide")
    return 0


def register(commands: Any) -> None:
    parser = commands.add_parser("demo", help="scan the built-in practice bot, vulnerable and fixed, on this machine")
    parser.add_argument("--dir", default="promptproof-demo", help="where the reports go (default promptproof-demo)")
    parser.add_argument("--replays", type=int, default=2, help="replays of each attack that worked (default 2)")
    parser.add_argument(
        "--live", action="store_true",
        help=f"let the practice refund tool really run for refunds up to {LIVE_CAP} (a ledger line; no money exists)",
    )  # fmt: skip
    parser.add_argument("--no-open", action="store_true", help="do not open the report in a browser")
    parser.set_defaults(handler=_demo)
