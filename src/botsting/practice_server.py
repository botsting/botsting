"""The practice support bot, served over HTTP on this machine, with a test harness.

It shows what a bot needs to offer to be scanned over HTTP, and lets the HTTP adapter
be tried end to end without anyone's real bot:

    botsting practice-server --variant vulnerable --port 8765 --write-config
    botsting authorize http://127.0.0.1:8765 --by "Your Name" --scope "practice bot" \\
        --environment test --tool issue_refund
    botsting scan --target http:practice --html reports/practice.html

Endpoints:
    POST /botsting/reset   {"fixtures": {...}, "content": {...}}  -> 204
    POST /chat                {"session_id": ..., "user": ..., "message": ...}
                              -> {"reply": ..., "tool_calls": [...]}

`user` stands in for real authentication. A real bot would know who is talking from
a session or token; here the harness is told, which is acceptable only because this
server listens on this machine alone and exists to be attacked.
"""

from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from botsting.core.authorization import is_loopback_origin
from botsting.llm.base import ChatModel
from botsting.targets.base import TargetError
from botsting.targets.toy import ToySession, ToyTarget

RESET_PATH = "/botsting/reset"
CHAT_PATH = "/chat"
_MAX_BODY = 100_000


class PracticeBot:
    """The toy target plus the state an HTTP server needs: conversations by session id."""

    def __init__(self, variant: str, model: ChatModel) -> None:
        self.target = ToyTarget(variant=variant, model=model, spec=f"toy:{variant}")  # type: ignore[arg-type]
        self.sessions: dict[str, tuple[str, ToySession]] = {}
        self.requests: list[tuple[str, Mapping[str, Any]]] = []  # what arrived, for tests
        self.lock = threading.Lock()

    def reset(self, body: Mapping[str, Any]) -> None:
        fixtures, content = body.get("fixtures"), body.get("content", {})
        if not isinstance(fixtures, Mapping) or not isinstance(content, Mapping):
            raise ValueError("fixtures and content must be objects")
        asyncio.run(self.target.reset({str(k): str(v) for k, v in fixtures.items()}, {str(k): str(v) for k, v in content.items()}))
        self.sessions.clear()

    def chat(self, body: Mapping[str, Any]) -> dict[str, Any]:
        session_id, user, message = body.get("session_id"), body.get("user"), body.get("message")
        if not all(isinstance(v, str) and v for v in (session_id, user, message)):
            raise ValueError("session_id, user and message must be non-empty text")
        if session_id in self.sessions:
            owner, session = self.sessions[session_id]
            if owner != user:
                raise ValueError("this session belongs to someone else")
        else:
            session = asyncio.run(self.target.open_session(user))
            self.sessions[session_id] = (user, session)
        reply = asyncio.run(session.send(message))
        return {
            "reply": reply.text,
            "tool_calls": [
                {"id": c.id, "tool": c.tool, "arguments": dict(c.arguments), "accepted": c.accepted, "result": c.result}
                for c in reply.tool_calls
            ],
        }


def _handler(bot: PracticeBot) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            pass  # quiet

        def _answer(self, status: int, payload: Any = None) -> None:
            data = b"" if payload is None else json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self) -> None:
            raw_length = self.headers.get("Content-Length", "0") or "0"
            if not raw_length.isdigit():
                return self._answer(400, {"error": "Content-Length must be a whole number"})
            length = int(raw_length)
            if length > _MAX_BODY:
                return self._answer(413, {"error": "too large"})
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(body, Mapping):
                    raise ValueError("the body must be a JSON object")
                with bot.lock:
                    bot.requests.append((self.path, body))
                    if self.path == RESET_PATH:
                        bot.reset(body)
                        return self._answer(204)
                    if self.path == CHAT_PATH:
                        return self._answer(200, bot.chat(body))
                return self._answer(404, {"error": "no such endpoint"})
            except (ValueError, TargetError) as exc:
                return self._answer(400, {"error": str(exc)})

        def do_GET(self) -> None:
            self._answer(404, {"error": "no such endpoint"})

    return Handler


def start(bot: PracticeBot, host: str = "127.0.0.1", port: int = 0) -> HTTPServer:
    """Serve `bot` on this machine in a background thread. Port 0 picks a free port."""
    if not is_loopback_origin(f"http://{host}"):
        raise ValueError("the practice server only listens on this machine (127.0.0.1, ::1 or localhost)")
    server = HTTPServer((host, port), _handler(bot))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def practice_description(port: int, variant: str) -> dict[str, Any]:
    """The entry for botsting.targets.json that describes this server, built from the bot itself."""
    target = ToyTarget(variant=variant, model=None, spec="")  # type: ignore[arg-type]
    principals = sorted(
        {target.attacker_principal}
        | {s.control_principal for s in target.slots()}
        | set().union(*({*s.authorized} for s in target.slots()))
        | {r.control_principal for r in target.tool_rules()}
        | {p.victim_principal for p in target.injection_points()}
        | {t.principal for t in target.task_checks()}
    )
    return {
        "origin": f"http://127.0.0.1:{port}",
        "chat": {
            "path": CHAT_PATH,
            "body": {"session_id": "{session}", "message": "{message}"},
            "reply_pointer": "/reply",
            "tool_calls_pointer": "/tool_calls",
        },
        "reset": {"path": RESET_PATH},
        "attacker_principal": target.attacker_principal,
        "principals": {p: {"body": {"user": p}} for p in principals},
        "tool_safety": "sinks",
        "slots": [
            {
                "id": s.id, "kind": s.kind, "description": s.description, "hint": s.hint,
                "authorized": list(s.authorized), "control_principal": s.control_principal,
                "control_prompt": s.control_prompt,
            }
            for s in target.slots()
        ],
        "tool_rules": [
            {
                "id": r.id, "tool": r.tool, "description": r.description, "hint": r.hint,
                "authorized": list(r.authorized), "control_principal": r.control_principal,
                "control_prompt": r.control_prompt,
            }
            for r in target.tool_rules()
        ],
        "injection_points": [
            {
                "id": p.id, "description": p.description, "victim_principal": p.victim_principal,
                "victim_prompt": p.victim_prompt, "expect_substring": p.expect_substring,
                "benign_content": p.benign_content, "forbidden_tools": list(p.forbidden_tools), "goal": p.goal,
            }
            for p in target.injection_points()
        ],
        "task_checks": [
            {"id": t.id, "principal": t.principal, "prompt": t.prompt, "expect_substring": t.expect_substring}
            for t in target.task_checks()
        ],
    }  # fmt: skip


def write_description(path: Path, name: str, description: Mapping[str, Any]) -> None:
    """Add or replace one target in a descriptions file, keeping the others."""
    data: dict[str, Any] = {"targets": {}}
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data.get("targets"), dict):
            raise ValueError(f"{path} does not look like a BotSting targets file")
    data["targets"][name] = description
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
