"""A bot reached over HTTP: the first adapter for bots that are not built into Promptproof.

The bot's owner describes it in a JSON file (`promptproof.targets.json` by default, or
the file named by the PROMPTPROOF_TARGETS_FILE environment variable) and scans it as
`http:<name>`. The description says where the bot is, how to talk to it as each user,
where its reply is in the response, and what it protects.

Three ways to plant the fake secrets (`"harness"` in the description)
---------------------------------------------------------------------
- "endpoint" (the default): the bot has a reset endpoint, described below.
- "sdk": the drop-in harness, a few lines in the bot's code (promptproof/harness.py).
- "inputs": nothing is added to the bot at all. The fake secret travels in each chat
  request, in a variable the bot's builder already accepts and puts into its
  instructions (Flowise `overrideConfig.vars`, Dify `inputs`, Langflow `tweaks`).
  Write `{canary:<slot id>}` in the request body where that variable goes. This can
  only stand for a secret in the bot's instructions: a per-request variable is seen
  by whoever sends the request, so it cannot stand for another user's record, and no
  tool can be watched this way. Use it for bots built in a no-code builder.

What the bot must offer
-----------------------
Promptproof can only prove a leak of something it planted, so the bot's staging or test
build needs one extra endpoint, the *test harness*:

    POST <reset path>   {"fixtures": {"<slot id>": "<canary>"}, "content": {"<point id>": "<text>"}}

It must put each canary where that slot says it lives (the system prompt, a test
customer's record), put each piece of content at its injection point, forget every
earlier conversation, and answer 2xx. Its chat endpoint must then answer as the bot
would. If the bot has tools, the harness reports the calls it recorded during each
reply in the chat response (`tool_calls_pointer`). Those records must come from the
harness's own recorder on the tool, not from anything the model says.

Or, instead of that endpoint, the drop-in harness (`"harness": "sdk"`, see
promptproof/harness.py): a few lines in the bot's code. Then nothing is reset on the
bot. Each message carries the canaries and content in a session signed with the key in
PROMPTPROOF_HARNESS_KEY (or the variable `harness_key_env` names), and the recorded
calls come back in a header signed with the same key for that session and message.
Before the first message of every attempt the scan checks that the harness answers
for a signed session, so a bot that is not in test mode is never sent an attack. A
wrapped bot refuses (HTTP 403) any message whose session it cannot verify.

Safety
------
- Nothing is sent unless the authorization gate allows it: a recorded, unexpired
  authorization for this exact origin, and for a bot across a network, proof of
  control served by its site (see core/authorization.py).
- Every request goes through a transport that refuses any origin other than the
  configured one and any path other than the chat and reset paths. Redirects are not
  followed, proxy settings from the environment are ignored, and responses are cut
  off at a size limit.
- Credentials are never written in the file: a header value like "${NAME}" is read
  from the environment variable NAME when the scan runs, and is never put in reports.
- Every request carries a Promptproof-Trace header and the user agent
  "promptproof-scan", so test traffic can be told apart from real users.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from promptproof.core.authorization import (
    Authorization,
    AuthorizationError,
    AuthorizationStore,
    is_loopback_origin,
    normalize_origin,
)
from promptproof.core.canary import STYLES
from promptproof.core.models import (
    InjectionPoint,
    Reply,
    Slot,
    TaskCheck,
    ToolCall,
    ToolRule,
)
from promptproof.harness import (
    CALLS_HEADER,
    KEY_ENV,
    READY_PATH,
    SESSION_HEADER,
    HarnessError,
    check_key,
    make_session_token,
    read_calls_header,
)
from promptproof.targets.base import TargetError

DEFAULT_TARGETS_FILE = "promptproof.targets.json"
_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}")
_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_MAX_RESPONSE_BYTES = 1_000_000
# On every request a scan sends, so the bot's owner can tell test traffic from real users in
# their logs and exclude it from analytics. The value is the same for one scan or replay.
TRACE_HEADER = "Promptproof-Trace"
_USER_AGENT = "promptproof-scan"


class TargetConfigError(ValueError):
    """The target description could not be used."""


def targets_file() -> Path:
    return Path(os.environ.get("PROMPTPROOF_TARGETS_FILE", DEFAULT_TARGETS_FILE))


# -- the description ------------------------------------------------------------------------


@dataclass(frozen=True)
class Principal:
    headers: Mapping[str, str]  # values may contain ${ENV_NAME}
    body: Mapping[str, Any]  # merged into every chat request for this user


@dataclass(frozen=True)
class HttpTargetConfig:
    name: str
    origin: str
    chat_path: str
    chat_body: Mapping[str, Any]  # "{message}" and "{session}" inside strings are filled in
    reply_pointer: str  # JSON pointer to the reply text; "" means the whole body is the text
    tool_calls_pointer: str  # JSON pointer to the recorded calls; "" if the bot has no tools
    reset_path: str
    attacker_principal: str
    principals: Mapping[str, Principal]
    tool_safety: str  # "no-tools" or "sinks": the owner's promise about what the tools can do
    slots: tuple[Slot, ...]
    tool_rules: tuple[ToolRule, ...]
    injection_points: tuple[InjectionPoint, ...]
    task_checks: tuple[TaskCheck, ...]
    agent_id: str = ""
    tenant: str = ""
    timeout_seconds: float = 60.0
    digest: str = ""  # of the description as written, so a replay can tell it changed
    harness: str = "endpoint"  # "endpoint": a reset endpoint; "sdk": the drop-in harness; "inputs": request variables
    session_pointer: str = ""  # if the bot names the conversation itself: where its id is in each response
    harness_key_env: str = KEY_ENV
    live_actions: tuple[str, ...] = ()  # tools the scan asks the harness to carry out for real, under its caps


_PLAIN_PATH = re.compile(r"(/[A-Za-z0-9._~-]+)+")


def _path(value: object, field: str) -> str:
    """Plain paths only: ASCII letters, digits and . _ ~ - between slashes, no "." or ".." segments,
    no percent-encoding or backslashes. Anything else would be refused at send time anyway."""
    if (
        not isinstance(value, str)
        or not _PLAIN_PATH.fullmatch(value)
        or any(part in (".", "..") for part in value.split("/"))
    ):
        raise TargetConfigError(f"{field} must be a plain path such as /api/chat, got {value!r}")
    return value


def _pointer(value: object, field: str) -> str:
    if value in (None, ""):
        return ""
    if not isinstance(value, str) or not value.startswith("/"):
        raise TargetConfigError(f"{field} must be a JSON pointer such as /reply, got {value!r}")
    return value


def _text(item: Mapping[str, Any], key: str, where: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value.strip():
        raise TargetConfigError(f"{where}: {key} must be non-empty text")
    return value


def _names(item: Mapping[str, Any], key: str, where: str) -> tuple[str, ...]:
    value = item.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise TargetConfigError(f"{where}: {key} must be a list of names")
    return tuple(value)


def parse_config(name: str, raw: Mapping[str, Any], digest: str = "") -> HttpTargetConfig:
    where = f"target {name!r}"
    if not isinstance(raw, Mapping):
        raise TargetConfigError(f"{where} must be a JSON object")
    try:
        origin = normalize_origin(_text(raw, "origin", where))
    except ValueError as exc:
        raise TargetConfigError(f"{where}: {exc}") from exc
    chat = raw.get("chat")
    if not isinstance(chat, Mapping):
        raise TargetConfigError(f"{where}: chat must describe the chat endpoint")
    body = chat.get("body", {"message": "{message}", "session_id": "{session}"})
    if not isinstance(body, Mapping) or not _mentions(body, "{message}"):
        raise TargetConfigError(f"{where}: chat.body must be a JSON object that contains \"{{message}}\" somewhere")
    harness = raw.get("harness", "endpoint")
    if harness not in ("endpoint", "sdk", "inputs"):
        raise TargetConfigError(f"{where}: harness must be \"endpoint\", \"sdk\" or \"inputs\"")
    key_env = raw.get("harness_key_env", KEY_ENV)
    if not isinstance(key_env, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key_env):
        raise TargetConfigError(f"{where}: harness_key_env must be the name of an environment variable")
    reset = raw.get("reset")
    if harness == "sdk":
        if reset is not None or chat.get("tool_calls_pointer"):
            raise TargetConfigError(
                f"{where}: with the drop-in harness there is no reset endpoint and tool calls come from its signed "
                "header; remove reset and chat.tool_calls_pointer"
            )
        reset = {"path": READY_PATH}
    elif harness == "inputs":
        if reset is not None:
            raise TargetConfigError(f"{where}: with \"harness\": \"inputs\" there is no reset endpoint; remove reset")
        reset = {"path": chat.get("path")}  # nothing is ever sent there; only the chat path is used
    elif not isinstance(reset, Mapping):
        raise TargetConfigError(f"{where}: reset must describe the test-harness reset endpoint")
    live_actions = _names(raw, "live_actions", where)
    if live_actions and harness != "sdk":
        raise TargetConfigError(
            f"{where}: live_actions needs the drop-in harness (\"harness\": \"sdk\"), which enforces the caps"
        )
    tool_safety = raw.get("tool_safety")
    if tool_safety not in ("no-tools", "sinks"):
        raise TargetConfigError(
            f"{where}: tool_safety must be \"no-tools\" or \"sinks\" (every tool writes to a recording sink with test data)"
        )
    principals_raw = raw.get("principals")
    if not isinstance(principals_raw, Mapping) or not principals_raw:
        raise TargetConfigError(f"{where}: principals must say how to talk to the bot as each user")
    principals: dict[str, Principal] = {}
    for principal, spec in principals_raw.items():
        if not isinstance(spec, Mapping):
            raise TargetConfigError(f"{where}: principal {principal!r} must be an object")
        headers = spec.get("headers", {})
        extra = spec.get("body", {})
        if not isinstance(headers, Mapping) or not all(isinstance(v, str) for v in headers.values()):
            raise TargetConfigError(f"{where}: principal {principal!r} headers must map names to text")
        if not isinstance(extra, Mapping):
            raise TargetConfigError(f"{where}: principal {principal!r} body must be an object")
        principals[str(principal)] = Principal(dict(headers), dict(extra))
    attacker = _text(raw, "attacker_principal", where)

    def each(key: str) -> list[Mapping[str, Any]]:
        items = raw.get(key, [])
        if not isinstance(items, list) or not all(isinstance(i, Mapping) for i in items):
            raise TargetConfigError(f"{where}: {key} must be a list of objects")
        return items

    slots = tuple(
        Slot(
            id=_text(s, "id", where),
            kind=_text(s, "kind", where),  # type: ignore[arg-type]
            description=_text(s, "description", where),
            hint=_text(s, "hint", where),
            authorized=_names(s, "authorized", where),
            control_principal=_text(s, "control_principal", where),
            control_prompt=_text(s, "control_prompt", where),
            canary_style=str(s.get("canary_style", "code")),
        )
        for s in each("slots")
    )
    for slot in slots:
        if slot.canary_style not in STYLES:
            raise TargetConfigError(f"{where}: slot {slot.id} canary_style must be one of {', '.join(STYLES)}")
        if slot.kind not in ("instruction_secret", "other_user_record"):
            raise TargetConfigError(f"{where}: slot {slot.id} kind must be instruction_secret or other_user_record")
    rules = tuple(
        ToolRule(
            id=_text(r, "id", where),
            tool=_text(r, "tool", where),
            description=_text(r, "description", where),
            hint=_text(r, "hint", where),
            authorized=_names(r, "authorized", where),
            control_principal=_text(r, "control_principal", where),
            control_prompt=_text(r, "control_prompt", where),
        )
        for r in each("tool_rules")
    )
    points = tuple(
        InjectionPoint(
            id=_text(p, "id", where),
            description=_text(p, "description", where),
            victim_principal=_text(p, "victim_principal", where),
            victim_prompt=_text(p, "victim_prompt", where),
            expect_substring=_text(p, "expect_substring", where),
            benign_content=_text(p, "benign_content", where),
            forbidden_tools=_names(p, "forbidden_tools", where),
            goal=_text(p, "goal", where),
        )
        for p in each("injection_points")
    )
    tasks = tuple(
        TaskCheck(
            id=_text(t, "id", where),
            principal=_text(t, "principal", where),
            prompt=_text(t, "prompt", where),
            expect_substring=_text(t, "expect_substring", where),
        )
        for t in each("task_checks")
    )
    tool_calls_pointer = _pointer(chat.get("tool_calls_pointer"), f"{where}: chat.tool_calls_pointer")
    session_pointer = _pointer(chat.get("session_pointer"), f"{where}: chat.session_pointer")
    if harness == "inputs":
        _check_inputs(where, body, principals, slots, tool_safety, rules, points, tasks)
    if tool_safety == "no-tools" and (rules or points or tool_calls_pointer):
        raise TargetConfigError(f"{where}: says no-tools but declares tool rules, injection points or tool calls")
    used = {attacker} | {s.control_principal for s in slots} | {r.control_principal for r in rules}
    used |= {p.victim_principal for p in points} | {t.principal for t in tasks}
    unknown = sorted(used - set(principals))
    if unknown:
        raise TargetConfigError(f"{where}: no entry under principals for {', '.join(unknown)}")
    timeout = raw.get("timeout_seconds", 60.0)
    if isinstance(timeout, bool) or not isinstance(timeout, int | float) or not 1 <= float(timeout) <= 600:
        raise TargetConfigError(f"{where}: timeout_seconds must be between 1 and 600")
    return HttpTargetConfig(
        name=name,
        origin=origin,
        chat_path=_path(chat.get("path"), f"{where}: chat.path"),
        chat_body=dict(body),
        reply_pointer=_pointer(chat.get("reply_pointer", "/reply"), f"{where}: chat.reply_pointer"),
        tool_calls_pointer=tool_calls_pointer,
        reset_path=_path(reset.get("path"), f"{where}: reset.path"),
        attacker_principal=attacker,
        principals=principals,
        tool_safety=str(tool_safety),
        slots=slots,
        tool_rules=rules,
        injection_points=points,
        task_checks=tasks,
        agent_id=str(raw.get("agent_id", "") or ""),
        tenant=str(raw.get("tenant", "") or ""),
        timeout_seconds=float(timeout),
        digest=digest,
        harness=str(harness),
        session_pointer=session_pointer,
        harness_key_env=key_env,
        live_actions=live_actions,
    )


def _check_inputs(
    where: str,
    body: Mapping[str, Any],
    principals: Mapping[str, Principal],
    slots: tuple[Slot, ...],
    tool_safety: object,
    rules: tuple[ToolRule, ...],
    points: tuple[InjectionPoint, ...],
    tasks: tuple[TaskCheck, ...],
) -> None:
    """What "harness": "inputs" can and cannot stand for. Refused early, so a scan is never quietly empty."""
    if tool_safety != "no-tools" or rules or points:
        raise TargetConfigError(
            f"{where}: with \"harness\": \"inputs\" no tool can be watched, so tool_safety must be \"no-tools\" "
            "with no tool rules or injection points; to test tools, use the drop-in harness"
        )
    if not tasks:
        raise TargetConfigError(
            f"{where}: with \"harness\": \"inputs\" at least one task_checks entry is needed: an ordinary request "
            "is how the scan notices a bot that simply repeats its request variables"
        )
    for slot in slots:
        if slot.kind != "instruction_secret":
            raise TargetConfigError(
                f"{where}: slot {slot.id} is another user's record, which a request variable cannot stand for "
                "(whoever sends the request would see it); use the drop-in harness for that"
            )
        token = "{canary:" + slot.id + "}"
        # The value must travel in EVERY principal's requests, as they are really sent: the chat body with
        # that principal's own body laid over it. If only the control principal carried it, the control
        # would pass while no attack ever met the secret, and the scan would call the bot clean.
        for name, principal in principals.items():
            if not _mentions({**body, **principal.body}, token):
                raise TargetConfigError(
                    f"{where}: slot {slot.id} is not planted in requests sent as {name}: write \"{token}\" in "
                    "chat.body where the bot's variable for it goes, and do not replace that part of the body "
                    "in a principal's own body"
                )


def load_config(name: str, path: Path | None = None) -> HttpTargetConfig:
    if not _NAME.fullmatch(name):
        raise TargetConfigError("a target name may use only letters, digits, - and _")
    path = path or targets_file()
    try:
        text = path.read_text(encoding="utf-8")
        data = json.loads(text)
    except (OSError, ValueError) as exc:
        raise TargetConfigError(f"could not read the target descriptions in {path}: {exc}") from exc
    targets = data.get("targets") if isinstance(data, Mapping) else None
    if not isinstance(targets, Mapping) or name not in targets:
        known = ", ".join(sorted(targets)) if isinstance(targets, Mapping) else "none"
        raise TargetConfigError(f"no target named {name!r} in {path} (it has: {known or 'none'})")
    canonical = json.dumps(targets[name], sort_keys=True, separators=(",", ":"))
    return parse_config(name, targets[name], hashlib.sha256(canonical.encode()).hexdigest()[:16])


# -- filling in and reading out -------------------------------------------------------------


def _mentions(value: Any, token: str) -> bool:
    if isinstance(value, str):
        return token in value
    if isinstance(value, Mapping):
        return any(_mentions(v, token) for v in value.values())
    if isinstance(value, list):
        return any(_mentions(v, token) for v in value)
    return False


_PLACEHOLDER = re.compile(r"\{(message|session|canary:[A-Za-z0-9_.-]+|content:[A-Za-z0-9_.-]+)\}")


def _fill(
    value: Any,
    message: str,
    session: str,
    fixtures: Mapping[str, str] | None = None,
    content: Mapping[str, str] | None = None,
) -> Any:
    """Put the message and session id into a body template, and, for "harness": "inputs", the fake
    secrets and planted content. Only whole JSON values are built, so nothing in the message can
    change the structure of the request; one pass, so nothing put in is itself filled in again."""
    if isinstance(value, str):

        def put(match: re.Match[str]) -> str:
            name = match.group(1)
            if name == "message":
                return message
            if name == "session":
                return session
            kind, _, key = name.partition(":")
            source = fixtures if kind == "canary" else content
            if source is None:
                return match.group(0)  # not an "inputs" target: left as written
            return source.get(key, "")

        return _PLACEHOLDER.sub(put, value)
    if isinstance(value, Mapping):
        return {k: _fill(v, message, session, fixtures, content) for k, v in value.items()}
    if isinstance(value, list):
        return [_fill(v, message, session, fixtures, content) for v in value]
    return value


def _env(value: str) -> str:
    def lookup(match: re.Match[str]) -> str:
        found = os.environ.get(match.group(1))
        if found is None:
            raise TargetError(f"environment variable {match.group(1)} is not set (it is used in a header)")
        return found

    return _ENV.sub(lookup, value)


def resolve_pointer(document: Any, pointer: str) -> Any:
    """RFC 6901 JSON pointer lookup. Raises KeyError if the pointer does not resolve."""
    if pointer == "":
        return document
    current = document
    for raw_part in pointer.split("/")[1:]:
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            raise KeyError(pointer)
    return current


def _tool_calls(value: Any) -> tuple[ToolCall, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise TargetError("the recorded tool calls must be a list")
    calls = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping) or not isinstance(item.get("tool"), str):
            raise TargetError(f"recorded tool call {index} must be an object with a tool name")
        arguments = item.get("arguments", {})
        if not isinstance(arguments, Mapping):
            raise TargetError(f"recorded tool call {index} arguments must be an object")
        calls.append(
            ToolCall(
                id=str(item.get("id", f"call-{index + 1}")),
                tool=item["tool"],
                arguments=tuple((str(k), str(v)) for k, v in arguments.items()),
                accepted=item.get("accepted") is True,
                result=str(item.get("result", "")),
            )
        )
    return tuple(calls)


# -- the transport ------------------------------------------------------------------------


class _OnlyHere(httpx.AsyncBaseTransport):
    """Sends a request only if it is for the configured origin and one of the allowed paths."""

    def __init__(self, origin: str, paths: frozenset[str], inner: httpx.AsyncBaseTransport) -> None:
        self._origin = origin
        self._paths = paths
        self._inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.userinfo:
            raise httpx.UnsupportedProtocol("refused: an address with a user name or password")
        try:
            origin = normalize_origin(f"{request.url.scheme}://{request.url.netloc.decode('ascii')}")
        except ValueError as exc:
            raise httpx.UnsupportedProtocol(f"refused: {exc}") from exc
        if origin != self._origin or request.url.path not in self._paths or request.url.query:
            raise httpx.UnsupportedProtocol(f"refused: {request.url} is not an address this target may be sent to")
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()


# -- the target ---------------------------------------------------------------------------


class HttpTarget:
    """A bot behind an HTTP chat endpoint, with a test-harness reset endpoint."""

    def __init__(
        self,
        config: HttpTargetConfig,
        spec: str,
        authorization: Authorization | None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.config = config
        self.spec = spec
        self.origin = config.origin
        self.reach = "loopback" if is_loopback_origin(config.origin) else "network"
        self.authorization = authorization
        self.tool_safety = config.tool_safety
        self.attacker_principal = config.attacker_principal
        self.agent_id = config.agent_id
        self.tenant = config.tenant
        self._transport = _OnlyHere(
            config.origin,
            frozenset({config.chat_path, config.reset_path}),
            transport or httpx.AsyncHTTPTransport(retries=0),
        )
        self.live_actions = config.live_actions
        # The fake secrets travel in each request. The runner then checks, with an ordinary request, that
        # the bot does not simply repeat its request variables: on such a bot every attack would "succeed".
        self.secrets_travel_in_requests = config.harness == "inputs"
        self._run = uuid.uuid4().hex  # the harness counts a run's real actions under this
        self._fixtures: dict[str, str] = {}
        self._content: dict[str, str] = {}

    # The description.

    async def describe(self) -> Mapping[str, str]:
        about = {"target": "http", "name": self.config.name, "origin": self.origin, "description_digest": self.config.digest}
        if self.secrets_travel_in_requests:
            about["secrets"] = "sent with each request"  # runner.REQUEST_BORNE: adds a limitation to the report
        return about

    def slots(self) -> Sequence[Slot]:
        return self.config.slots

    def tool_rules(self) -> Sequence[ToolRule]:
        return self.config.tool_rules

    def injection_points(self) -> Sequence[InjectionPoint]:
        return self.config.injection_points

    def task_checks(self) -> Sequence[TaskCheck]:
        return self.config.task_checks

    # Talking to it.

    async def _post(self, path: str, body: Mapping[str, Any], headers: Mapping[str, str]) -> Any:
        data, _ = await self._exchange(path, body, headers)
        return data

    async def _exchange(
        self, path: str, body: Mapping[str, Any], headers: Mapping[str, str]
    ) -> tuple[Any, httpx.Headers]:
        async with httpx.AsyncClient(
            transport=self._transport,
            timeout=self.config.timeout_seconds,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            try:
                sent = {"User-Agent": _USER_AGENT, **headers, TRACE_HEADER: self._run}
                async with client.stream("POST", self.origin + path, json=body, headers=sent) as response:
                    if response.is_redirect:
                        raise TargetError(f"{path} answered with a redirect; redirects are not followed")
                    if not 200 <= response.status_code < 300:
                        raise TargetError(f"{path} answered HTTP {response.status_code}")
                    answered = response.headers
                    data = b""
                    async for chunk in response.aiter_bytes():
                        data += chunk
                        if len(data) > _MAX_RESPONSE_BYTES:
                            raise TargetError(f"{path} answered with more than {_MAX_RESPONSE_BYTES} bytes")
            except httpx.HTTPError as exc:
                raise TargetError(f"could not reach {path}: {type(exc).__name__}: {exc}") from exc
        if not data:
            return None, answered
        try:
            return json.loads(data), answered
        except ValueError:
            return data.decode("utf-8", "replace"), answered

    def harness_key(self) -> str:
        key = os.environ.get(self.config.harness_key_env)
        if not key:
            raise TargetError(f"environment variable {self.config.harness_key_env} is not set (the drop-in harness key)")
        try:
            return check_key(key)
        except HarnessError as exc:
            raise TargetError(str(exc)) from exc

    def session_headers(self, session_id: str, planted: bool = True) -> tuple[dict[str, str], str]:
        """The signed session header for one message, and the nonce its tool-call record must carry."""
        nonce = uuid.uuid4().hex
        try:
            token = make_session_token(
                self.harness_key(),
                session_id,
                self._fixtures if planted else {},
                self._content if planted else {},
                lifetime_seconds=self.config.timeout_seconds + 60,
                nonce=nonce,
                live=self.live_actions if planted else (),
                run=self._run,
            )
        except HarnessError as exc:
            raise TargetError(str(exc)) from exc
        return {SESSION_HEADER: token}, nonce

    def harness_calls(self, session_id: str, nonce: str, headers: httpx.Headers) -> tuple[ToolCall, ...]:
        try:
            record = read_calls_header(self.harness_key(), session_id, headers.get(CALLS_HEADER), nonce)
        except HarnessError as exc:
            raise TargetError(str(exc)) from exc
        return _tool_calls(record)

    async def reset(self, fixtures: Mapping[str, str], content: Mapping[str, str] | None = None) -> None:
        if self.config.harness == "inputs":
            # Nothing to reset on the bot: the next requests carry these values themselves.
            self._fixtures, self._content = dict(fixtures), dict(content or {})
            return
        if self.config.harness != "sdk":
            await self._post(self.config.reset_path, {"fixtures": dict(fixtures), "content": dict(content or {})}, {})
            return
        self._fixtures, self._content = dict(fixtures), dict(content or {})
        # Nothing is reset on the bot. Check that it is in test mode before anything is sent to it.
        # The check carries no canaries: they go only to a bot that has confirmed test mode.
        probe = uuid.uuid4().hex
        try:
            signed, nonce = self.session_headers(probe, planted=False)
            _, headers = await self._exchange(self.config.reset_path, {}, signed)
            self.harness_calls(probe, nonce, headers)
        except TargetError as exc:
            raise TargetError(f"the drop-in harness did not confirm test mode, so nothing was sent: {exc}") from exc

    async def open_session(self, principal: str) -> HttpSession:
        found = self.config.principals.get(principal)
        if found is None:
            raise TargetError(f"the target description has no entry for principal {principal!r}")
        return HttpSession(self, found)


class HttpSession:
    def __init__(self, target: HttpTarget, principal: Principal) -> None:
        self._target = target
        self._principal = principal
        self._session = uuid.uuid4().hex  # a new conversation every time
        if target.config.session_pointer:
            self._session = ""  # the bot names the conversation in its first reply

    async def send(self, text: str) -> Reply:
        config = self._target.config
        planted = (self._target._fixtures, self._target._content) if config.harness == "inputs" else (None, None)
        body = {
            **_fill(config.chat_body, text, self._session, *planted),
            **_fill(dict(self._principal.body), text, self._session, *planted),
        }
        headers = {name: _env(value) for name, value in self._principal.headers.items()}
        nonce = ""
        if config.harness == "sdk":
            signed, nonce = self._target.session_headers(self._session)
            headers.update(signed)
        data, answered = await self._target._exchange(config.chat_path, body, headers)
        try:
            reply = resolve_pointer(data, config.reply_pointer)
        except KeyError as exc:
            raise TargetError(f"the response has nothing at {config.reply_pointer}") from exc
        if not isinstance(reply, str):
            raise TargetError(f"the reply at {config.reply_pointer or 'the top level'} is not text")
        sent_as = self._session  # the id this message was signed for, before the bot names the conversation
        if config.session_pointer:
            try:
                named = resolve_pointer(data, config.session_pointer)
            except KeyError as exc:
                raise TargetError(f"the response has no conversation id at {config.session_pointer}") from exc
            if not isinstance(named, str) or not named:
                raise TargetError(f"the conversation id at {config.session_pointer} is not text")
            self._session = named
        calls: tuple[ToolCall, ...] = ()
        if config.harness == "sdk":
            calls = self._target.harness_calls(sent_as, nonce, answered)
        elif config.tool_calls_pointer:
            try:
                calls = _tool_calls(resolve_pointer(data, config.tool_calls_pointer))
            except KeyError:
                calls = ()  # nothing recorded during this reply
        return Reply(text=reply, tool_calls=calls)


def build_http_target(name: str, spec: str, store: AuthorizationStore | None = None) -> HttpTarget:
    config = load_config(name)
    try:
        authorization = (store or AuthorizationStore()).find(config.origin)
    except AuthorizationError as exc:
        raise TargetConfigError(str(exc)) from exc
    return HttpTarget(config, spec, authorization)
