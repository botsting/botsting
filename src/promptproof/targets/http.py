"""A bot reached over HTTP: the first adapter for bots that are not built into Promptproof.

The bot's owner describes it in a JSON file (`promptproof.targets.json` by default, or
the file named by the PROMPTPROOF_TARGETS_FILE environment variable) and scans it as
`http:<name>`. The description says where the bot is, how to talk to it as each user,
where its reply is in the response, and what it protects.

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
calls come back in a header signed with the same key. Before the first message of
every attempt the scan checks that the harness answers for a signed session, so a bot
that is not in test mode is never sent an attack.

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
    harness: str = "endpoint"  # "endpoint": the bot has a reset endpoint; "sdk": the drop-in harness
    harness_key_env: str = KEY_ENV


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
    if harness not in ("endpoint", "sdk"):
        raise TargetConfigError(f"{where}: harness must be \"endpoint\" or \"sdk\"")
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
    elif not isinstance(reset, Mapping):
        raise TargetConfigError(f"{where}: reset must describe the test-harness reset endpoint")
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
        harness_key_env=key_env,
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


def _fill(value: Any, message: str, session: str) -> Any:
    """Put the message and session id into a body template. Only whole JSON values are built,
    so nothing in the message can change the structure of the request."""
    if isinstance(value, str):
        return value.replace("{session}", session).replace("{message}", message)
    if isinstance(value, Mapping):
        return {k: _fill(v, message, session) for k, v in value.items()}
    if isinstance(value, list):
        return [_fill(v, message, session) for v in value]
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
        self._fixtures: dict[str, str] = {}
        self._content: dict[str, str] = {}

    # The description.

    async def describe(self) -> Mapping[str, str]:
        return {"target": "http", "name": self.config.name, "origin": self.origin, "description_digest": self.config.digest}

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
                async with client.stream("POST", self.origin + path, json=body, headers=dict(headers)) as response:
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

    def session_headers(self, session_id: str) -> dict[str, str]:
        try:
            token = make_session_token(
                self.harness_key(),
                session_id,
                self._fixtures,
                self._content,
                lifetime_seconds=self.config.timeout_seconds + 60,
            )
        except HarnessError as exc:
            raise TargetError(str(exc)) from exc
        return {SESSION_HEADER: token}

    def harness_calls(self, session_id: str, headers: httpx.Headers) -> tuple[ToolCall, ...]:
        try:
            return _tool_calls(read_calls_header(self.harness_key(), session_id, headers.get(CALLS_HEADER)))
        except HarnessError as exc:
            raise TargetError(str(exc)) from exc

    async def reset(self, fixtures: Mapping[str, str], content: Mapping[str, str] | None = None) -> None:
        if self.config.harness != "sdk":
            await self._post(self.config.reset_path, {"fixtures": dict(fixtures), "content": dict(content or {})}, {})
            return
        self._fixtures, self._content = dict(fixtures), dict(content or {})
        # Nothing is reset on the bot. Check that it is in test mode before anything is sent to it.
        probe = uuid.uuid4().hex
        try:
            _, headers = await self._exchange(self.config.reset_path, {}, self.session_headers(probe))
            self.harness_calls(probe, headers)
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

    async def send(self, text: str) -> Reply:
        config = self._target.config
        body = {**_fill(config.chat_body, text, self._session), **dict(self._principal.body)}
        headers = {name: _env(value) for name, value in self._principal.headers.items()}
        if config.harness == "sdk":
            headers.update(self._target.session_headers(self._session))
        data, answered = await self._target._exchange(config.chat_path, body, headers)
        try:
            reply = resolve_pointer(data, config.reply_pointer)
        except KeyError as exc:
            raise TargetError(f"the response has nothing at {config.reply_pointer}") from exc
        if not isinstance(reply, str):
            raise TargetError(f"the reply at {config.reply_pointer or 'the top level'} is not text")
        calls: tuple[ToolCall, ...] = ()
        if config.harness == "sdk":
            calls = self._target.harness_calls(self._session, answered)
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
