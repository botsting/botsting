"""Turn a target spec string into a target.

    toy:vulnerable                       scripted stand-in model, no LLM needed
    toy:hardened?model=ollama:llama3.2   prompt-hardened Acorn bot on a local Ollama model
    toy:fixed?model=ollama:llama3.2      application-code-fixed Acorn bot on Ollama
    hardened:keyword                     held-out keyword-filtered hardened target
    hardened:keyword-fixed               application-code-fixed control for hardened:keyword
    hardened:multiturn                   held-out multi-turn intake hardened target
    hardened:multiturn-fixed             application-code-fixed control for hardened:multiturn

Only local practice targets exist so far. Remote targets arrive together with the
authorization gate, not before it.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl

from botsting.llm.base import ChatModel
from botsting.llm.scripted import ScriptedModel
from botsting.targets.base import Target
from botsting.targets.hardened import KeywordHardenedTarget, MultiTurnHardenedTarget
from botsting.targets.toy import ToyTarget


class SpecError(ValueError):
    """The target spec could not be understood."""


def build_model(name: str) -> ChatModel:
    if name == "scripted":
        return ScriptedModel()
    if name == "scripted-attacker":
        from botsting.attacks.adaptive import ScriptedAttackerModel

        return ScriptedAttackerModel()
    if name.startswith("ollama:") and len(name) > len("ollama:"):
        from botsting.llm.ollama import OllamaModel

        return OllamaModel(model=name.removeprefix("ollama:"))
    raise SpecError(f"unknown model {name!r}; use 'scripted', 'scripted-attacker', or 'ollama:<model name>'")


_SPEC = re.compile(r"[A-Za-z0-9:._?=&-]+")


def build_target(spec: str) -> Target:
    # A spec is copied into reports and replay commands, so it is held to a plain
    # character set: no whitespace, quotes or markup can ride along in it.
    if not _SPEC.fullmatch(spec):
        raise SpecError("a target spec may contain only letters, digits and the characters : . _ ? = & -")
    head, _, query = spec.partition("?")
    kind, _, variant = head.partition(":")
    if kind == "http":
        # A bot reached over HTTP, described by name in botsting.targets.json.
        if query or "?" in spec:
            raise SpecError("http targets take no options; put settings in the targets file")
        from botsting.targets.http import TargetConfigError, build_http_target

        try:
            return build_http_target(variant, spec)
        except TargetConfigError as exc:
            raise SpecError(str(exc)) from exc
    try:
        if "?" in spec and not query:
            raise ValueError("'?' must be followed by options such as model=scripted")
        options = dict(parse_qsl(query, strict_parsing=True)) if query else {}
    except ValueError as exc:
        raise SpecError(f"malformed options in target spec: {exc}") from exc
    unknown = set(options) - {"model"}
    if unknown:
        raise SpecError(f"unknown option(s) in target spec: {sorted(unknown)}")
    if kind == "toy":
        if variant not in ("vulnerable", "hardened", "fixed"):
            raise SpecError(
                f"unknown toy variant {variant!r}; use 'toy:vulnerable', 'toy:hardened' or 'toy:fixed'"
            )
        model = build_model(options.get("model", "scripted"))
        return ToyTarget(variant=variant, model=model, spec=spec)  # type: ignore[arg-type]
    if kind == "hardened":
        if options:
            raise SpecError(f"hardened targets do not take options: {sorted(options)}")
        if variant == "keyword":
            return KeywordHardenedTarget(variant="hardened", spec=spec)
        if variant == "keyword-fixed":
            return KeywordHardenedTarget(variant="fixed", spec=spec)
        if variant == "multiturn":
            return MultiTurnHardenedTarget(variant="hardened", spec=spec)
        if variant == "multiturn-fixed":
            return MultiTurnHardenedTarget(variant="fixed", spec=spec)
        raise SpecError(
            f"unknown hardened variant {variant!r}; use 'hardened:keyword', 'hardened:keyword-fixed', "
            "'hardened:multiturn' or 'hardened:multiturn-fixed'"
        )
    raise SpecError(f"unknown target kind {kind!r}; use 'toy', 'hardened' or 'http'")
