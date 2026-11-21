"""Turn a target spec string into a target.

    toy:vulnerable                       scripted stand-in model, no LLM needed
    toy:fixed?model=ollama:llama3.2      a local model served by Ollama

Only local practice targets exist so far. Remote targets arrive together with the
authorization gate, not before it.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl

from promptproof.llm.base import ChatModel
from promptproof.llm.scripted import ScriptedModel
from promptproof.targets.base import Target
from promptproof.targets.toy import ToyTarget


class SpecError(ValueError):
    """The target spec could not be understood."""


def _build_model(name: str) -> ChatModel:
    if name == "scripted":
        return ScriptedModel()
    if name.startswith("ollama:") and len(name) > len("ollama:"):
        from promptproof.llm.ollama import OllamaModel

        return OllamaModel(model=name.removeprefix("ollama:"))
    raise SpecError(f"unknown model {name!r}; use 'scripted' or 'ollama:<model name>'")


_SPEC = re.compile(r"[A-Za-z0-9:._?=&-]+")


def build_target(spec: str) -> Target:
    # A spec is copied into reports and replay commands, so it is held to a plain
    # character set: no whitespace, quotes or markup can ride along in it.
    if not _SPEC.fullmatch(spec):
        raise SpecError("a target spec may contain only letters, digits and the characters : . _ ? = & -")
    head, _, query = spec.partition("?")
    kind, _, variant = head.partition(":")
    try:
        if "?" in spec and not query:
            raise ValueError("'?' must be followed by options such as model=scripted")
        options = dict(parse_qsl(query, strict_parsing=True)) if query else {}
    except ValueError as exc:
        raise SpecError(f"malformed options in target spec: {exc}") from exc
    unknown = set(options) - {"model"}
    if unknown:
        raise SpecError(f"unknown option(s) in target spec: {sorted(unknown)}")
    if kind != "toy":
        raise SpecError(f"unknown target kind {kind!r}; only 'toy' is available")
    if variant not in ("vulnerable", "fixed"):
        raise SpecError(f"unknown toy variant {variant!r}; use 'toy:vulnerable' or 'toy:fixed'")
    model = _build_model(options.get("model", "scripted"))
    return ToyTarget(variant=variant, model=model, spec=spec)  # type: ignore[arg-type]
