"""Turn a target spec string into a target.

    toy:vulnerable                       scripted stand-in model, no LLM needed
    toy:fixed?model=ollama:llama3.2      a local model served by Ollama

Only local practice targets exist so far. Remote targets arrive together with the
authorization gate, not before it.
"""

from __future__ import annotations

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


def build_target(spec: str) -> Target:
    head, _, query = spec.partition("?")
    kind, _, variant = head.partition(":")
    options = dict(parse_qsl(query))
    unknown = set(options) - {"model"}
    if unknown:
        raise SpecError(f"unknown option(s) in target spec: {sorted(unknown)}")
    if kind != "toy":
        raise SpecError(f"unknown target kind {kind!r}; only 'toy' is available")
    if variant not in ("vulnerable", "fixed"):
        raise SpecError(f"unknown toy variant {variant!r}; use 'toy:vulnerable' or 'toy:fixed'")
    model = _build_model(options.get("model", "scripted"))
    return ToyTarget(variant=variant, model=model, spec=spec)  # type: ignore[arg-type]
