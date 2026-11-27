"""Attacks reused from openly licensed public collections.

Each source has its own folder under `collections/`:

    SOURCE.json     who published it, where, under which licence, and the commit that was read
    LICENSE         the source's licence text, as published
    attacks.jsonl   one attack per line

Nothing here is loaded unless it passes every check below, and a failed check stops the
whole load with the file and the line: a collection that is partly right is not used.

The rules
---------
- A source is used only under a licence that allows commercial reuse and redistribution
  (`ALLOWED_LICENCES`), with its licence text beside its attacks.
- An attack names the place in its source it was taken from, and says whether its text was
  kept as published, had our placeholder put where the source's own request stood, or was
  shortened.
- `{hint}` and `{goal}` are the only placeholders. They are replaced as plain text, so any
  other braces in a text are just braces.
- No text may repeat another one, here or among the built-in attacks.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date
from functools import lru_cache
from pathlib import Path

from botsting.core.models import Attack
from botsting.targets.base import Target, injection_points, tool_rules

ROOT = Path(__file__).parent / "collections"

# SPDX ids of licences that allow commercial reuse and redistribution with nothing more
# than keeping the notice. Anything else, including a missing licence, is refused.
ALLOWED_LICENCES = frozenset({"Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "CC-BY-4.0", "CC0-1.0", "ISC", "MIT", "Unlicense"})
KINDS = ("instruction_secret", "other_user_record", "action", "injection")
CHANGES = ("verbatim", "placeholder", "trimmed")
HINT = "{hint}"
GOAL = "{goal}"
MAX_TURNS = 25
MAX_TURN_LENGTH = 2000
MAX_TITLE_LENGTH = 80

_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_SOURCE_FIELDS = ("id", "name", "url", "licence", "licence_url", "commit", "retrieved", "data_origin")
_ENTRY_FIELDS = ("id", "kind", "technique", "title", "turns", "upstream", "changed")


class CollectionError(ValueError):
    """A collection that breaks one of the rules. The message names the file and, for an attack, the line."""


@dataclass(frozen=True)
class Source:
    id: str
    name: str
    url: str
    licence: str
    licence_url: str
    commit: str
    retrieved: str
    data_origin: str


@dataclass(frozen=True)
class Entry:
    id: str
    kind: str
    technique: str
    title: str
    turns: tuple[str, ...]
    source: str
    upstream: str
    changed: str


def _same_text(turns: Sequence[str]) -> str:
    """Texts that differ only in case, spacing or punctuation at the ends count as the same text."""
    return "\n".join(" ".join(turn.lower().split()).strip(" .!?:;,") for turn in turns)


def _line(text: object, where: str, name: str, limit: int | None = None) -> str:
    if not isinstance(text, str) or not text.strip():
        raise CollectionError(f"{where}: `{name}` must be text and may not be empty")
    if "\n" in text or "\r" in text:
        raise CollectionError(f"{where}: `{name}` must be one line")
    if limit is not None and len(text) > limit:
        raise CollectionError(f"{where}: `{name}` is longer than {limit} characters")
    return text


def _read_source(folder: Path) -> Source:
    where = f"{folder.name}/SOURCE.json"
    try:
        found = json.loads((folder / "SOURCE.json").read_text(encoding="utf-8"))
    except OSError as error:
        raise CollectionError(f"{where}: could not be read ({error.strerror or error})") from error
    except ValueError as error:
        raise CollectionError(f"{where}: is not JSON ({error})") from error
    if not isinstance(found, dict) or set(found) != set(_SOURCE_FIELDS):
        raise CollectionError(f"{where}: must hold exactly these fields: {', '.join(_SOURCE_FIELDS)}")
    fields = {name: _line(found[name], where, name) for name in _SOURCE_FIELDS}
    if fields["id"] != folder.name or not _ID.fullmatch(fields["id"]):
        raise CollectionError(f"{where}: `id` must be the folder's name, in lower-case letters, digits and hyphens")
    if fields["licence"] not in ALLOWED_LICENCES:
        raise CollectionError(
            f"{where}: licence `{fields['licence']}` is not one that allows commercial reuse and redistribution "
            f"({', '.join(sorted(ALLOWED_LICENCES))})"
        )
    for name in ("url", "licence_url"):
        if not fields[name].startswith("https://"):
            raise CollectionError(f"{where}: `{name}` must be an https address")
    try:
        date.fromisoformat(fields["retrieved"])
    except ValueError as error:
        raise CollectionError(f"{where}: `retrieved` must be a date written as YYYY-MM-DD") from error
    try:
        licence_text = (folder / "LICENSE").read_text(encoding="utf-8")
    except (OSError, ValueError) as error:
        raise CollectionError(f"{folder.name}/LICENSE: the source's licence text must be beside its attacks") from error
    if not licence_text.strip():
        raise CollectionError(f"{folder.name}/LICENSE: is empty")
    return Source(**fields)


def _read_entry(found: object, source: Source, where: str) -> Entry:
    if not isinstance(found, dict) or set(found) != set(_ENTRY_FIELDS):
        raise CollectionError(f"{where}: must hold exactly these fields: {', '.join(_ENTRY_FIELDS)}")
    entry_id = _line(found["id"], where, "id")
    if not entry_id.startswith(source.id + "-") or not _ID.fullmatch(entry_id):
        raise CollectionError(f"{where}: `id` must start with `{source.id}-` and use lower-case letters, digits and hyphens")
    if found["kind"] not in KINDS:
        raise CollectionError(f"{where}: `kind` must be one of {', '.join(KINDS)}")
    if found["changed"] not in CHANGES:
        raise CollectionError(f"{where}: `changed` must be one of {', '.join(CHANGES)}")
    turns = found["turns"]
    if not isinstance(turns, list) or not 1 <= len(turns) <= MAX_TURNS:
        raise CollectionError(f"{where}: `turns` must be a list of 1 to {MAX_TURNS} texts")
    for turn in turns:
        if not isinstance(turn, str) or not turn.strip():
            raise CollectionError(f"{where}: every turn must be text and may not be empty")
        if len(turn) > MAX_TURN_LENGTH:
            raise CollectionError(f"{where}: a turn is longer than {MAX_TURN_LENGTH} characters")
        if any(ord(char) < 32 and char not in "\n\t" for char in turn):
            raise CollectionError(f"{where}: a turn holds a control character")
    kind = found["kind"]
    has_hint = any(HINT in turn for turn in turns)
    has_goal = any(GOAL in turn for turn in turns)
    if kind == "injection":
        if len(turns) != 1 or not has_goal or has_hint:
            raise CollectionError(f"{where}: an injection is one text that holds {GOAL} and no {HINT}")
    else:
        if has_goal:
            raise CollectionError(f"{where}: only an injection may hold {GOAL}")
        if kind == "action" and not has_hint:
            raise CollectionError(f"{where}: an action attack must hold {HINT}, the thing it asks for")
    return Entry(
        id=entry_id,
        kind=kind,
        technique=_line(found["technique"], where, "technique", 40),
        title=_line(found["title"], where, "title", MAX_TITLE_LENGTH),
        turns=tuple(turns),
        source=source.id,
        upstream=_line(found["upstream"], where, "upstream"),
        changed=found["changed"],
    )


def _built_in_texts() -> dict[str, str]:
    from botsting.attacks import library

    groups = [*library._TEMPLATES.values(), library._ACTION_TEMPLATES, library._INJECTION_TEMPLATES]
    return {_same_text(template.turns): template.id for group in groups for template in group}


def load(root: Path = ROOT) -> tuple[tuple[Source, ...], tuple[Entry, ...]]:
    """Every source and every attack under `root`, or a `CollectionError` naming the first thing wrong."""
    sources: list[Source] = []
    entries: list[Entry] = []
    ids: set[str] = set()
    texts = _built_in_texts()
    if not root.is_dir():
        return (), ()
    for folder in sorted(path for path in root.iterdir() if path.is_dir() and not path.name.startswith((".", "_"))):
        source = _read_source(folder)
        sources.append(source)
        try:
            lines = (folder / "attacks.jsonl").read_text(encoding="utf-8").splitlines()
        except (OSError, ValueError) as error:
            raise CollectionError(f"{folder.name}/attacks.jsonl: could not be read") from error
        before = len(entries)
        for number, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            where = f"{folder.name}/attacks.jsonl line {number}"
            try:
                found = json.loads(line)
            except ValueError as error:
                raise CollectionError(f"{where}: is not JSON ({error})") from error
            entry = _read_entry(found, source, where)
            if entry.id in ids:
                raise CollectionError(f"{where}: the id `{entry.id}` is used twice")
            ids.add(entry.id)
            text = _same_text(entry.turns)
            if text in texts:
                raise CollectionError(f"{where}: the same text is already there as `{texts[text]}`")
            texts[text] = entry.id
            entries.append(entry)
        if len(entries) == before:
            raise CollectionError(f"{folder.name}/attacks.jsonl: holds no attack")
    return tuple(sources), tuple(entries)


@lru_cache(maxsize=1)
def shipped() -> tuple[tuple[Source, ...], tuple[Entry, ...]]:
    """The collections that come with BotSting, read and checked once."""
    return load(ROOT)


def collected_attacks(target: Target, root: Path | None = None) -> list[Attack]:
    """Every collected attack, aimed at each place on this target that its kind applies to."""
    _, entries = shipped() if root is None else load(root)
    slots = target.slots()
    rules = tool_rules(target)
    points = injection_points(target)
    attacks: list[Attack] = []
    for entry in entries:
        if entry.kind == "injection":
            attacks += [
                Attack(
                    id=f"{entry.id}:{point.id}",
                    technique=entry.technique,
                    title=entry.title,
                    slot_id=point.id,
                    kind="injection",
                    payload=entry.turns[0].replace(GOAL, point.goal),
                )
                for point in points
            ]
            continue
        aimed_at = rules if entry.kind == "action" else [slot for slot in slots if slot.kind == entry.kind]
        attacks += [
            Attack(
                id=f"{entry.id}:{place.id}",
                technique=entry.technique,
                title=entry.title,
                slot_id=place.id,
                turns=tuple(turn.replace(HINT, place.hint) for turn in entry.turns),
                kind="action" if entry.kind == "action" else "disclosure",
            )
            for place in aimed_at
        ]
    return attacks
