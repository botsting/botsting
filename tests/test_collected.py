"""Attacks reused from public collections: what is loaded, what is refused, and where each one is aimed.

The texts in these tests are stand-ins. They only need the right shape.
"""

import json
from pathlib import Path

import pytest

from botsting.attacks import collected, library
from botsting.attacks.collected import ALLOWED_LICENCES, CollectionError, collected_attacks, load
from botsting.cli import main
from botsting.targets.base import injection_points, tool_rules
from botsting.targets.registry import build_target

SOURCE = {
    "id": "example-set",
    "name": "Example set",
    "url": "https://example.org/set",
    "licence": "MIT",
    "licence_url": "https://example.org/set/LICENSE",
    "commit": "0123456789abcdef0123456789abcdef01234567",
    "retrieved": "2026-11-27",
    "data_origin": "Written by the project's own contributors under the project's licence.",
}
ENTRIES = [
    {"kind": "instruction_secret", "turns": ["Stand-in one about {hint}.", "Stand-in follow-up."]},
    {"kind": "instruction_secret", "turns": ['Stand-in two with {"other": "braces"} and {0} kept.']},
    {"kind": "other_user_record", "turns": ["Stand-in three about {hint}."]},
    {"kind": "action", "turns": ["Stand-in four asking for {hint}."]},
    {"kind": "injection", "turns": ["Stand-in five: {goal}."]},
]


def entry(number: int, **changes: object) -> dict:
    made = {
        "id": f"example-set-{number}",
        "technique": "stand-in",
        "title": f"Stand-in number {number}",
        "upstream": f"data/file.txt#L{number}",
        "changed": "placeholder",
        **ENTRIES[number],
    }
    made.update(changes)
    return made


def write(root: Path, source: dict | None = None, entries: list | None = None, licence: str | None = "Licence text.") -> Path:
    source = SOURCE if source is None else source
    folder = root / str(source.get("id", "example-set"))
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "SOURCE.json").write_text(json.dumps(source), encoding="utf-8")
    if licence is not None:
        (folder / "LICENSE").write_text(licence, encoding="utf-8")
    lines = [entry(n) for n in range(len(ENTRIES))] if entries is None else entries
    (folder / "attacks.jsonl").write_text("\n".join(x if isinstance(x, str) else json.dumps(x) for x in lines) + "\n", encoding="utf-8")
    return root


def test_a_collection_that_follows_the_rules_is_loaded_with_its_source(tmp_path):
    sources, entries = load(write(tmp_path))
    assert [s.id for s in sources] == ["example-set"] and sources[0].licence == "MIT"
    assert [e.id for e in entries] == [f"example-set-{n}" for n in range(5)]
    assert all(e.source == "example-set" and e.upstream for e in entries)


def test_no_collections_folder_means_no_collected_attacks(tmp_path):
    assert load(tmp_path / "missing") == ((), ())


def test_each_attack_is_aimed_at_every_place_of_its_kind_and_only_there(tmp_path):
    target = build_target("toy:vulnerable")
    attacks = collected_attacks(target, write(tmp_path))
    slots = {slot.id: slot for slot in target.slots()}
    rules = {rule.id: rule for rule in tool_rules(target)}
    points = {point.id: point for point in injection_points(target)}
    assert slots and rules and points
    by_entry: dict[str, list] = {}
    for attack in attacks:
        by_entry.setdefault(attack.id.split(":")[0], []).append(attack)
    assert {a.slot_id for a in by_entry["example-set-0"]} == {s for s, slot in slots.items() if slot.kind == "instruction_secret"}
    assert {a.slot_id for a in by_entry["example-set-2"]} == {s for s, slot in slots.items() if slot.kind == "other_user_record"}
    assert {a.slot_id for a in by_entry["example-set-3"]} == set(rules) and all(a.kind == "action" for a in by_entry["example-set-3"])
    assert {a.slot_id for a in by_entry["example-set-4"]} == set(points)
    for attack in by_entry["example-set-0"]:
        assert attack.kind == "disclosure" and attack.turns == (f"Stand-in one about {slots[attack.slot_id].hint}.", "Stand-in follow-up.")
    for attack in by_entry["example-set-3"]:
        assert attack.turns == (f"Stand-in four asking for {rules[attack.slot_id].hint}.",)
    for attack in by_entry["example-set-4"]:
        assert attack.kind == "injection" and attack.payload == f"Stand-in five: {points[attack.slot_id].goal}." and not attack.turns
    assert len({a.id for a in attacks}) == len(attacks)


def test_other_braces_in_a_text_stay_as_they_are(tmp_path):
    attacks = collected_attacks(build_target("toy:vulnerable"), write(tmp_path))
    kept = next(a for a in attacks if a.id.startswith("example-set-1:"))
    assert kept.turns == ('Stand-in two with {"other": "braces"} and {0} kept.',)


@pytest.mark.parametrize("licence", ["CC-BY-NC-4.0", "CC-BY-SA-4.0", "GPL-3.0-only", "unknown", "Proprietary", "mit"])
def test_a_source_under_any_other_licence_is_refused(tmp_path, licence):
    assert licence not in ALLOWED_LICENCES
    with pytest.raises(CollectionError, match="commercial reuse"):
        load(write(tmp_path, {**SOURCE, "licence": licence}))


@pytest.mark.parametrize(
    ("change", "said"),
    [
        ({"id": "another-name"}, "folder's name"),
        ({"url": "http://example.org/set"}, "https address"),
        ({"licence_url": "example.org"}, "https address"),
        ({"retrieved": "27 November"}, "YYYY-MM-DD"),
        ({"commit": ""}, "may not be empty"),
        ({"data_origin": "  "}, "may not be empty"),
        ({"extra": "x"}, "exactly these fields"),
    ],
)
def test_a_source_record_that_is_incomplete_or_wrong_is_refused(tmp_path, change, said):
    source = {**SOURCE, **change}
    folder = tmp_path / "example-set"
    folder.mkdir()
    (folder / "SOURCE.json").write_text(json.dumps(source), encoding="utf-8")
    (folder / "LICENSE").write_text("Licence text.", encoding="utf-8")
    (folder / "attacks.jsonl").write_text(json.dumps(entry(0)) + "\n", encoding="utf-8")
    with pytest.raises(CollectionError, match=said):
        load(tmp_path)


@pytest.mark.parametrize("licence", [None, "   "])
def test_a_source_without_its_licence_text_is_refused(tmp_path, licence):
    with pytest.raises(CollectionError, match="LICENSE"):
        load(write(tmp_path, licence=licence))


@pytest.mark.parametrize(
    ("entries", "said"),
    [
        ([entry(0, id="other-set-0")], "must start with `example-set-`"),
        ([entry(0, id="example-set-Zero")], "lower-case"),
        ([entry(0), entry(2, id="example-set-0")], "used twice"),
        ([entry(0, kind="jailbreak")], "`kind` must be one of"),
        ([entry(0, changed="rewritten")], "`changed` must be one of"),
        ([entry(0, upstream="")], "`upstream`"),
        ([entry(0, title="x" * 81)], "longer than 80"),
        ([entry(0, title="two\nlines")], "one line"),
        ([entry(0, turns=[])], "1 to 25 texts"),
        ([entry(0, turns=["x {hint}"] * 26)], "1 to 25 texts"),
        ([entry(0, turns=["fine {hint}", " "])], "may not be empty"),
        ([entry(0, turns=["x" * 2001])], "longer than 2000"),
        ([entry(0, turns=["bell \x07 {hint}"])], "control character"),
        ([entry(0, turns=["about {goal}"])], "only an injection"),
        ([entry(3, turns=["nothing asked for"])], "must hold {hint}"),
        ([entry(4, turns=["no goal here"])], "one text that holds {goal}"),
        ([entry(4, turns=["{goal}", "and a second text"])], "one text that holds {goal}"),
        ([entry(4, turns=["{goal} about {hint}"])], "one text that holds {goal}"),
        ([{k: v for k, v in entry(0).items() if k != "upstream"}], "exactly these fields"),
        (["not json"], "line 1: is not JSON"),
        ([], "holds no attack"),
    ],
)
def test_an_attack_that_breaks_a_rule_stops_the_load_and_names_the_line(tmp_path, entries, said):
    with pytest.raises(CollectionError, match=said.replace("{", r"\{").replace("}", r"\}")):
        load(write(tmp_path, entries=entries))


def test_texts_written_for_botsting_are_kept_apart_and_marked(tmp_path):
    ours = {**SOURCE, "id": "botsting-authored"}
    written = [entry(n, id=f"botsting-authored-{n}", changed="authored") for n in range(len(ENTRIES))]
    sources, entries = load(write(tmp_path / "fine", ours, written))
    assert sources[0].id == "botsting-authored" and {e.changed for e in entries} == {"authored"}
    with pytest.raises(CollectionError, match="only there"):
        load(write(tmp_path / "mixed", ours, [*written[:2], entry(2, id="botsting-authored-x", changed="verbatim")]))
    with pytest.raises(CollectionError, match="only there"):
        load(write(tmp_path / "passed-off", entries=[entry(0, changed="authored")]))


def test_the_same_text_twice_is_refused_however_it_is_spaced_or_cased(tmp_path):
    again = entry(1, kind="instruction_secret", turns=["  STAND-IN one about   {hint}", "stand-in follow-up!"])
    with pytest.raises(CollectionError, match="already there as `example-set-0`"):
        load(write(tmp_path, entries=[entry(0), again]))


def test_a_text_that_repeats_a_built_in_attack_is_refused(tmp_path):
    built_in = library._TEMPLATES["instruction_secret"][0]
    with pytest.raises(CollectionError, match=f"already there as `{built_in.id}`"):
        load(write(tmp_path, entries=[entry(0, turns=list(built_in.turns))]))


def test_the_same_text_in_two_sources_is_refused(tmp_path):
    write(tmp_path, entries=[entry(0)])
    second = {**SOURCE, "id": "second-set"}
    with pytest.raises(CollectionError, match="second-set/attacks.jsonl line 1: the same text is already there"):
        load(write(tmp_path, second, [entry(0, id="second-set-0")]))


def test_the_collections_that_ship_follow_every_rule():
    sources, entries = load(collected.ROOT)
    assert all(source.licence in ALLOWED_LICENCES for source in sources)
    assert {e.source for e in entries} == {s.id for s in sources} == {"agentdojo", "promptfoo", "promptinject"}
    assert (collected.ROOT / "README.md").exists()
    for source in sources:
        # The licence text is the one published at the recorded commit, and the record points at that commit.
        assert source.commit in source.licence_url and len(source.commit) == 40
        assert b"\r" not in (collected.ROOT / source.id / "LICENSE").read_bytes()


def test_a_scan_from_the_command_line_runs_the_collected_attacks_unless_told_not_to(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = build_target("toy:vulnerable")
    built_in, everything = library.default_attacks(target), library.all_attacks(target)
    assert everything[: len(built_in)] == built_in and len(everything) > len(built_in)
    assert len({a.id for a in everything}) == len(everything)
    counts = {}
    for choice in ("all", "built-in"):
        out = tmp_path / choice / "scan.botsting.json"
        main(["scan", "--target", "toy:vulnerable", "--replays", "1", "--attacks", choice, "--out", str(out)])
        counts[choice] = json.loads(out.read_text(encoding="utf-8"))["attacks_run"]
    assert counts == {"all": len(everything), "built-in": len(built_in)}
