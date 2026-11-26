"""Sealed evidence bundles: any change after sealing is caught."""

import json
import zipfile

import pytest

from kritalon.cli import main
from kritalon.seal import MANIFEST, SealError, check, seal, seal_of


@pytest.fixture
def run_dir(tmp_path):
    run = tmp_path / "run"
    (run / "transcripts").mkdir(parents=True)
    (run / "report.md").write_text("No verified violations observed.", encoding="utf-8")
    (run / "transcripts" / "a1.json").write_text('{"turns": []}', encoding="utf-8")
    (run / "egress-trap.jsonl").write_text(
        '{"at": "t", "method": "CONNECT", "target": "api.anthropic.com:443", "allowed": "true"}\n'
        '{"at": "t", "method": "CONNECT", "target": "api.anthropic.com:443", "allowed": "true"}\n'
        '{"at": "t", "method": "POST", "target": "http://hooks.example.com/x"}\n',
        encoding="utf-8",
    )
    return run


def rewrite(bundle, change):
    """Rebuild the zip with change(name, data) -> data or None (drop), as a tamperer would."""
    with zipfile.ZipFile(bundle) as old:
        items = [(i.filename, old.read(i.filename)) for i in old.infolist()]
    with zipfile.ZipFile(bundle, "w") as new:
        for name, data in items:
            result = change(name, data)
            if result is not None:
                new.writestr(name, result)
    return bundle


def test_a_fresh_bundle_checks_and_summarizes_egress(run_dir, tmp_path):
    out = tmp_path / "bundle.zip"
    value = seal(run_dir, out)
    manifest = check(out, value)
    assert manifest["seal"] == value and len(manifest["files"]) == 3
    assert manifest["egress"]["allowed"] == {"api.anthropic.com:443": 2}
    assert manifest["egress"]["refused"] == {"http://hooks.example.com/x": 1}
    assert {f["path"] for f in manifest["files"]} == {"report.md", "transcripts/a1.json", "egress-trap.jsonl"}


def test_the_seal_does_not_depend_on_when_it_was_made(run_dir, tmp_path):
    assert seal(run_dir, tmp_path / "one.zip") == seal(run_dir, tmp_path / "two.zip")


def test_a_changed_file_is_caught(run_dir, tmp_path):
    out = tmp_path / "bundle.zip"
    value = seal(run_dir, out)
    rewrite(out, lambda n, d: b"Verified violations: none at all!" if n == "report.md" else d)
    with pytest.raises(SealError, match="report.md was changed"):
        check(out, value)


def test_a_changed_file_with_a_fixed_up_manifest_is_caught_by_the_seal(run_dir, tmp_path):
    import hashlib

    out = tmp_path / "bundle.zip"
    value = seal(run_dir, out)
    forged = b"edited"

    def change(name, data):
        if name == "report.md":
            return forged
        if name == MANIFEST:
            manifest = json.loads(data)
            for item in manifest["files"]:
                if item["path"] == "report.md":
                    item["sha256"], item["bytes"] = hashlib.sha256(forged).hexdigest(), len(forged)
            return json.dumps(manifest).encode()
        return data

    rewrite(out, change)
    with pytest.raises(SealError, match="manifest was changed"):
        check(out)
    # Even a forger who also recomputes the seal is caught by the seal shared separately.
    def reseal(name, data):
        if name != MANIFEST:
            return data
        manifest = json.loads(data)
        manifest["seal"] = seal_of(manifest["files"], manifest["egress"])
        return json.dumps(manifest).encode()

    rewrite(out, reseal)
    check(out)  # self-consistent now
    with pytest.raises(SealError, match="not the one you were given"):
        check(out, value)


def test_removed_or_added_files_are_caught(run_dir, tmp_path):
    out = tmp_path / "bundle.zip"
    value = seal(run_dir, out)
    rewrite(out, lambda n, d: None if n == "egress-trap.jsonl" else d)
    with pytest.raises(SealError, match="missing"):
        check(out, value)
    out2 = tmp_path / "bundle2.zip"
    value2 = seal(run_dir, out2)
    with zipfile.ZipFile(out2, "a") as bundle:
        bundle.writestr("extra.txt", "planted later")
    with pytest.raises(SealError, match="extra"):
        check(out2, value2)


def test_an_edited_egress_log_is_caught(run_dir, tmp_path):
    out = tmp_path / "bundle.zip"
    value = seal(run_dir, out)
    rewrite(out, lambda n, d: d.splitlines(keepends=True)[0] if n == "egress-trap.jsonl" else d)
    with pytest.raises(SealError):
        check(out, value)


def test_bad_inputs_are_refused(run_dir, tmp_path):
    with pytest.raises(SealError, match="outside the run directory"):
        seal(run_dir, run_dir / "self.zip")
    with pytest.raises(SealError, match="no files"):
        (tmp_path / "empty").mkdir()
        seal(tmp_path / "empty", tmp_path / "e.zip")
    with pytest.raises(SealError, match="not a directory"):
        seal(tmp_path / "missing", tmp_path / "m.zip")
    (tmp_path / "junk.zip").write_bytes(b"not a zip")
    with pytest.raises(SealError, match="not a readable bundle"):
        check(tmp_path / "junk.zip")


def test_unsafe_manifest_paths_are_refused(run_dir, tmp_path):
    out = tmp_path / "bundle.zip"
    seal(run_dir, out)

    def change(name, data):
        if name != MANIFEST:
            return data
        manifest = json.loads(data)
        manifest["files"][0]["path"] = "../outside.txt"
        return json.dumps(manifest).encode()

    rewrite(out, change)
    with pytest.raises(SealError, match="unsafe path"):
        check(out)


def test_the_command_line(run_dir, tmp_path, capsys):
    out = tmp_path / "bundle.zip"
    assert main(["seal", str(run_dir), "--out", str(out)]) == 0
    value = next(line for line in capsys.readouterr().out.splitlines() if line.startswith("Seal: "))[6:]
    assert main(["check-seal", str(out), "--seal", value]) == 0
    printed = capsys.readouterr().out
    assert "Intact: 3 files" in printed and "api.anthropic.com:443 (2)" in printed and "hooks.example.com" in printed
    assert main(["check-seal", str(out), "--seal", "0" * 64]) == 1
    assert main(["seal", str(tmp_path / "missing")]) == 2
