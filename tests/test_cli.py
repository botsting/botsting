import json

import pytest

from promptproof import __version__
from promptproof.cli import EXIT_INCONCLUSIVE, EXIT_NO_VERIFIED, EXIT_VIOLATIONS, NO_VERIFIED_HEADLINE, main


def test_version(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"promptproof {__version__}"


def test_scan_vulnerable_then_replay(tmp_path, capsys):
    out = tmp_path / "nested" / "scan.json"
    assert main(["scan", "--target", "toy:vulnerable", "--out", str(out), "--replays", "2"]) == EXIT_VIOLATIONS
    printed = capsys.readouterr().out
    assert "11 verified violation(s)." in printed
    assert f"promptproof replay {out} --finding F1" in printed

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["status"] == "violations_verified"
    assert data["findings"][0]["level"] == 1
    assert data["findings"][0]["level_label"] == "Protected data disclosed"

    assert main(["replay", str(out), "--finding", "F1", "--trials", "3"]) == EXIT_VIOLATIONS
    assert "3 of 3 replays" in capsys.readouterr().out
    # The same frozen attack against the fixed build does nothing.
    assert main(["replay", str(out), "--finding", "F1", "--trials", "3", "--target", "toy:fixed"]) == EXIT_NO_VERIFIED
    assert "0 of 3 replays" in capsys.readouterr().out


def test_scan_fixed_uses_the_careful_wording(tmp_path, capsys):
    out = tmp_path / "scan.json"
    assert main(["scan", "--target", "toy:fixed", "--out", str(out)]) == EXIT_NO_VERIFIED
    printed = capsys.readouterr().out
    assert printed.splitlines()[0] == NO_VERIFIED_HEADLINE
    for word in ("safe", "secure", "clean", "certified", "passed"):
        assert word not in printed.lower()


def test_usage_errors(tmp_path, capsys):
    assert main(["scan", "--target", "http://example.com", "--out", str(tmp_path / "x.json")]) == EXIT_INCONCLUSIVE
    assert main(["scan", "--target", "toy:fixed", "--out", str(tmp_path / "x.json"), "--replays", "0"]) == EXIT_INCONCLUSIVE
    assert not (tmp_path / "x.json").exists()
    assert main(["replay", str(tmp_path / "missing.json"), "--finding", "F1"]) == EXIT_INCONCLUSIVE

    out = tmp_path / "scan.json"
    main(["scan", "--target", "toy:fixed", "--out", str(out)])
    assert main(["replay", str(out), "--finding", "F1"]) == EXIT_INCONCLUSIVE
    assert "no finding 'F1'" in capsys.readouterr().err
