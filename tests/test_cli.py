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
    assert (
        "14 verified violation(s): 11 protected data disclosed, 3 forbidden action(s) carried out, "
        "0 forbidden action(s) attempted and refused by the tool."
    ) in printed
    assert f"promptproof replay {out.as_posix()} --finding F1" in printed

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


class _SaysNo:
    """A target that refuses everything, including legitimate use: broken, not fixed."""

    spec = "toy:fixed"
    attacker_principal = "customer:alice"
    tool_safety = "no-tools"
    reach = "in-process"

    def __init__(self, real) -> None:
        self._real = real

    async def describe(self):
        return await self._real.describe()

    def slots(self):
        return self._real.slots()

    def task_checks(self):
        return self._real.task_checks()

    async def reset(self, fixtures) -> None:
        return None

    async def open_session(self, principal):
        return self

    async def send(self, text: str) -> str:
        return "no"


def test_replay_against_a_broken_target_is_inconclusive_not_a_pass(tmp_path, capsys, monkeypatch):
    """Review finding 2: this used to exit 0, so a script checking a fix would accept a dead bot."""
    import promptproof.cli as cli

    out = tmp_path / "scan.json"
    main(["scan", "--target", "toy:vulnerable", "--out", str(out), "--replays", "1"])
    capsys.readouterr()
    real_build = cli.build_target
    monkeypatch.setattr(cli, "build_target", lambda spec: _SaysNo(real_build("toy:fixed")))
    assert main(["replay", str(out), "--finding", "F1", "--trials", "2"]) == EXIT_INCONCLUSIVE
    printed = capsys.readouterr().out
    assert "0 of 2 replays" in printed
    assert "cannot be relied on" in printed and "unreachable" in printed


def test_replay_notes_a_changed_configuration(tmp_path, capsys):
    out = tmp_path / "scan.json"
    main(["scan", "--target", "toy:vulnerable", "--out", str(out), "--replays", "1"])
    capsys.readouterr()
    main(["replay", str(out), "--finding", "F1", "--trials", "1"])
    assert "not the configuration that was scanned" not in capsys.readouterr().out
    main(["replay", str(out), "--finding", "F1", "--trials", "1", "--target", "toy:fixed"])
    printed = capsys.readouterr().out
    assert "not the configuration that was scanned. Changed: build." in printed
    assert "still works by its legitimate route" in printed


def test_replay_command_is_quoted_when_the_path_needs_it(tmp_path, capsys):
    out = tmp_path / "my reports" / "scan.json"
    main(["scan", "--target", "toy:vulnerable", "--out", str(out), "--replays", "1"])
    assert f'promptproof replay "{out.as_posix()}" --finding F1' in capsys.readouterr().out


def test_hostile_target_specs_are_rejected(tmp_path, capsys):
    for spec in ["toy:fixed?\n\n![x](https://invalid.example/p)", "toy:fixed?", "toy:fixed?model", "toy:fixed `x`", ""]:
        assert main(["scan", "--target", spec, "--out", str(tmp_path / "x.json")]) == EXIT_INCONCLUSIVE, repr(spec)
    assert not (tmp_path / "x.json").exists()
