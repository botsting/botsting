"""The maintenance scripts in tools/: they must keep working, because each is run once and matters."""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name: str):
    spec = importlib.util.spec_from_file_location(f"tools_{name}", ROOT / "tools" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_signed_values_the_javascript_tests_hold_are_what_python_makes_today(capsys):
    """If this fails, the wire format changed: run `python tools/regenerate_js_fixtures.py`."""
    assert load("regenerate_js_fixtures").main(["--check"]) == 0, capsys.readouterr().out


@pytest.fixture
def rename():
    """The rename script, while there is still something for it to rename."""
    module = load("rename_project")
    if not (ROOT / ".git").exists() or not (ROOT / "src" / module.OLD).is_dir():
        pytest.skip("not a git checkout, or the project has already been renamed")
    return module


def test_the_rename_plan_covers_the_code_and_changes_nothing_without_apply(rename, capsys):
    before = (ROOT / "pyproject.toml").read_bytes()
    assert rename.main(["BotPentest"]) == 0
    printed = capsys.readouterr().out
    assert "BotPentest / botpentest / BOTPENTEST" in printed and "Nothing was changed" in printed
    contents, moves, _ = rename.plan(ROOT, "BotPentest")
    changed = {name for name, _ in contents}
    assert {"pyproject.toml", "README.md", "action.yml", "js/harness/package.json"} <= changed
    assert (f"src/{rename.OLD}/harness.py", "src/botpentest/harness.py") in moves
    assert "tools/rename_project.py" not in changed and "uv.lock" not in changed
    assert (ROOT / "pyproject.toml").read_bytes() == before


@pytest.mark.parametrize("name", ["bot pentest", "bot-pentest", "ab", "9lives", "current", "Current"])
def test_a_name_that_cannot_be_a_package_or_is_the_current_one_is_refused(rename, name, capsys):
    if name.lower() == "current":
        name = rename.OLD.capitalize() if name[0].isupper() else rename.OLD
    assert rename.main([name]) == 2
    assert "error:" in capsys.readouterr().out
