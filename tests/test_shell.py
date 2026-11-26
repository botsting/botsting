"""A command shown to the user must mean the same thing in bash, PowerShell and cmd, or not be shown."""

import shlex

import pytest

from kritalon.shell import quote_arg, replay_command

# Characters that some shell expands or interprets inside double quotes.
ACTIVE = set('$`%!"\\&|;<>^*?\n\r\t')


@pytest.mark.parametrize(
    "path",
    ["reports/scan.json", "C:/Users/me/scan.json", "my reports/scan (2).json", "it's here/scan.json"],
)
def test_ordinary_paths_round_trip(path):
    command = replay_command(path, "F1")
    assert command.count('"') in (0, 2), "at most one pair of wrapping quotes"
    assert not ACTIVE & set(command.replace('"', ""))
    assert shlex.split(command) == ["kritalon", "replay", path, "--finding", "F1"]


def test_windows_backslashes_become_forward_slashes():
    command = replay_command("reports\\scan.kritalon.json", "F2")
    assert command == "kritalon replay reports/scan.kritalon.json --finding F2"
    assert replay_command("C:\\My Files\\scan.json", "F2") == 'kritalon replay "C:/My Files/scan.json" --finding F2'


@pytest.mark.parametrize(
    "path",
    [
        "reports/$HOME/a.json",
        "reports/$(whoami).json",
        "reports/`id`.json",
        "reports/%USERPROFILE%/a.json",
        'reports/a".json',
        "reports/a;rm -rf.json",
        "reports/a|b.json",
        "reports/a&b.json",
        "reports/a\nb.json",
        "reports/!!.json",
        "",
    ],
)
def test_paths_no_shell_agrees_on_are_never_emitted(path):
    """Review 2, finding 4: double quotes do not stop $ or backticks from expanding."""
    command = replay_command(path, "F1")
    assert command == "kritalon replay <path to this report> --finding F1"
    assert quote_arg(path) is None


def test_hostile_finding_id_is_not_emitted():
    assert replay_command("r.json", "F1; echo x") == "kritalon replay r.json --finding <finding id>"
    assert replay_command("r.json", "--target") == "kritalon replay r.json --finding <finding id>"
