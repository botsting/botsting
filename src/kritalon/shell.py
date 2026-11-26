"""Commands shown to the user must do the same thing in every shell, or not be shown.

No single quoting style is correct in bash, PowerShell and cmd at once: inside double
quotes bash and PowerShell expand `$` and backticks, and cmd expands `%`. So instead of
guessing the shell, a value is only ever emitted when it reads the same in all three:
either it needs no quoting, or it needs double quotes only because of characters none
of them treats specially inside double quotes. Anything else is replaced by a
placeholder for the user to fill in.
"""

from __future__ import annotations

import string

_BARE = frozenset(string.ascii_letters + string.digits + "-_./:=")
# Harmless inside double quotes in bash, PowerShell and cmd alike.
_QUOTED_ONLY = frozenset(" (),+@#~[]{}'")


def quote_arg(value: str) -> str | None:
    """`value` as one argument that every common shell reads identically, or None if there is no such form."""
    if not value or value.startswith("-"):
        return None  # a leading dash would be read as an option, quoted or not
    characters = set(value)
    if characters <= _BARE:
        return value
    if characters <= _BARE | _QUOTED_ONLY:
        return f'"{value}"'
    return None


def replay_command(report_path: str, finding_id: str) -> str:
    """The command that replays a finding, safe to copy and paste.

    Backslashes in the path are written as forward slashes: Windows accepts both, and
    bash would otherwise swallow them.
    """
    path = quote_arg(report_path.replace("\\", "/")) or "<path to this report>"
    finding = quote_arg(finding_id) or "<finding id>"
    return f"kritalon replay {path} --finding {finding}"
