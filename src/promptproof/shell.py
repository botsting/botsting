"""Commands shown to the user must work when copied and pasted."""

from __future__ import annotations


def quote_arg(value: str) -> str:
    """`value` as one command-line argument that survives common shells.

    Plain values are left alone. Anything with a space or another special character is
    wrapped in double quotes, which bash, PowerShell and cmd all accept.
    """
    if value and all(ch.isalnum() or ch in "-_./\\:=" for ch in value):
        return value
    return '"' + value.replace('"', '\\"') + '"'


def replay_command(report_path: str, finding_id: str) -> str:
    return f"promptproof replay {quote_arg(report_path)} --finding {quote_arg(finding_id)}"
