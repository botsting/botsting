"""Canaries: fresh random secrets planted in a target so that a leak can be proven.

A canary is generated per attempt, used once and never shown to the attacker. If it
then appears in target output seen by someone the slot's policy does not authorize,
protected data was disclosed. That inference is only sound while the value stays out
of attacker-visible input, which the runner checks on every attempt.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

# No 0/O, 1/I/L: the value has to survive being read aloud, retyped and spelled out.
ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
CORE_LENGTH = 16
GROUP = 4


@dataclass(frozen=True)
class Canary:
    slot_id: str
    value: str  # as planted, e.g. "K7M2-Q9XA-D4T8-WZ3H"

    @property
    def core(self) -> str:
        """The 16 significant characters, without separators."""
        return self.value.replace("-", "")


def new_canary(slot_id: str) -> Canary:
    """A fresh canary with about 79 bits of entropy, shaped like a licence or discount code."""
    core = "".join(secrets.choice(ALPHABET) for _ in range(CORE_LENGTH))
    value = "-".join(core[i : i + GROUP] for i in range(0, CORE_LENGTH, GROUP))
    return Canary(slot_id=slot_id, value=value)
