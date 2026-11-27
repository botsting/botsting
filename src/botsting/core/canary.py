"""Canaries: fresh random secrets planted in a target so that a leak can be proven.

A canary is generated per attempt, used once and never shown to the attacker. If it
then appears in target output seen by someone the slot's policy does not authorize,
protected data was disclosed. That inference is only sound while the value stays out
of attacker-visible input, which the runner checks on every attempt.

Two styles, chosen per slot:

code   K7M2-Q9XA-D4T8-WZ3H. Looks like a discount code, licence key or password. Right
       for secrets that really are codes. About 79 bits.
name   Velomar Tisandu Korapek. Three invented, pronounceable words. Right for personal
       details (a nickname, a pet's name, a private note): a careful assistant treats a
       code-shaped value as a password and declines to repeat it even to its owner, which
       makes the legitimate route fail and the slot untestable. About 66 bits.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

# No 0/O, 1/I/L: the value has to survive being read aloud, retyped and spelled out.
ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
CORE_LENGTH = 16
GROUP = 4

STYLES = ("code", "name")
_CONSONANTS = "bdfgklmnprstvz"
_VOWELS = "aeiou"
NAME_WORDS = 3
NAME_WORD_SHAPE = "cvcvcvc"  # consonant-vowel pattern of each word; 7 letters


@dataclass(frozen=True)
class Canary:
    slot_id: str
    value: str  # as planted, e.g. "K7M2-Q9XA-D4T8-WZ3H" or "Velomar Tisandu Korapek"
    style: str = "code"

    @property
    def core(self) -> str:
        """The significant characters, upper-case, without separators: what the matcher looks for."""
        return "".join(ch for ch in self.value.upper() if ch.isalnum())


def _word() -> str:
    letters = [secrets.choice(_CONSONANTS if kind == "c" else _VOWELS) for kind in NAME_WORD_SHAPE]
    return "".join(letters).capitalize()


def new_canary(slot_id: str, style: str = "code") -> Canary:
    """A fresh canary in the given style."""
    if style == "code":
        core = "".join(secrets.choice(ALPHABET) for _ in range(CORE_LENGTH))
        value = "-".join(core[i : i + GROUP] for i in range(0, CORE_LENGTH, GROUP))
    elif style == "name":
        value = " ".join(_word() for _ in range(NAME_WORDS))
    else:
        raise ValueError(f"canary style must be one of {', '.join(STYLES)}, got {style!r}")
    return Canary(slot_id=slot_id, value=value, style=style)


def space_size(style: str) -> int:
    """How many different canaries a style can produce: the denominator of every chance-match bound."""
    if style == "code":
        return len(ALPHABET) ** CORE_LENGTH
    if style == "name":
        per_word = 1
        for kind in NAME_WORD_SHAPE:
            per_word *= len(_CONSONANTS) if kind == "c" else len(_VOWELS)
        return per_word**NAME_WORDS
    raise ValueError(style)


def pass_phrase() -> str:
    """Three invented words, for a control route: not a phrase anyone would type by chance."""
    return " ".join(
        "".join(secrets.choice(_CONSONANTS if i % 2 == 0 else _VOWELS) for i in range(6)) for _ in range(3)
    )
