"""Success rates with an honest interval."""

from __future__ import annotations

import math

from promptproof.core.models import Rate

_Z95 = 1.959963984540054


def wilson_interval(successes: int, trials: int) -> tuple[float, float] | None:
    """Two-sided 95% Wilson score interval for a binomial proportion.

    Chosen over the normal approximation because it stays inside [0, 1] and behaves at
    0 of n and n of n, which are the common cases here. Returns None for zero trials.
    """
    if trials <= 0:
        return None
    if not 0 <= successes <= trials:
        raise ValueError(f"successes must be between 0 and trials, got {successes} of {trials}")
    p = successes / trials
    z2 = _Z95 * _Z95
    denominator = 1 + z2 / trials
    centre = (p + z2 / (2 * trials)) / denominator
    half = (_Z95 * math.sqrt(p * (1 - p) / trials + z2 / (4 * trials * trials))) / denominator
    low = 0.0 if successes == 0 else max(0.0, centre - half)
    high = 1.0 if successes == trials else min(1.0, centre + half)
    return (low, high)


def make_rate(successes: int, trials: int, errors: int = 0) -> Rate:
    """A Rate over the trials that completed. Errored trials are reported, not counted."""
    interval = wilson_interval(successes, trials)
    return Rate(
        successes=successes,
        trials=trials,
        errors=errors,
        interval_low=None if interval is None else interval[0],
        interval_high=None if interval is None else interval[1],
    )
