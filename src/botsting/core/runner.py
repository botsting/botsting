"""Run a scan: confirm the instruments work, search for attacks that work, then replay them.

The runner used to be one module; it is now split by job, and this module only gathers
the names the rest of the code imports from it, so nothing outside had to change:

- meter.py      ScanConfig and Meter: the limits a scan obeys, and waiting that stops;
                run_to_completion runs the whole thing without waiting on the abandoned.
- judge.py      _judge, _evaluate_transcript and the level and rate helpers.
- preflight.py  Preflight and the checks that exercise every instrument legitimately.
- scan.py       run_scan, discovery (static and adaptive) and finding assembly; run_attempt.
- replay.py     ReplayResult, replay and replay_finding.

The description of the order of work and of the three kinds of attack lives in scan.py.
"""

from __future__ import annotations

from botsting.core.judge import _judge, _rate_for
from botsting.core.meter import Meter, ScanConfig, run_to_completion
from botsting.core.preflight import _fresh, preflight
from botsting.core.replay import ReplayResult, attack_from, replay, replay_finding
from botsting.core.scan import identity_unknown, run_attempt, run_scan

__all__ = [
    "Meter",
    "ReplayResult",
    "ScanConfig",
    "_fresh",
    "_judge",
    "_rate_for",
    "attack_from",
    "identity_unknown",
    "preflight",
    "replay",
    "replay_finding",
    "run_attempt",
    "run_scan",
    "run_to_completion",
]
