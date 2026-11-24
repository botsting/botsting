"""The exit codes, in one place.

Every command exits 0 when it did what was asked and found nothing to act on. What
the other codes mean is each command's own; the table below is the whole list:

    scan, ci         0 no verified violations; 1 violations verified; 2 inconclusive,
                     a usage error, nothing was tested, or the evidence could not be
                     sealed (ci with --fail-on never still exits 0)
    replay           0 the finding was not reproduced; 1 it was reproduced; 2 inconclusive
    benchmark        0 passed; 1 a control was violated or the margin was not met; 2 usage error
    sterile-check    0 sterile; 1 a live action is present; 2 usage error
    check-seal       0 intact; 1 the bundle was changed or its outbound log cannot be relied on
    authorize        0 done; 2 could not
    init             0 wrote the description; 2 could not
    seal             0 sealed; 2 could not
    demo             0 done; 2 the --dir was not empty
    doctor           0 ready to scan; 2 not ready
    egress-trap      0 stopped cleanly; 2 could not start
    harness-key      0
    practice-server  0 (2 if it could not start)
    mcp serve        0

A script can therefore tell "found nothing" from "could not tell", and a broken
target can never be mistaken for a fixed one.
"""

# The scan verdicts, shared by `scan` (and the first scan behind it), `ci`, `replay`
# and `benchmark`.
EXIT_NO_VERIFIED = 0  # nothing was proven
EXIT_VIOLATIONS = 1  # violations were verified, a finding was reproduced, or a control failed
EXIT_INCONCLUSIVE = 2  # the scan could not tell, or could not run at all

# The other commands: what they return when they did their job and when they could not.
EXIT_OK = 0
EXIT_FAILED = 2

# A command whose 1 means the thing it checked failed the check.
EXIT_CHECK_FAILED = 1
