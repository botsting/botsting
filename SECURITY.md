# Security policy

BotSting sends hostile messages to bots and handles evidence about their weaknesses, so problems in BotSting itself matter.

## Reporting a problem in BotSting

Use GitHub's private vulnerability reporting on this repository ("Security" tab, "Report a vulnerability"). Please do not open a public issue for a security problem.

Include what you did, what happened, and what you expected. A failing test is the most useful report.

We aim to acknowledge a report within 3 working days and to tell you what we will do within 10. We will credit you in the release notes unless you ask us not to.

## What counts

- A way to make BotSting send anything to a target without a valid authorization, or to an address other than the one authorized.
- A way for a test message to be handled as an ordinary request by a bot that carries the drop-in harness.
- A way for a marked tool to run for real outside its caps, or without every switch described in the README.
- A reported finding that the evidence does not support, or a leak that the matcher misses in a form the documentation says it catches.
- A way to change a sealed evidence bundle without `check-seal` noticing.
- Anything that sends scan data, reports or credentials off the machine that runs the scan.

## What does not

- Findings about your own bot: those are what the tool is for.
- The built-in practice bots are vulnerable on purpose.
- That open-source checks can be removed by editing the code. They are on by default; they cannot bind someone who rewrites them.

## Using BotSting on systems you do not own

Do not. BotSting asks for a named person's authorization and proof of control of the address because testing someone else's system without permission is, in most places, against the law. See `docs/never-do.md`.
