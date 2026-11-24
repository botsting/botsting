# What Promptproof never does

These are properties of the tool, enforced in code and covered by tests. Each line names where.

1. **It never sends anything to a bot without a named person's authorization** for that exact address, scope and period, and, across a network, a token served by the address itself. The check runs before every scan and replay and again during long ones. (`core/authorization.py`)
2. **It never follows a redirect or talks to any address other than the one authorized**, and there only to the paths in the description and the one path where the ownership token is served. (`targets/http.py`, `core/authorization.py`)
3. **It never runs against a bot with tools unless they are recorders**, declared by the owner and checked before any attack. (`targets/base.py`, preflight in `core/runner.py`)
4. **It never lets a test message be handled as an ordinary request** by a bot carrying the drop-in harness. A session that cannot be verified is refused before the bot's code runs. (`harness.py`)
5. **It never carries out a real action unless four things agree**: a cap in the bot's own code, a switch on the deployment, a request in the signed session, and a line in the authorization. A call outside a cap is recorded and not run. (`harness.py`, `core/authorization.py`)
6. **It never needs real personal data.** A finding is proven by a fake secret made for that attempt. (`core/canary.py`, `core/matcher.py`)
7. **It never reports an opinion as a finding.** A finding is a planted secret recovered in full, or a tool call recorded at the tool. Partial matches are shown as suspected and never counted. (`core/matcher.py`, `core/runner.py`)
8. **It never calls a scan clean when it could not have seen a failure.** If the planted secret cannot be fetched by its legitimate route, or normal use is broken, the result is inconclusive. (`core/runner.py`)
9. **It never keeps going past its limits.** Messages, tool calls and time are capped, and Ctrl+C stops it. (`core/runner.py`)
10. **It never sends your reports, transcripts or credentials anywhere.** The open-source tool runs on your machine or your build runner and makes no connection except to the bot you named and the model you chose. A test runs the demo with every outbound connection watched and fails if one leaves the machine. Credentials are read from the environment and never written to a report. (`targets/http.py`)
11. **It never writes an authorization for you through an assistant.** The assistant integration can read whether one exists; only a person at a terminal can create one. (`mcp_server.py`)

## What we ask you never to do with it

- Test a system you do not own or have written permission to test.
- Test a hosted platform whose terms forbid security testing without that platform's written consent.
- Run attacks that change what other people see (shared memory, a knowledge base, public posts) against a real system. Use a copy.
- Point it at a production system at level 3 (real actions) before you have read the caps in your own code.

## What Promptproof cannot promise

That a bot with no findings is safe, that every tool in your code was marked, or that your own harness code tells the truth. Each report states its limits.
