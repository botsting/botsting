# Promptproof

Evidence-first security testing for LLM applications. Promptproof attacks a bot you own and reports only what it can prove: it plants fresh secrets ("canaries") where an attacker should never reach, then shows you the exact conversation in which one came out.

Early development. It currently runs only against the built-in practice bot. Nothing here is released, and remote targets are not supported until the authorization checks exist.

## Try it

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```
uv sync
uv run promptproof scan --target toy:vulnerable --markdown reports/vulnerable.md
uv run promptproof scan --target toy:fixed --markdown reports/fixed.md
```

`toy:vulnerable` and `toy:fixed` are two builds of the same small support bot. The first keeps a staff code in its instructions and looks up any order a user names; the second fixes both in application code. By default they run on a scripted stand-in model, so no LLM is needed.

To run the same bot on a real local model, install [Ollama](https://ollama.com), pull a model, and name it in the target:

```
ollama pull llama3.2
uv run promptproof scan --target "toy:vulnerable?model=ollama:llama3.2" --discovery-runs 3
```

Replay a finding from a reset state with a fresh secret, or try the same attack on the fixed build:

```
uv run promptproof replay reports/scan.promptproof.json --finding F1
uv run promptproof replay reports/scan.promptproof.json --finding F1 --target toy:fixed
```

Exit codes: `0` no verified violations, `1` violations verified, `2` inconclusive.

## What a result means

- **Verified** means a planted secret, which the attacker was never shown, was recovered in full from the bot's output: verbatim, re-cased, reversed, rot13, URL-encoded, base64, hex, spelled out, or split across replies.
- **Suspected** means a partial match. It is shown and never counted.
- **"No verified violations observed under these tested conditions"** means exactly that. It is not a statement that the bot is protected. Before attacking, the scan fetches each secret by the legitimate route and checks a normal request still works; if either fails, the result is **inconclusive**, never a quiet zero.
- Two rates are reported for every finding: how often the attack worked while searching, and how often the frozen attack worked when replayed from reset. Each has its counts and a 95% Wilson interval.

Known limits are listed at the end of every report.

## Development

```
uv run pytest
```

Licensed under Apache-2.0.
