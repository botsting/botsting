# Attacks reused from public collections

One folder per source. Each folder holds three files:

| File | What it is |
|---|---|
| `SOURCE.json` | The source's name and address, its licence (SPDX id) and the licence's address, the commit that was read, the date, and one sentence on where its texts come from. |
| `LICENSE` | The source's licence text, as published. |
| `attacks.jsonl` | One attack per line, each naming the place in the source it was taken from. |

A source is used only if its licence allows commercial reuse and redistribution. A source with a
non-commercial licence, an unclear licence or no licence is not used.

The texts are kept as published, apart from three kinds of change, which each attack records: our
placeholder (`{hint}` or `{goal}`) put where the source's own request stood, shortening, and a
source's own blanks (a user's name, a model's name) filled with that source's own default values.

Texts written for BotSting itself are kept apart, in a folder whose name ends in `-authored`, under
BotSting's own licence. Each of them is marked `authored`, so a reader can always tell what was
reused from what was written here.

`botsting/attacks/collected.py` reads these folders and refuses the whole set if any file breaks a
rule. The rules are in that module's first lines.
