# Rules of engagement (template)

Fill this in before testing a bot for someone else. It is a plain record of what was agreed, signed by a person who can give permission. It is not legal advice: have a lawyer check it before you rely on it with a paying client.

---

**Test of:** _the bot's name and what it does_

**Owner of the system:** _organisation_

**Authorized by (owner's side):** _name, role_. This person confirms they have the authority to allow this test, including for the hosting, the AI model account and any connected service.

**Tester:** _name, organisation_

**Independence:** _self (the builder tests its own bot) / internal (another team in the same organisation) / third party_

## Scope

| | |
|---|---|
| Address tested | _one exact origin, for example https://staging.example.com_ |
| Environment | _test / staging / production_ |
| Agent or tenant | _if the address serves several_ |
| Test accounts | _the accounts the tester will act as; all must be test accounts_ |
| Period | _from, to (at most 90 days)_ |
| Hours | _for example weekdays 09:00 to 17:00 owner's time_ |

## Level of realism

Tick one per tool.

| Tool | Level 1: copy | Level 2: real system, recorded not run | Level 3: real action under a cap | Cap (level 3 only) |
|---|---|---|---|---|
| _issue_refund_ | | | | _at most 10 per call, test orders only, 5 calls and 50 in total per scan_ |
| _send_email_ | | | | _only to qa@example.com_ |

The caps are the ones written in the bot's own code. The owner has read them.

## Out of scope

- Any address, account, data or tool not listed above.
- Denial of service, load testing, and anything meant to exhaust a budget.
- Attacks that change what other users see, on a real system.
- Reading, copying or keeping real personal data. If any appears in a reply, the tester removes it from the record and tells the owner.
- Social engineering of people.

## Limits and stopping

- At most _N_ messages, _N_ recorded tool calls and _N_ minutes per scan.
- The tester stops at once, and tells the owner's contact, if: a tool appears to have acted outside its level or cap; real personal data appears in a reply; the bot or a connected system becomes unavailable; or the owner asks.
- Owner's contact during the test: _name, phone_. Tester's contact: _name, phone_.

## Evidence and reporting

- The owner receives the report, the conversations behind each finding, and the sealed evidence bundle with its seal sent separately.
- Findings are confidential to the owner for _N_ days or until fixed, whichever is first, unless the owner agrees otherwise.
- The tester keeps the evidence for _N_ days and then deletes it.
- The report describes what was tested and found. It is not a certificate, and it does not say the bot is safe.

## Platforms and providers

The owner confirms that the hosting provider's and the AI model provider's terms allow this test, or that written permission has been obtained: _reference_.

**Signed for the owner:** _name, date_

**Signed for the tester:** _name, date_

---

The matching command, run by the person who signed for the owner or on their written instruction:

```
promptproof authorize https://staging.example.com --by "NAME" --scope "AS ABOVE" \
    --environment staging --days 30 --tool issue_refund --tool send_email
```
