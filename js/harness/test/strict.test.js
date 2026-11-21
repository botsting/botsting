// A signed token is still read strictly: the right types or nothing. Mirrors
// test_a_signed_token_is_still_read_strictly in tests/test_harness_live.py.

import assert from "node:assert/strict";
import { test } from "node:test";
import * as pp from "../index.js";

const KEY = "k".repeat(40);
const DOMAIN = Buffer.from("promptproof-session/1\n");

// Set the key only while one of these tests runs: the suites share a process on newer Node.
function open(token) {
  const before = process.env[pp.KEY_ENV];
  process.env[pp.KEY_ENV] = KEY;
  try {
    return pp.openSession(token);
  } finally {
    if (before === undefined) delete process.env[pp.KEY_ENV];
    else process.env[pp.KEY_ENV] = before;
  }
}

function signed(body) {
  const payload = Buffer.from(JSON.stringify(body)).toString("base64url");
  return payload + "." + pp.mac(KEY, DOMAIN, [payload]);
}

function honest() {
  return { v: 1, sid: "s1", n: "", exp: Math.floor(Date.now() / 1000) + 300, fixtures: {}, content: {} };
}

test("the honest token opens", () => {
  assert.notEqual(open(signed(honest())), null);
});

const changes = {
  "v as true": (b) => (b.v = true),
  "exp as text": (b) => (b.exp = String(b.exp)),
  "exp as a fraction": (b) => (b.exp = b.exp + 0.5),
  "fixtures as a list of pairs": (b) => (b.fixtures = [["admin_code", "x"]]),
  "a fixture that is a number": (b) => (b.fixtures = { admin_code: 5 }),
  "content that is not text": (b) => (b.content = { note: null }),
  "sid as a number": (b) => (b.sid = 5),
  "nonce as a number": (b) => (b.n = 5),
  "live as text": (b) => Object.assign(b, { live: "issue_refund", run: "r" }),
  "live holding a number": (b) => Object.assign(b, { live: [1], run: "r" }),
  "run as a number": (b) => Object.assign(b, { live: ["issue_refund"], run: 7 }),
};

for (const [name, change] of Object.entries(changes)) {
  test(`a signed token with ${name} is refused`, () => {
    const body = honest();
    change(body);
    assert.equal(open(signed(body)), null);
  });
}
