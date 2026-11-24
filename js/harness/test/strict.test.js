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

function signedRecord(record) {
  const json = typeof record === "string" ? record : JSON.stringify(record);
  const payload = Buffer.from(json).toString("base64url");
  return payload + "." + pp.mac(KEY, "promptproof-calls/1\n", ["s1", "n1", payload]);
}

test("a signed record can include name lists or omit them", () => {
  const old = signedRecord({ calls: [], dropped: 0 });
  assert.deepEqual(pp.readRecord(KEY, "s1", old, "n1"), { calls: [], read: [], tools: [] });
  const current = signedRecord({ calls: [], dropped: 0, read: ["sample"], tools: ["example"] });
  assert.deepEqual(pp.readRecord(KEY, "s1", current, "n1"), {
    calls: [],
    read: ["sample"],
    tools: ["example"],
  });
  assert.throws(() => pp.readRecord(KEY, "s1", current, "n2"), /not signed/);
});

test("signed records with malformed name lists or drop counts are rejected", () => {
  for (const field of ["read", "tools"]) {
    for (const bad of [null, "sample", {}, [0]]) {
      const header = signedRecord({ calls: [], dropped: 0, [field]: bad });
      assert.throws(() => pp.readRecord(KEY, "s1", header, "n1"), /must be a list of names/);
      assert.throws(() => pp.readCallsHeader(KEY, "s1", header, "n1"), /must be a list of names/);
    }
  }
  for (const dropped of [false, "0", null, 0.5]) {
    const header = signedRecord({ calls: [], dropped });
    assert.throws(() => pp.readRecord(KEY, "s1", header, "n1"), /count of dropped ones/);
  }
  for (const literal of ["0.0", "-0e2", "1e-999"]) {
    const header = signedRecord(`{"calls":[],"dropped":${literal}}`);
    assert.throws(() => pp.readRecord(KEY, "s1", header, "n1"), /count of dropped ones/);
  }
  const nestedFloat = signedRecord('{"calls":[{"dropped":0.0}],"dropped":0,"read":["1e10"]}');
  assert.deepEqual(pp.readRecord(KEY, "s1", nestedFloat, "n1"), {
    calls: [{ dropped: 0 }],
    read: ["1e10"],
    tools: [],
  });
  const dropped = signedRecord({ calls: [], dropped: 1 });
  assert.throws(() => pp.readRecord(KEY, "s1", dropped, "n1"), /1 were not recorded/);
});
