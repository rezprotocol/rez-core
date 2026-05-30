import test from "node:test";
import assert from "node:assert/strict";

import { RHandle } from "../src/capability/RHandle.js";

const VALID = {
  name: "my-cool-name",
  resourceId: "mailbox:inbox_001",
  ownerAccountId: "rez:acct:alice",
  registeredAtMs: 1700000000000,
  signatureB64: "c2lnbmF0dXJl",
};

test("RHandle — construct and seal", () => {
  const h = new RHandle(VALID);
  assert.equal(h.type, "RHandle");
  assert.equal(h.name, "my-cool-name");
  assert.equal(h.resourceId, "mailbox:inbox_001");
  assert.equal(h.ownerAccountId, "rez:acct:alice");
  assert.equal(h.registeredAtMs, 1700000000000);
  assert.equal(h.signatureB64, "c2lnbmF0dXJl");
});

test("RHandle — signatureB64 defaults to null", () => {
  const { signatureB64: _, ...rest } = VALID;
  const h = new RHandle(rest);
  assert.equal(h.signatureB64, null);
});

test("RHandle — rejects empty name", () => {
  assert.throws(() => new RHandle({ ...VALID, name: "" }), /non-empty string/);
});

test("RHandle — rejects name > 64 chars", () => {
  assert.throws(() => new RHandle({ ...VALID, name: "a".repeat(65) }), /at most 64/);
});

test("RHandle — rejects uppercase in name", () => {
  assert.throws(() => new RHandle({ ...VALID, name: "MyName" }), /lowercase/);
});

test("RHandle — rejects name starting with hyphen", () => {
  assert.throws(() => new RHandle({ ...VALID, name: "-bad" }), /lowercase/);
});

test("RHandle — rejects single-char name", () => {
  assert.throws(() => new RHandle({ ...VALID, name: "a" }), /min 2 chars/);
});

test("RHandle — accepts valid names", () => {
  const names = ["ab", "my-name", "my_name", "user123", "a0", "a-b_c"];
  for (const name of names) {
    const h = new RHandle({ ...VALID, name });
    assert.equal(h.name, name);
  }
});

test("RHandle — rejects empty resourceId", () => {
  assert.throws(() => new RHandle({ ...VALID, resourceId: "" }), /non-empty string/);
});

test("RHandle — rejects empty ownerAccountId", () => {
  assert.throws(() => new RHandle({ ...VALID, ownerAccountId: "" }), /non-empty string/);
});

test("RHandle — rejects zero registeredAtMs", () => {
  assert.throws(() => new RHandle({ ...VALID, registeredAtMs: 0 }), /positive number/);
});

test("RHandle — toJSON / fromJSON round-trip", () => {
  const h = new RHandle(VALID);
  const json = h.toJSON();
  assert.equal(json.name, "my-cool-name");

  const restored = RHandle.fromJSON(json);
  assert.equal(restored.name, h.name);
  assert.equal(restored.resourceId, h.resourceId);
});

test("RHandle — _toSignablePayload excludes signatureB64", () => {
  const h = new RHandle(VALID);
  const payload = h._toSignablePayload();
  const parsed = JSON.parse(payload);
  assert.ok(!("signatureB64" in parsed));
  assert.equal(parsed.name, "my-cool-name");
});

test("RHandle — _toSignablePayload has canonical key order", () => {
  const h = new RHandle(VALID);
  const payload = h._toSignablePayload();
  const parsed = JSON.parse(payload);
  const keys = Object.keys(parsed);
  assert.deepEqual(keys, [...keys].sort());
});

test("RHandle — is frozen after construction", () => {
  const h = new RHandle(VALID);
  assert.throws(() => { h.name = "changed"; }, TypeError);
});
