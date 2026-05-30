import test from "node:test";
import assert from "node:assert/strict";

import { RCapability } from "../src/capability/RCapability.js";

const VALID = {
  capId: "cap_abc123",
  resource: "mailbox:inbox_001",
  actions: ["read", "post"],
  constraints: { expiresAt: 9999999999999 },
  signerPublicKeyB64: "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=",
  signatureB64: "c2lnbmF0dXJl",
};

test("RCapability — construct and seal", () => {
  const cap = new RCapability(VALID);
  assert.equal(cap.type, "RCapability");
  assert.equal(cap.capId, "cap_abc123");
  assert.equal(cap.parentCapId, null);
  assert.equal(cap.resource, "mailbox:inbox_001");
  assert.deepEqual(cap.actions, ["post", "read"]); // sorted
  assert.deepEqual(cap.constraints, { expiresAt: 9999999999999 });
  assert.equal(cap.signerPublicKeyB64, "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=");
  assert.equal(cap.signatureB64, "c2lnbmF0dXJl");
});

test("RCapability — actions are sorted", () => {
  const cap = new RCapability({ ...VALID, actions: ["write", "admin", "read"] });
  assert.deepEqual(cap.actions, ["admin", "read", "write"]);
});

test("RCapability — actions are frozen", () => {
  const cap = new RCapability(VALID);
  assert.throws(() => { cap.actions.push("admin"); }, TypeError);
});

test("RCapability — constraints are frozen", () => {
  const cap = new RCapability(VALID);
  assert.throws(() => { cap.constraints.expiresAt = 0; }, TypeError);
});

test("RCapability — rejects empty capId", () => {
  assert.throws(() => new RCapability({ ...VALID, capId: "" }), /non-empty string/);
});

test("RCapability — rejects invalid resource format", () => {
  assert.throws(() => new RCapability({ ...VALID, resource: "nocolon" }), /invalid format/);
});

test("RCapability — rejects invalid resource kind", () => {
  assert.throws(() => new RCapability({ ...VALID, resource: "bogus:id" }), /must be one of/);
});

test("RCapability — rejects empty actions", () => {
  assert.throws(() => new RCapability({ ...VALID, actions: [] }), /non-empty array/);
});

test("RCapability — rejects invalid action name", () => {
  assert.throws(() => new RCapability({ ...VALID, actions: ["read", "destroy"] }), /invalid action/);
});

test("RCapability — rejects invalid constraints.expiresAt", () => {
  assert.throws(
    () => new RCapability({ ...VALID, constraints: { expiresAt: "soon" } }),
    /must be a number/
  );
});

test("RCapability — rejects non-positive maxUses", () => {
  assert.throws(
    () => new RCapability({ ...VALID, constraints: { maxUses: 0 } }),
    /positive number/
  );
});

test("RCapability — rejects negative maxDelegationDepth", () => {
  assert.throws(
    () => new RCapability({ ...VALID, constraints: { maxDelegationDepth: -1 } }),
    /non-negative/
  );
});

test("RCapability — rejects missing signerPublicKeyB64", () => {
  assert.throws(
    () => new RCapability({ ...VALID, signerPublicKeyB64: "" }),
    /non-empty string/
  );
});

test("RCapability — granteePublicKeyB64 defaults to null and accepts non-empty string", () => {
  const bearer = new RCapability(VALID);
  assert.equal(bearer.granteePublicKeyB64, null);

  const granted = new RCapability({ ...VALID, granteePublicKeyB64: "QUJDREVGRw==" });
  assert.equal(granted.granteePublicKeyB64, "QUJDREVGRw==");

  assert.throws(
    () => new RCapability({ ...VALID, granteePublicKeyB64: "" }),
    /null or a non-empty string/,
  );
});

test("RCapability — toJSON / fromJSON round-trip", () => {
  const cap = new RCapability(VALID);
  const json = cap.toJSON();

  assert.equal(json.capId, "cap_abc123");
  assert.equal(json.parentCapId, null);
  assert.equal(json.resource, "mailbox:inbox_001");
  assert.deepEqual(json.actions, ["post", "read"]);

  const restored = RCapability.fromJSON(json);
  assert.equal(restored.capId, cap.capId);
  assert.equal(restored.resource, cap.resource);
  assert.deepEqual(restored.actions, cap.actions);
});

test("RCapability — _toSignablePayload excludes signatureB64", () => {
  const cap = new RCapability(VALID);
  const payload = cap._toSignablePayload();
  const parsed = JSON.parse(payload);

  assert.ok(!("signatureB64" in parsed), "signatureB64 must be excluded");
  assert.equal(parsed.capId, "cap_abc123");
  assert.equal(parsed.resource, "mailbox:inbox_001");
});

test("RCapability — _toSignablePayload is canonical (sorted keys)", () => {
  const cap = new RCapability(VALID);
  const payload = cap._toSignablePayload();
  const parsed = JSON.parse(payload);
  const keys = Object.keys(parsed);
  const sorted = [...keys].sort();
  assert.deepEqual(keys, sorted, "keys must be in sorted order");
});

test("RCapability — parentCapId accepted as string", () => {
  const cap = new RCapability({ ...VALID, parentCapId: "cap_parent" });
  assert.equal(cap.parentCapId, "cap_parent");
});

test("RCapability — signatureB64 null allowed", () => {
  const cap = new RCapability({ ...VALID, signatureB64: null });
  assert.equal(cap.signatureB64, null);
});

test("RCapability — ACTIONS constant", () => {
  assert.deepEqual(RCapability.ACTIONS, ["admin", "connect", "grant", "post", "read", "write"]);
  assert.ok(Object.isFrozen(RCapability.ACTIONS));
});

test("RCapability — is frozen after construction", () => {
  const cap = new RCapability(VALID);
  assert.throws(() => { cap.capId = "changed"; }, TypeError);
});
