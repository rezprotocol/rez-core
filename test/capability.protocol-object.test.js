import test from "node:test";
import assert from "node:assert/strict";

import { RProtocolObject } from "../src/capability/RProtocolObject.js";

const VALID = {
  objectId: "obj_abc123",
  ciphertextB64: "ZW5jcnlwdGVk",
  metadata: { contentType: "application/octet-stream", sizeBytes: 1024, createdAtMs: 1700000000000 },
};

test("RProtocolObject — construct and seal", () => {
  const obj = new RProtocolObject(VALID);
  assert.equal(obj.type, "RProtocolObject");
  assert.equal(obj.objectId, "obj_abc123");
  assert.equal(obj.ciphertextB64, "ZW5jcnlwdGVk");
  assert.equal(obj.metadata.contentType, "application/octet-stream");
  assert.equal(obj.signatureB64, null);
  assert.equal(obj.signerPublicKeyB64, null);
});

test("RProtocolObject — with signature and signer", () => {
  const obj = new RProtocolObject({
    ...VALID,
    signatureB64: "c2ln",
    signerPublicKeyB64: "rez:acct:alice",
  });
  assert.equal(obj.signatureB64, "c2ln");
  assert.equal(obj.signerPublicKeyB64, "rez:acct:alice");
});

test("RProtocolObject — rejects signature without signer", () => {
  assert.throws(
    () => new RProtocolObject({ ...VALID, signatureB64: "c2ln" }),
    /both be present or both null/
  );
});

test("RProtocolObject — rejects signer without signature", () => {
  assert.throws(
    () => new RProtocolObject({ ...VALID, signerPublicKeyB64: "rez:acct:alice" }),
    /both be present or both null/
  );
});

test("RProtocolObject — rejects empty objectId", () => {
  assert.throws(() => new RProtocolObject({ ...VALID, objectId: "" }), /non-empty string/);
});

test("RProtocolObject — rejects empty ciphertextB64", () => {
  assert.throws(() => new RProtocolObject({ ...VALID, ciphertextB64: "" }), /non-empty string/);
});

test("RProtocolObject — rejects negative sizeBytes", () => {
  assert.throws(
    () => new RProtocolObject({ ...VALID, metadata: { sizeBytes: -1 } }),
    /non-negative/
  );
});

test("RProtocolObject — metadata is frozen", () => {
  const obj = new RProtocolObject(VALID);
  assert.throws(() => { obj.metadata.contentType = "changed"; }, TypeError);
});

test("RProtocolObject — toJSON / fromJSON round-trip", () => {
  const obj = new RProtocolObject(VALID);
  const json = obj.toJSON();
  const restored = RProtocolObject.fromJSON(json);
  assert.equal(restored.objectId, obj.objectId);
  assert.equal(restored.ciphertextB64, obj.ciphertextB64);
  assert.deepEqual(restored.metadata, obj.metadata);
});

test("RProtocolObject — minimal metadata accepted", () => {
  const obj = new RProtocolObject({
    objectId: "obj_1",
    ciphertextB64: "YQ==",
  });
  assert.deepEqual(obj.metadata, {});
});
