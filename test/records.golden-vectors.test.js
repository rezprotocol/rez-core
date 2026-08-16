/**
 * P7.1 — canonical bytes and ID derivation against the frozen golden vectors.
 * rez-core owns the vectors; this test proves the SSOT functions REPRODUCE
 * them (deterministic Ed25519: signatures must match byte-for-byte).
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createPrivateKey, sign as nodeSign, verify as nodeVerify, createPublicKey } from "node:crypto";
import {
  relayKeyIdForNodePublicKeyB64,
  nodeKeyIdForNodePublicKeyB64,
  validateRelayIdentityBinding,
  durableRecordSignableBytes,
  durableRecordLocalId,
  validateRelayDescriptorV1,
} from "../src/index.js";
import {
  GOLDEN_NODE_PUBLIC_KEY_B64,
  GOLDEN_NODE_PRIVATE_KEY_B64,
  GOLDEN_RELAY_KEY_ID,
  GOLDEN_NODE_KEY_ID,
  GOLDEN_NOW_MS,
  GOLDEN_RELAY_DESCRIPTOR,
  GOLDEN_DURABLE_RECORD_V1,
  GOLDEN_DURABLE_RECORD_V1_SIGNABLE_STRING,
  GOLDEN_DURABLE_RECORD_V1_LOCAL_ID,
} from "./support/goldenVectors.js";

test("identity derivation reproduces the golden relay and node IDs", () => {
  assert.equal(relayKeyIdForNodePublicKeyB64(GOLDEN_NODE_PUBLIC_KEY_B64), GOLDEN_RELAY_KEY_ID);
  assert.equal(nodeKeyIdForNodePublicKeyB64(GOLDEN_NODE_PUBLIC_KEY_B64), GOLDEN_NODE_KEY_ID);
  assert.equal(validateRelayIdentityBinding({
    relayKeyId: GOLDEN_RELAY_KEY_ID,
    nodeKeyId: GOLDEN_NODE_KEY_ID,
    nodePublicKeyB64: GOLDEN_NODE_PUBLIC_KEY_B64,
  }).ok, true);
});

test("DurableRecordV1 canonical signable bytes, slot id, and signature reproduce the goldens", () => {
  const signable = durableRecordSignableBytes(GOLDEN_DURABLE_RECORD_V1);
  assert.equal(Buffer.from(signable).toString("utf8"), GOLDEN_DURABLE_RECORD_V1_SIGNABLE_STRING);
  assert.equal(durableRecordLocalId({
    publisherPublicKeyB64: GOLDEN_DURABLE_RECORD_V1.publisherPublicKeyB64,
    recordKind: GOLDEN_DURABLE_RECORD_V1.recordKind,
    recordId: GOLDEN_DURABLE_RECORD_V1.recordId,
  }), GOLDEN_DURABLE_RECORD_V1_LOCAL_ID);

  const privKey = createPrivateKey({
    key: Buffer.from(GOLDEN_NODE_PRIVATE_KEY_B64, "base64"), format: "der", type: "pkcs8",
  });
  const sig = nodeSign(null, Buffer.from(signable), privKey);
  assert.equal(Buffer.from(sig).toString("base64"), GOLDEN_DURABLE_RECORD_V1.sigB64,
    "deterministic Ed25519 must reproduce the golden signature exactly");

  const pubKey = createPublicKey(privKey);
  assert.equal(nodeVerify(null, Buffer.from(signable), pubKey,
    Buffer.from(GOLDEN_DURABLE_RECORD_V1.sigB64, "base64")), true);
});

test("the golden relay descriptor passes the canonical validator at its epoch", () => {
  const verdict = validateRelayDescriptorV1(structuredClone(GOLDEN_RELAY_DESCRIPTOR), { nowMs: GOLDEN_NOW_MS });
  assert.equal(verdict.ok, true, verdict.reason || "");
  assert.equal(verdict.descriptor.relayKeyId, GOLDEN_RELAY_KEY_ID);
});

// ── DurableRecordV2 golden vectors (re-audit R7) ────────────────────────────
import {
  durableRecordV2SignableBytes,
  durableRecordV2Slot,
  verifyDurableRecordV2,
} from "../src/protocol/index.js";
import { AccountDeviceCapabilityV1 } from "../src/objects/device/index.js";
import {
  GOLDEN_DEVICE_PUBLIC_KEY_B64,
  GOLDEN_DEVICE_PRIVATE_KEY_B64,
  GOLDEN_DEVICE_CERT,
  GOLDEN_DEVICE_CERT_SIGNABLE_STRING,
  GOLDEN_DURABLE_RECORD_V2_DIRECT,
  GOLDEN_DURABLE_RECORD_V2_DIRECT_SIGNABLE_STRING,
  GOLDEN_DURABLE_RECORD_V2_DIRECT_SLOT,
  GOLDEN_DURABLE_RECORD_V2_DELEGATED,
  GOLDEN_DURABLE_RECORD_V2_DELEGATED_SIGNABLE_STRING,
  GOLDEN_DURABLE_RECORD_V2_DELEGATED_SLOT,
} from "./support/goldenVectors.js";

const V2_VERIFIER = {
  async verify({ publicKey, msg, sig }) {
    const keyObj = createPublicKey({ key: Buffer.from(publicKey), format: "der", type: "spki" });
    return nodeVerify(null, Buffer.from(msg), keyObj, Buffer.from(sig));
  },
};

test("V2 direct: canonical signable bytes, slot, and signature reproduce the frozen vector", async () => {
  const signable = durableRecordV2SignableBytes(GOLDEN_DURABLE_RECORD_V2_DIRECT);
  assert.equal(new TextDecoder().decode(signable), GOLDEN_DURABLE_RECORD_V2_DIRECT_SIGNABLE_STRING,
    "V2 canonicalization changed — that is a wire-breaking event");
  assert.equal(durableRecordV2Slot(GOLDEN_DURABLE_RECORD_V2_DIRECT), GOLDEN_DURABLE_RECORD_V2_DIRECT_SLOT);

  const key = createPrivateKey({ key: Buffer.from(GOLDEN_NODE_PRIVATE_KEY_B64, "base64"), format: "der", type: "pkcs8" });
  const resigned = nodeSign(null, Buffer.from(signable), key);
  assert.equal(resigned.toString("base64"), GOLDEN_DURABLE_RECORD_V2_DIRECT.sigB64,
    "deterministic Ed25519 must REPRODUCE the direct-owner signature byte-for-byte");

  const res = await verifyDurableRecordV2({
    record: GOLDEN_DURABLE_RECORD_V2_DIRECT, crypto: V2_VERIFIER, nowMs: GOLDEN_NOW_MS + 1,
  });
  assert.equal(res.ok, true, res.reason || "");
  assert.equal(res.mode, "direct");
});

test("V2 delegated: chain-committed signable bytes, slot, and device signature reproduce the frozen vector", async () => {
  const signable = durableRecordV2SignableBytes(GOLDEN_DURABLE_RECORD_V2_DELEGATED);
  assert.equal(new TextDecoder().decode(signable), GOLDEN_DURABLE_RECORD_V2_DELEGATED_SIGNABLE_STRING,
    "the chain commitment (ordered certIds) is part of the signed bytes");
  assert.equal(durableRecordV2Slot(GOLDEN_DURABLE_RECORD_V2_DELEGATED), GOLDEN_DURABLE_RECORD_V2_DELEGATED_SLOT,
    "the slot stays OWNER-keyed — a delegated signer never moves the coordinate");

  const deviceKey = createPrivateKey({ key: Buffer.from(GOLDEN_DEVICE_PRIVATE_KEY_B64, "base64"), format: "der", type: "pkcs8" });
  const resigned = nodeSign(null, Buffer.from(signable), deviceKey);
  assert.equal(resigned.toString("base64"), GOLDEN_DURABLE_RECORD_V2_DELEGATED.sigB64,
    "deterministic Ed25519 must REPRODUCE the delegated (device) signature byte-for-byte");

  const res = await verifyDurableRecordV2({
    record: GOLDEN_DURABLE_RECORD_V2_DELEGATED, crypto: V2_VERIFIER, nowMs: GOLDEN_NOW_MS + 1,
  });
  assert.equal(res.ok, true, res.reason || "");
  assert.equal(res.mode, "delegated");
  assert.equal(res.leafCertId, GOLDEN_DEVICE_CERT.certId);
});

test("V2 delegated: the capability cert's signable bytes and root signature reproduce the frozen vector", () => {
  const signable = AccountDeviceCapabilityV1.signableBytes(GOLDEN_DEVICE_CERT);
  assert.equal(new TextDecoder().decode(signable), GOLDEN_DEVICE_CERT_SIGNABLE_STRING);
  assert.equal(AccountDeviceCapabilityV1.deriveCertId(GOLDEN_DEVICE_CERT), GOLDEN_DEVICE_CERT.certId,
    "certId is the deterministic digest of the cert body");

  const rootKey = createPrivateKey({ key: Buffer.from(GOLDEN_NODE_PRIVATE_KEY_B64, "base64"), format: "der", type: "pkcs8" });
  const resigned = nodeSign(null, Buffer.from(signable), rootKey);
  assert.equal(resigned.toString("base64"), GOLDEN_DEVICE_CERT.sig.sigB64);
  assert.equal(GOLDEN_DEVICE_CERT.granteeDevicePublicKeyB64, GOLDEN_DEVICE_PUBLIC_KEY_B64);
});
