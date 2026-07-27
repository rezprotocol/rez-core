import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  AccountDeviceMutationV1,
  ACCOUNT_DEVICE_MUTATION_PURPOSE,
  AccountDeviceMutationV2,
  ACCOUNT_DEVICE_MUTATION_V2_VERSION,
  ACCOUNT_DEVICE_MUTATION_V2_PURPOSE,
  DeviceInboxBindingV1,
  AccountDeviceCapabilityV1,
  ACCOUNT_DEVICE_CAPABILITY_PURPOSE,
  DeviceRegistrationV1,
} from "../src/objects/device/index.js";
import { REZ_CONTRACT_TYPES } from "../src/protocol/index.js";

// S2.5 S11 L2 — the device→home mutation envelope. Real Ed25519; mirrors the
// device-records.test.js conventions. Authority is proven by the session at the
// home, so the envelope carries NO cert chain — just a signer-bound signature.

const NOW = 1_000_000;
const FAR = NOW + 3_600_000;

function genKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const spki = new Uint8Array(publicKey.export({ format: "der", type: "spki" }));
  return { publicKeyB64: Buffer.from(spki).toString("base64"), privateKey };
}
function sign(privateKey, bytes) {
  return { alg: "ed25519", sigB64: Buffer.from(crypto.sign(null, Buffer.from(bytes), privateKey)).toString("base64") };
}
function verify(publicKeyB64, bytes, sig) {
  const keyObj = crypto.createPublicKey({ key: Buffer.from(publicKeyB64, "base64"), format: "der", type: "spki" });
  return crypto.verify(null, Buffer.from(bytes), keyObj, Buffer.from(sig.sigB64, "base64"));
}
function deviceId(pubB64) {
  return DeviceRegistrationV1.deviceIdFor(pubB64);
}

function makeBinding(device, inboxId = "rez:inbox:sibling") {
  const body = {
    v: 1,
    purpose: "rez:device-inbox-binding:v1",
    devicePublicKeyB64: device.publicKeyB64,
    deviceId: deviceId(device.publicKeyB64),
    inboxId,
    issuedAtMs: NOW,
    expiresAtMs: FAR,
  };
  const sig = sign(device.privateKey, DeviceInboxBindingV1.signableBytes(body));
  return new DeviceInboxBindingV1({ ...body, sig }).toJSON();
}

// The account→device leaf capability cert (C←B) the home stores so a later revoke
// auto-revokes it (audit R4 completeness). Signed by the account root B.
function makeCapability({ account, device, capabilities = ["deviceSet.publish"], overrides = {} } = {}) {
  const fields = {
    v: 1,
    purpose: ACCOUNT_DEVICE_CAPABILITY_PURPOSE,
    accountIdentityPublicKeyB64: account.publicKeyB64,
    parentCertId: null,
    granteeDevicePublicKeyB64: device.publicKeyB64,
    granteeDeviceId: deviceId(device.publicKeyB64),
    capabilities,
    maxDelegationDepth: 0,
    issuedAtMs: NOW,
    expiresAtMs: FAR,
    signerPublicKeyB64: account.publicKeyB64,
    ...overrides,
  };
  const certId = AccountDeviceCapabilityV1.deriveCertId(fields);
  const sig = sign(account.privateKey, AccountDeviceCapabilityV1.signableBytes({ ...fields, certId }));
  return new AccountDeviceCapabilityV1({ ...fields, certId, sig }).toJSON();
}

// A complete, coherent device.add target: the sibling's inbox binding + its leaf cert.
function addTarget(account, sibling) {
  return { deviceInboxBinding: makeBinding(sibling), deviceCapability: makeCapability({ account, device: sibling }) };
}

function makeMutation({ account, signer, action, target, opId = "op-1", expectedRevision = 0, overrides = {} } = {}) {
  const body = {
    v: ACCOUNT_DEVICE_MUTATION_V2_VERSION,
    purpose: ACCOUNT_DEVICE_MUTATION_V2_PURPOSE,
    opId,
    accountIdentityPublicKeyB64: account.publicKeyB64,
    expectedRevision,
    action,
    target,
    signerPublicKeyB64: signer.publicKeyB64,
    issuedAtMs: NOW,
    expiresAtMs: FAR,
    ...overrides,
  };
  const sig = sign(signer.privateKey, AccountDeviceMutationV2.signableBytes(body));
  return new AccountDeviceMutationV2({ ...body, sig });
}

test("wire types exist for the mutation + authority-state ops", () => {
  assert.equal(REZ_CONTRACT_TYPES.ACCOUNT_DEVICE_MUTATION_SUBMIT, "account.deviceMutation.submit");
  assert.equal(REZ_CONTRACT_TYPES.ACCOUNT_DEVICE_MUTATION_SUBMIT_RES, "account.deviceMutation.submit.res");
  assert.equal(REZ_CONTRACT_TYPES.ACCOUNT_AUTHORITY_STATE_GET, "account.authorityState.get");
  assert.equal(REZ_CONTRACT_TYPES.ACCOUNT_AUTHORITY_STATE_GET_RES, "account.authorityState.get.res");
});

test("device.add mutation: constructs, verifies (signer-bound), round-trips", () => {
  const account = genKey();
  const sibling = genKey();
  const rec = makeMutation({ account, signer: account, action: "device.add", target: addTarget(account, sibling) });
  assert.equal(rec.action, "device.add");
  // The signer (here the primary account key) signs the envelope.
  assert.ok(verify(account.publicKeyB64, AccountDeviceMutationV2.signableBytes(rec.toJSON()), rec.sig));
  const back = AccountDeviceMutationV2.fromJSON(rec.toJSON());
  assert.equal(back.opId, rec.opId);
  assert.equal(back.target.deviceInboxBinding.deviceId, deviceId(sibling.publicKeyB64));
  assert.equal(back.target.deviceCapability.granteeDeviceId, deviceId(sibling.publicKeyB64), "the leaf cert grants the added device");
});

test("device.add: a delegated device (C) can sign the envelope", () => {
  const account = genKey();
  const deviceC = genKey();
  const sibling = genKey();
  const rec = makeMutation({ account, signer: deviceC, action: "device.add", target: addTarget(account, sibling) });
  assert.equal(rec.signerPublicKeyB64, deviceC.publicKeyB64);
  assert.ok(verify(deviceC.publicKeyB64, AccountDeviceMutationV2.signableBytes(rec.toJSON()), rec.sig), "C's signature verifies");
  assert.ok(!verify(account.publicKeyB64, AccountDeviceMutationV2.signableBytes(rec.toJSON()), rec.sig), "not B's");
});

test("device.revoke mutation: revokedDeviceId + optional revokedCertId", () => {
  const account = genKey();
  const victim = genKey();
  const rec = makeMutation({
    account, signer: account, action: "device.revoke",
    target: { revokedDeviceId: deviceId(victim.publicKeyB64), revokedCertId: "rez:cap:" + "a".repeat(64) },
  });
  assert.equal(rec.action, "device.revoke");
  const back = AccountDeviceMutationV2.fromJSON(rec.toJSON());
  assert.equal(back.target.revokedCertId, "rez:cap:" + "a".repeat(64));
  // revokedCertId is optional.
  const rec2 = makeMutation({ account, signer: account, action: "device.revoke", target: { revokedDeviceId: deviceId(victim.publicKeyB64) } });
  assert.equal(rec2.target.revokedCertId, undefined);
});

test("rejects an unknown action, bad expectedRevision, and malformed targets", () => {
  const account = genKey();
  const sibling = genKey();
  assert.throws(() => makeMutation({ account, signer: account, action: "device.rename", target: {} }), /action must be/);
  assert.throws(() => makeMutation({ account, signer: account, action: "device.add", target: addTarget(account, sibling), overrides: { expectedRevision: -1 } }), /expectedRevision must be a non-negative integer/);
  assert.throws(() => makeMutation({ account, signer: account, action: "device.add", target: { deviceInboxBinding: {}, deviceCapability: makeCapability({ account, device: sibling }) } }), /device.add target.deviceInboxBinding is invalid/);
  assert.throws(() => makeMutation({ account, signer: account, action: "device.revoke", target: { revokedDeviceId: "not-a-dev-id" } }), /must be a canonical rez:dev/);
  // A merely `rez:dev:`-prefixed but non-canonical id (audit R4 F1 DoS-syntax
  // guard) — the forgeable tombstone vector — is now rejected at the record.
  assert.throws(() => makeMutation({ account, signer: account, action: "device.revoke", target: { revokedDeviceId: "rez:dev:ghost" } }), /must be a canonical rez:dev/);
  assert.throws(() => makeMutation({ account, signer: account, action: "device.revoke", target: { revokedDeviceId: "rez:dev:" + "A".repeat(64) } }), /must be a canonical rez:dev/);
  // revokedCertId must be the EXACT canonical rez:cap:<64-hex> shape (F3-remediation
  // finding 2) — a bare prefix, non-hex, wrong length, or uppercase is rejected.
  const sib = deviceId(sibling.publicKeyB64);
  for (const bad of ["not-a-cap", "rez:cap:revoked-leaf", "rez:cap:" + "a".repeat(63), "rez:cap:" + "a".repeat(65), "rez:cap:" + "A".repeat(64), "rez:cap:" + "g".repeat(64)]) {
    assert.throws(() => makeMutation({ account, signer: account, action: "device.revoke", target: { revokedDeviceId: sib, revokedCertId: bad } }), /must be a canonical rez:cap:<64-hex> id or omitted/);
  }
  assert.throws(() => makeMutation({ account, signer: account, action: "device.add", target: addTarget(account, sibling), overrides: { opId: "" } }), /opId must be a non-empty string/);
});

test("device.add completeness: the leaf capability cert is REQUIRED and bound to the added device + account", () => {
  const account = genKey();
  const sibling = genKey();
  // Missing deviceCapability entirely.
  assert.throws(
    () => makeMutation({ account, signer: account, action: "device.add", target: { deviceInboxBinding: makeBinding(sibling) } }),
    /device.add target.deviceCapability is invalid/,
  );
  // A leaf cert for a DIFFERENT device than the binding.
  const other = genKey();
  assert.throws(
    () => makeMutation({ account, signer: account, action: "device.add", target: { deviceInboxBinding: makeBinding(sibling), deviceCapability: makeCapability({ account, device: other }) } }),
    /granteeDeviceId must equal the binding deviceId/,
  );
  // A leaf cert anchored to a DIFFERENT account than the mutation.
  const otherAccount = genKey();
  assert.throws(
    () => makeMutation({ account, signer: account, action: "device.add", target: { deviceInboxBinding: makeBinding(sibling), deviceCapability: makeCapability({ account: otherAccount, device: sibling }) } }),
    /must anchor to the mutation's account/,
  );
});

test("the signed body binds the target: tampering the target breaks the signature", () => {
  const account = genKey();
  const sibling = genKey();
  const rec = makeMutation({ account, signer: account, action: "device.revoke", target: { revokedDeviceId: deviceId(sibling.publicKeyB64) } });
  const tampered = { ...rec.toJSON(), target: { revokedDeviceId: deviceId(genKey().publicKeyB64) } };
  assert.ok(!verify(account.publicKeyB64, AccountDeviceMutationV2.signableBytes(tampered), rec.sig), "swapped target no longer verifies");
});
