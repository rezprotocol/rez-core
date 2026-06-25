import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  DURABLE_RECORD_V2_VERSION,
  durableRecordV2Slot,
  durableRecordV2SignableBytes,
  buildDurableRecordV2,
  verifyDurableRecordV2,
} from "../src/protocol/index.js";
import {
  AccountDeviceCapabilityV1,
  ACCOUNT_DEVICE_CAPABILITY_PURPOSE,
  DeviceRegistrationV1,
} from "../src/objects/device/index.js";

// S2.5 S8 / F2 — DurableRecordV2 owner/signer separation, proven with REAL
// Ed25519 (node:crypto, SPKI/PKCS8). The slot is keyed on the OWNER (B-sign) so a
// delegated signer never moves the coordinate; the signature is checked against
// the SIGNER key; owner→signer authority routes through verifyAccountAuthority.
// DIRECT mode (signer == owner, no chain) is the byte-for-byte V1 primary path.

const NOW = 2_000_000;
const FAR = NOW + 1_000_000;

function genKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const spki = new Uint8Array(publicKey.export({ format: "der", type: "spki" }));
  return { publicKeyB64: Buffer.from(spki).toString("base64"), privateKey };
}

const verifier = {
  async verify({ publicKey, msg, sig }) {
    let keyObj;
    try {
      keyObj = crypto.createPublicKey({ key: Buffer.from(publicKey), format: "der", type: "spki" });
    } catch (err) {
      return false;
    }
    return crypto.verify(null, Buffer.from(msg), keyObj, Buffer.from(sig));
  },
};

// A signed AccountDeviceCapabilityV1, anchored to `account`, signed by `signer`.
function buildCert({ account, signer, parentCertId = null, granteePub, capabilities, maxDelegationDepth = 0, issuedAtMs = NOW, expiresAtMs = FAR }) {
  const fields = {
    v: 1,
    purpose: ACCOUNT_DEVICE_CAPABILITY_PURPOSE,
    accountIdentityPublicKeyB64: account,
    parentCertId,
    granteeDevicePublicKeyB64: granteePub,
    granteeDeviceId: DeviceRegistrationV1.deviceIdFor(granteePub),
    capabilities,
    maxDelegationDepth,
    issuedAtMs,
    expiresAtMs,
    signerPublicKeyB64: signer.publicKeyB64,
  };
  const certId = AccountDeviceCapabilityV1.deriveCertId(fields);
  const msg = AccountDeviceCapabilityV1.signableBytes({ ...fields, certId });
  const sigB64 = Buffer.from(crypto.sign(null, Buffer.from(msg), signer.privateKey)).toString("base64");
  return new AccountDeviceCapabilityV1({ ...fields, certId, sig: { alg: "ed25519", sigB64 } });
}

function signRecord(record, privateKey) {
  const msg = durableRecordV2SignableBytes(record);
  const sigB64 = Buffer.from(crypto.sign(null, Buffer.from(msg), privateKey)).toString("base64");
  return { ...record, sigB64 };
}

const B = genKey(); // account root (B-sign) = owner
const C = genKey(); // delegated device
const OTHER = genKey();
const PAYLOAD_B64 = Buffer.from("device-set-ciphertext").toString("base64");

function directRecord() {
  return buildDurableRecordV2({
    recordKind: "rez.device-set.v1",
    recordId: "peer-abc",
    ownerPublicKeyB64: B.publicKeyB64,
    payloadB64: PAYLOAD_B64,
    issuedAtMs: NOW,
    expiresAtMs: FAR,
  });
}

function delegatedRecord({ cap = "deviceSet.publish", signer = C, grantee = C, leafCaps = ["deviceSet.publish"] } = {}) {
  const leaf = buildCert({ account: B.publicKeyB64, signer: B, granteePub: grantee.publicKeyB64, capabilities: leafCaps });
  return {
    leaf,
    record: buildDurableRecordV2({
      recordKind: "rez.device-set.v1",
      recordId: "peer-abc",
      ownerPublicKeyB64: B.publicKeyB64,
      signerPublicKeyB64: signer.publicKeyB64,
      certChain: [leaf],
      requiredCapability: cap,
      payloadB64: PAYLOAD_B64,
      issuedAtMs: NOW,
      expiresAtMs: FAR,
    }),
  };
}

// ── DIRECT mode ───────────────────────────────────────────────────────────────
test("direct mode: owner signs its own record (no chain) — verifies, mode=direct", async () => {
  const signed = signRecord(directRecord(), B.privateKey);
  const res = await verifyDurableRecordV2({ record: signed, crypto: verifier, nowMs: NOW + 1 });
  assert.equal(res.ok, true, res.reason);
  assert.equal(res.mode, "direct");
  assert.equal(res.ownerPublicKeyB64, B.publicKeyB64);
  assert.equal(res.signerPublicKeyB64, B.publicKeyB64);
  assert.equal(res.payloadB64, PAYLOAD_B64);
  assert.equal(res.leafCertId, null);
});

test("buildDurableRecordV2 defaults the signer to the owner with an empty chain (direct)", () => {
  const r = directRecord();
  assert.equal(r.v, DURABLE_RECORD_V2_VERSION);
  assert.equal(r.signerPublicKeyB64, B.publicKeyB64, "signer defaults to owner");
  assert.deepEqual(r.certChain, []);
  assert.equal(r.requiredCapability, null);
});

// ── DELEGATED mode ────────────────────────────────────────────────────────────
test("delegated mode: C signs with a B→C chain granting the cap — verifies, mode=delegated", async () => {
  const { record, leaf } = delegatedRecord();
  const signed = signRecord(record, C.privateKey);
  const res = await verifyDurableRecordV2({ record: signed, crypto: verifier, nowMs: NOW + 1 });
  assert.equal(res.ok, true, res.reason);
  assert.equal(res.mode, "delegated");
  assert.equal(res.signerPublicKeyB64, C.publicKeyB64);
  assert.equal(res.ownerPublicKeyB64, B.publicKeyB64);
  assert.equal(res.leafCertId, leaf.certId);
  assert.ok(res.grantedCapabilities.includes("deviceSet.publish"));
});

// ── Slot is OWNER-keyed and stable across the signer ──────────────────────────
test("slot is keyed on the OWNER — identical for direct and delegated; signer never moves it", async () => {
  const slot = durableRecordV2Slot({ ownerPublicKeyB64: B.publicKeyB64, recordKind: "rez.device-set.v1", recordId: "peer-abc" });
  const direct = await verifyDurableRecordV2({ record: signRecord(directRecord(), B.privateKey), crypto: verifier, nowMs: NOW + 1 });
  const { record } = delegatedRecord();
  const deleg = await verifyDurableRecordV2({ record: signRecord(record, C.privateKey), crypto: verifier, nowMs: NOW + 1 });
  assert.equal(direct.localId, slot);
  assert.equal(deleg.localId, slot, "delegated signer fetches at the unchanged owner coordinate");
});

test("expectedLocalId mismatch is rejected (slot substitution)", async () => {
  const signed = signRecord(directRecord(), B.privateKey);
  const res = await verifyDurableRecordV2({ record: signed, crypto: verifier, nowMs: NOW + 1, expectedLocalId: "deadbeef" });
  assert.equal(res.ok, false);
  assert.match(res.reason, /owner-keyed coordinate/);
});

// ── Authority failures ────────────────────────────────────────────────────────
test("C signs but presents NO chain — rejected (direct mode requires the owner key)", async () => {
  const r = buildDurableRecordV2({
    recordKind: "rez.device-set.v1",
    recordId: "peer-abc",
    ownerPublicKeyB64: B.publicKeyB64,
    signerPublicKeyB64: C.publicKeyB64,
    payloadB64: PAYLOAD_B64,
    issuedAtMs: NOW,
    expiresAtMs: FAR,
  });
  const res = await verifyDurableRecordV2({ record: signRecord(r, C.privateKey), crypto: verifier, nowMs: NOW + 1 });
  assert.equal(res.ok, false);
  assert.match(res.reason, /authority:/);
});

test("delegated chain that does NOT grant the required capability is rejected", async () => {
  const { record } = delegatedRecord({ cap: "device.revoke", leafCaps: ["deviceSet.publish"] });
  const res = await verifyDurableRecordV2({ record: signRecord(record, C.privateKey), crypto: verifier, nowMs: NOW + 1 });
  assert.equal(res.ok, false);
  assert.match(res.reason, /does not grant/);
});

test("chain anchored to a DIFFERENT account is rejected", async () => {
  const leaf = buildCert({ account: OTHER.publicKeyB64, signer: OTHER, granteePub: C.publicKeyB64, capabilities: ["deviceSet.publish"] });
  const r = buildDurableRecordV2({
    recordKind: "rez.device-set.v1",
    recordId: "peer-abc",
    ownerPublicKeyB64: B.publicKeyB64, // owner is B but the chain anchors to OTHER
    signerPublicKeyB64: C.publicKeyB64,
    certChain: [leaf],
    requiredCapability: "deviceSet.publish",
    payloadB64: PAYLOAD_B64,
    issuedAtMs: NOW,
    expiresAtMs: FAR,
  });
  const res = await verifyDurableRecordV2({ record: signRecord(r, C.privateKey), crypto: verifier, nowMs: NOW + 1 });
  assert.equal(res.ok, false);
  assert.match(res.reason, /account mismatch/);
});

test("leaf granted to a different device than the signer is rejected (non-bearer)", async () => {
  const { record } = delegatedRecord({ signer: C, grantee: OTHER });
  const res = await verifyDurableRecordV2({ record: signRecord(record, C.privateKey), crypto: verifier, nowMs: NOW + 1 });
  assert.equal(res.ok, false);
  assert.match(res.reason, /leaf cert grantee/);
});

// ── Integrity ─────────────────────────────────────────────────────────────────
test("tampering the payload after signing invalidates the signature", async () => {
  const signed = signRecord(directRecord(), B.privateKey);
  signed.payloadB64 = Buffer.from("tampered").toString("base64");
  const res = await verifyDurableRecordV2({ record: signed, crypto: verifier, nowMs: NOW + 1 });
  assert.equal(res.ok, false);
  assert.match(res.reason, /signature invalid/);
});

test("swapping the cert chain for a different (broader) valid chain invalidates the signature", async () => {
  const { record } = delegatedRecord({ leafCaps: ["deviceSet.publish"] });
  const signed = signRecord(record, C.privateKey);
  // Attacker swaps in a different valid B→C chain granting broader caps. The
  // signed bytes commit to the original chain's certIds, so the signature breaks.
  const broader = buildCert({ account: B.publicKeyB64, signer: B, granteePub: C.publicKeyB64, capabilities: ["deviceSet.publish", "device.revoke"] });
  signed.certChain = [broader.toJSON()];
  const res = await verifyDurableRecordV2({ record: signed, crypto: verifier, nowMs: NOW + 1 });
  assert.equal(res.ok, false);
  assert.match(res.reason, /signature invalid/);
});

// ── Time window ───────────────────────────────────────────────────────────────
test("expired and not-yet-valid records are rejected (nowMs required, no fail-open)", async () => {
  const signed = signRecord(directRecord(), B.privateKey);
  const expired = await verifyDurableRecordV2({ record: signed, crypto: verifier, nowMs: FAR + 1 });
  assert.equal(expired.ok, false);
  assert.match(expired.reason, /expired/);
  const early = await verifyDurableRecordV2({ record: signed, crypto: verifier, nowMs: NOW - 1 });
  assert.equal(early.ok, false);
  assert.match(early.reason, /not yet valid/);
  const noNow = await verifyDurableRecordV2({ record: signed, crypto: verifier });
  assert.equal(noNow.ok, false);
  assert.match(noNow.reason, /nowMs required/);
});

// ── Structural guards ─────────────────────────────────────────────────────────
test("non-v2, missing owner/signer, and missing sig are rejected", async () => {
  const ok = signRecord(directRecord(), B.privateKey);
  assert.equal((await verifyDurableRecordV2({ record: { ...ok, v: 1 }, crypto: verifier, nowMs: NOW + 1 })).ok, false);
  assert.equal((await verifyDurableRecordV2({ record: { ...ok, ownerPublicKeyB64: "" }, crypto: verifier, nowMs: NOW + 1 })).ok, false);
  assert.equal((await verifyDurableRecordV2({ record: { ...ok, signerPublicKeyB64: "" }, crypto: verifier, nowMs: NOW + 1 })).ok, false);
  assert.equal((await verifyDurableRecordV2({ record: { ...ok, sigB64: "" }, crypto: verifier, nowMs: NOW + 1 })).ok, false);
});

test("revoking the leaf cert via revocationState kills a delegated record", async () => {
  const { record, leaf } = delegatedRecord();
  const signed = signRecord(record, C.privateKey);
  const res = await verifyDurableRecordV2({
    record: signed,
    crypto: verifier,
    nowMs: NOW + 1,
    revocationState: { revokedCertIds: [leaf.certId] },
  });
  assert.equal(res.ok, false);
  assert.match(res.reason, /revoked/);
});
