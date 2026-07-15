import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  AccountDeviceCapabilityV1,
  ACCOUNT_DEVICE_CAPABILITY_PURPOSE,
  AccountDeviceCapabilityRevokeV1,
  verifyAccountAuthority,
  ACCOUNT_CAPABILITY_ACTIONS,
  DeviceRegistrationV1,
} from "../src/objects/device/index.js";

// S2.5 Slice 6 — account→device capability hierarchy. The validator is PURE
// (revocation/authority state passed in), proven with REAL Ed25519 (node:crypto,
// SPKI/PKCS8 — the exact encoding the records pin). Pins every guardrail:
// anchoring, deterministic certIds, mandatory nowMs, future/expired rejection,
// subset narrowing, exact depth consumption, chain ordering + duplicate rejection,
// non-bearer grantee, recursive parent-revocation, direct-vs-delegated, and no
// authority beyond what is held.

const NOW = 1_000_000;
const FAR = NOW + 1_000_000;

function genKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const spki = new Uint8Array(publicKey.export({ format: "der", type: "spki" }));
  return { publicKeyB64: Buffer.from(spki).toString("base64"), privateKey };
}

// The crypto provider verifyAccountAuthority expects: publicKey arrives as the
// SPKI DER bytes (base64ToBytes of signerPublicKeyB64).
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

// Build a signed AccountDeviceCapabilityV1. `account` is the B-sign pubkey (anchor),
// `signer` is the keypair that signs THIS cert (B at the root, the parent's grantee
// when re-delegating).
function buildCert({ account, signer, parentCertId = null, granteePub, capabilities, maxDelegationDepth, issuedAtMs = NOW, expiresAtMs = FAR }) {
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

const B = genKey();   // account signing root
const C = genKey();   // primary delegated device
const C2 = genKey();  // re-delegated device
const OTHER = genKey();

function leafFor(grantee, caps, depth = 0) {
  return buildCert({ account: B.publicKeyB64, signer: B, granteePub: grantee.publicKeyB64, capabilities: caps, maxDelegationDepth: depth });
}

// ── Record: deterministic certId + structural validation ──────────────────────
test("certId is deterministic and the signature binds it; bad fields are rejected at construction", () => {
  const a = leafFor(C, ["peerLink.create", "deviceSet.publish"]);
  const b = leafFor(C, ["peerLink.create", "deviceSet.publish"]);
  assert.equal(a.certId, b.certId, "same core body → same certId");
  assert.ok(a.certId.startsWith("rez:cap:"));

  const json = a.toJSON();
  assert.throws(() => new AccountDeviceCapabilityV1({ ...json, certId: "rez:cap:deadbeef" }), /certId must be the deterministic/);
  assert.throws(() => new AccountDeviceCapabilityV1({ ...json, capabilities: ["not.a.capability"] }), /unknown capability/);
  assert.throws(() => new AccountDeviceCapabilityV1({ ...json, granteeDeviceId: "rez:dev:wrong" }), /granteeDeviceId must equal/);
  assert.throws(() => new AccountDeviceCapabilityV1({ ...json, parentCertId: "nope" }), /parentCertId must be null or a canonical rez:cap/);
  // F3-remediation finding 2: a bare rez:cap: prefix (not 64 lowercase hex) is rejected.
  assert.throws(() => new AccountDeviceCapabilityV1({ ...json, parentCertId: "rez:cap:parent-leaf" }), /parentCertId must be null or a canonical rez:cap/);
  assert.throws(() => new AccountDeviceCapabilityV1({ ...json, maxDelegationDepth: -1 }), /maxDelegationDepth must be a non-negative integer/);
  assert.throws(() => new AccountDeviceCapabilityV1({ ...json, capabilities: ["deviceSet.publish", "deviceSet.publish"] }), /duplicate capability/);
});

// ── Direct (B-sign) mode ──────────────────────────────────────────────────────
test("direct mode: the account root is authorized for everything; a non-account signer is not", async () => {
  const ok = await verifyAccountAuthority({
    expectedAccountIdentityPublicKeyB64: B.publicKeyB64,
    requiredCapability: "peerLink.create",
    opSignerPublicKeyB64: B.publicKeyB64,
    certChain: null,
    crypto: verifier,
    nowMs: NOW,
  });
  assert.equal(ok.ok, true);
  assert.equal(ok.mode, "direct");
  assert.deepEqual([...ok.grantedCapabilities].sort(), [...ACCOUNT_CAPABILITY_ACTIONS].sort());
  // S11: device.add is in the locked vocab and a direct (B-sign) account is
  // authorized for it (the pin for the vocab addition).
  assert.ok(ACCOUNT_CAPABILITY_ACTIONS.includes("device.add"), "device.add is a known capability");
  assert.ok(ok.grantedCapabilities.includes("device.add"), "the account root is authorized for device.add");

  const bad = await verifyAccountAuthority({
    expectedAccountIdentityPublicKeyB64: B.publicKeyB64,
    requiredCapability: "peerLink.create",
    opSignerPublicKeyB64: C.publicKeyB64,
    certChain: null,
    crypto: verifier,
    nowMs: NOW,
  });
  assert.equal(bad.ok, false);
  assert.match(bad.reason, /direct mode requires B-sign/);
});

// ── Delegated (cert C) mode — happy path + required-capability gate ────────────
test("delegated mode: a valid B→C leaf authorizes the granted capability and refuses an ungranted one", async () => {
  const leaf = leafFor(C, ["deviceSet.publish"]);
  const ok = await verifyAccountAuthority({
    expectedAccountIdentityPublicKeyB64: B.publicKeyB64,
    requiredCapability: "deviceSet.publish",
    opSignerPublicKeyB64: C.publicKeyB64,
    certChain: [leaf],
    crypto: verifier,
    nowMs: NOW,
  });
  assert.equal(ok.ok, true);
  assert.equal(ok.mode, "delegated");
  assert.equal(ok.leafCertId, leaf.certId);
  assert.deepEqual(ok.grantedCapabilities, ["deviceSet.publish"]);

  const ungranted = await verifyAccountAuthority({
    expectedAccountIdentityPublicKeyB64: B.publicKeyB64,
    requiredCapability: "device.revoke",
    opSignerPublicKeyB64: C.publicKeyB64,
    certChain: [leaf],
    crypto: verifier,
    nowMs: NOW,
  });
  assert.equal(ungranted.ok, false);
  assert.match(ungranted.reason, /does not grant "device.revoke"/);
});

// ── Expected-account anchoring ────────────────────────────────────────────────
test("anchoring: a self-consistent chain for the WRONG account is rejected", async () => {
  const leaf = leafFor(C, ["deviceSet.publish"]);
  const r = await verifyAccountAuthority({
    expectedAccountIdentityPublicKeyB64: OTHER.publicKeyB64,
    requiredCapability: "deviceSet.publish",
    opSignerPublicKeyB64: C.publicKeyB64,
    certChain: [leaf],
    crypto: verifier,
    nowMs: NOW,
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /account mismatch/);
});

// ── Mandatory nowMs ───────────────────────────────────────────────────────────
test("nowMs is mandatory (no fail-open on expiry)", async () => {
  const leaf = leafFor(C, ["deviceSet.publish"]);
  const r = await verifyAccountAuthority({
    expectedAccountIdentityPublicKeyB64: B.publicKeyB64,
    requiredCapability: "deviceSet.publish",
    opSignerPublicKeyB64: C.publicKeyB64,
    certChain: [leaf],
    crypto: verifier,
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /nowMs required/);
});

// ── Future-issued + expired ───────────────────────────────────────────────────
test("a not-yet-valid cert and an expired cert are both rejected", async () => {
  const future = buildCert({ account: B.publicKeyB64, signer: B, granteePub: C.publicKeyB64, capabilities: ["deviceSet.publish"], maxDelegationDepth: 0, issuedAtMs: 2_000_000, expiresAtMs: 3_000_000 });
  const notYet = await verifyAccountAuthority({ expectedAccountIdentityPublicKeyB64: B.publicKeyB64, requiredCapability: "deviceSet.publish", opSignerPublicKeyB64: C.publicKeyB64, certChain: [future], crypto: verifier, nowMs: NOW });
  assert.equal(notYet.ok, false);
  assert.match(notYet.reason, /not yet valid/);

  const leaf = leafFor(C, ["deviceSet.publish"]);
  const expired = await verifyAccountAuthority({ expectedAccountIdentityPublicKeyB64: B.publicKeyB64, requiredCapability: "deviceSet.publish", opSignerPublicKeyB64: C.publicKeyB64, certChain: [leaf], crypto: verifier, nowMs: FAR + 1 });
  assert.equal(expired.ok, false);
  assert.match(expired.reason, /expired/);
});

// ── Non-bearer grantee ────────────────────────────────────────────────────────
test("the operation signer MUST be the leaf grantee (no bearer caps)", async () => {
  const leaf = leafFor(C, ["deviceSet.publish"]);
  const r = await verifyAccountAuthority({
    expectedAccountIdentityPublicKeyB64: B.publicKeyB64,
    requiredCapability: "deviceSet.publish",
    opSignerPublicKeyB64: OTHER.publicKeyB64,
    certChain: [leaf],
    crypto: verifier,
    nowMs: NOW,
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /not the leaf cert grantee/);
});

// ── Re-delegation: happy depth-1 chain B→C1→C2 ────────────────────────────────
test("a depth-1 chain B→C1→C2 authorizes C2 for a capability narrowed from C1", async () => {
  const root = buildCert({ account: B.publicKeyB64, signer: B, granteePub: C.publicKeyB64, capabilities: ["deviceSet.publish", "capability.delegate"], maxDelegationDepth: 1 });
  const child = buildCert({ account: B.publicKeyB64, signer: C, parentCertId: root.certId, granteePub: C2.publicKeyB64, capabilities: ["deviceSet.publish"], maxDelegationDepth: 0 });
  const r = await verifyAccountAuthority({
    expectedAccountIdentityPublicKeyB64: B.publicKeyB64,
    requiredCapability: "deviceSet.publish",
    opSignerPublicKeyB64: C2.publicKeyB64,
    certChain: [root, child],
    crypto: verifier,
    nowMs: NOW,
  });
  assert.equal(r.ok, true);
  assert.equal(r.leafCertId, child.certId);
});

// ── Exact depth consumption ───────────────────────────────────────────────────
test("depth must strictly decrement: no delegation at depth 0, and a child cannot keep the parent's depth", async () => {
  // Parent has capability.delegate but depth 0 → no re-delegation (the launch default).
  const root0 = buildCert({ account: B.publicKeyB64, signer: B, granteePub: C.publicKeyB64, capabilities: ["deviceSet.publish", "capability.delegate"], maxDelegationDepth: 0 });
  const childOfDepth0 = buildCert({ account: B.publicKeyB64, signer: C, parentCertId: root0.certId, granteePub: C2.publicKeyB64, capabilities: ["deviceSet.publish"], maxDelegationDepth: 0 });
  const noDepth = await verifyAccountAuthority({ expectedAccountIdentityPublicKeyB64: B.publicKeyB64, requiredCapability: "deviceSet.publish", opSignerPublicKeyB64: C2.publicKeyB64, certChain: [root0, childOfDepth0], crypto: verifier, nowMs: NOW });
  assert.equal(noDepth.ok, false);
  assert.match(noDepth.reason, /no remaining delegation depth/);

  // Parent depth 1, child keeps depth 1 (does not consume) → rejected.
  const root1 = buildCert({ account: B.publicKeyB64, signer: B, granteePub: C.publicKeyB64, capabilities: ["deviceSet.publish", "capability.delegate"], maxDelegationDepth: 1 });
  const greedy = buildCert({ account: B.publicKeyB64, signer: C, parentCertId: root1.certId, granteePub: C2.publicKeyB64, capabilities: ["deviceSet.publish"], maxDelegationDepth: 1 });
  const noConsume = await verifyAccountAuthority({ expectedAccountIdentityPublicKeyB64: B.publicKeyB64, requiredCapability: "deviceSet.publish", opSignerPublicKeyB64: C2.publicKeyB64, certChain: [root1, greedy], crypto: verifier, nowMs: NOW });
  assert.equal(noConsume.ok, false);
  assert.match(noConsume.reason, /does not consume delegation depth/);
});

// ── Subset + TTL narrowing, and capability.delegate requirement ───────────────
test("a child cannot grant a capability the parent lacks, outlive the parent, or re-delegate without capability.delegate", async () => {
  const root = buildCert({ account: B.publicKeyB64, signer: B, granteePub: C.publicKeyB64, capabilities: ["deviceSet.publish", "capability.delegate"], maxDelegationDepth: 1 });

  const broaden = buildCert({ account: B.publicKeyB64, signer: C, parentCertId: root.certId, granteePub: C2.publicKeyB64, capabilities: ["device.revoke"], maxDelegationDepth: 0 });
  const broadenR = await verifyAccountAuthority({ expectedAccountIdentityPublicKeyB64: B.publicKeyB64, requiredCapability: "device.revoke", opSignerPublicKeyB64: C2.publicKeyB64, certChain: [root, broaden], crypto: verifier, nowMs: NOW });
  assert.equal(broadenR.ok, false);
  assert.match(broadenR.reason, /not held by parent/);

  const outlive = buildCert({ account: B.publicKeyB64, signer: C, parentCertId: root.certId, granteePub: C2.publicKeyB64, capabilities: ["deviceSet.publish"], maxDelegationDepth: 0, expiresAtMs: FAR + 1 });
  const outliveR = await verifyAccountAuthority({ expectedAccountIdentityPublicKeyB64: B.publicKeyB64, requiredCapability: "deviceSet.publish", opSignerPublicKeyB64: C2.publicKeyB64, certChain: [root, outlive], crypto: verifier, nowMs: NOW });
  assert.equal(outliveR.ok, false);
  assert.match(outliveR.reason, /outlives its parent/);

  // Parent without capability.delegate (but depth 1) → its child is unauthorized.
  const noDelegate = buildCert({ account: B.publicKeyB64, signer: B, granteePub: C.publicKeyB64, capabilities: ["deviceSet.publish"], maxDelegationDepth: 1 });
  const child = buildCert({ account: B.publicKeyB64, signer: C, parentCertId: noDelegate.certId, granteePub: C2.publicKeyB64, capabilities: ["deviceSet.publish"], maxDelegationDepth: 0 });
  const r = await verifyAccountAuthority({ expectedAccountIdentityPublicKeyB64: B.publicKeyB64, requiredCapability: "deviceSet.publish", opSignerPublicKeyB64: C2.publicKeyB64, certChain: [noDelegate, child], crypto: verifier, nowMs: NOW });
  assert.equal(r.ok, false);
  assert.match(r.reason, /lacks capability.delegate/);
});

// ── Chain integrity: signer linkage, ordering, duplicate, root-must-be-account ─
test("chain integrity: bad signer linkage, broken parent link, duplicate cert, and a non-account root are all rejected", async () => {
  const root = buildCert({ account: B.publicKeyB64, signer: B, granteePub: C.publicKeyB64, capabilities: ["deviceSet.publish", "capability.delegate"], maxDelegationDepth: 1 });

  // Child signed by OTHER, not the parent's grantee (C).
  const wrongSigner = buildCert({ account: B.publicKeyB64, signer: OTHER, parentCertId: root.certId, granteePub: C2.publicKeyB64, capabilities: ["deviceSet.publish"], maxDelegationDepth: 0 });
  const wsR = await verifyAccountAuthority({ expectedAccountIdentityPublicKeyB64: B.publicKeyB64, requiredCapability: "deviceSet.publish", opSignerPublicKeyB64: C2.publicKeyB64, certChain: [root, wrongSigner], crypto: verifier, nowMs: NOW });
  assert.equal(wsR.ok, false);
  assert.match(wsR.reason, /not the parent's grantee/);

  // Broken parent link (parentCertId points elsewhere).
  const otherRoot = buildCert({ account: B.publicKeyB64, signer: B, granteePub: C.publicKeyB64, capabilities: ["device.revoke", "capability.delegate"], maxDelegationDepth: 1 });
  const mislinked = buildCert({ account: B.publicKeyB64, signer: C, parentCertId: otherRoot.certId, granteePub: C2.publicKeyB64, capabilities: ["deviceSet.publish"], maxDelegationDepth: 0 });
  const mlR = await verifyAccountAuthority({ expectedAccountIdentityPublicKeyB64: B.publicKeyB64, requiredCapability: "deviceSet.publish", opSignerPublicKeyB64: C2.publicKeyB64, certChain: [root, mislinked], crypto: verifier, nowMs: NOW });
  assert.equal(mlR.ok, false);
  assert.match(mlR.reason, /does not link to the preceding cert/);

  // Duplicate cert in the chain.
  const dup = await verifyAccountAuthority({ expectedAccountIdentityPublicKeyB64: B.publicKeyB64, requiredCapability: "deviceSet.publish", opSignerPublicKeyB64: C.publicKeyB64, certChain: [root, root], crypto: verifier, nowMs: NOW });
  assert.equal(dup.ok, false);
  assert.match(dup.reason, /duplicate cert/);

  // A "root" (parentCertId null) signed by C, not the account.
  const fakeRoot = buildCert({ account: B.publicKeyB64, signer: C, granteePub: C2.publicKeyB64, capabilities: ["deviceSet.publish"], maxDelegationDepth: 0 });
  const frR = await verifyAccountAuthority({ expectedAccountIdentityPublicKeyB64: B.publicKeyB64, requiredCapability: "deviceSet.publish", opSignerPublicKeyB64: C2.publicKeyB64, certChain: [fakeRoot], crypto: verifier, nowMs: NOW });
  assert.equal(frR.ok, false);
  assert.match(frR.reason, /must be signed by the account root/);
});

// ── Tampered signature ────────────────────────────────────────────────────────
test("a structurally-valid cert with a signature over the wrong bytes fails verification", async () => {
  const leaf = leafFor(C, ["deviceSet.publish"]);
  const json = leaf.toJSON();
  json.sig = { alg: "ed25519", sigB64: Buffer.from(crypto.sign(null, Buffer.from("not the signed body"), B.privateKey)).toString("base64") };
  const tampered = new AccountDeviceCapabilityV1(json); // structurally valid (certId still matches the body)
  const r = await verifyAccountAuthority({ expectedAccountIdentityPublicKeyB64: B.publicKeyB64, requiredCapability: "deviceSet.publish", opSignerPublicKeyB64: C.publicKeyB64, certChain: [tampered], crypto: verifier, nowMs: NOW });
  assert.equal(r.ok, false);
  assert.match(r.reason, /signature invalid/);
});

// ── Recursive revocation + authority-epoch cutoff (state passed in) ────────────
test("revoking a PARENT recursively invalidates descendants; an epoch cutoff rejects pre-cutoff certs", async () => {
  const root = buildCert({ account: B.publicKeyB64, signer: B, granteePub: C.publicKeyB64, capabilities: ["deviceSet.publish", "capability.delegate"], maxDelegationDepth: 1 });
  const child = buildCert({ account: B.publicKeyB64, signer: C, parentCertId: root.certId, granteePub: C2.publicKeyB64, capabilities: ["deviceSet.publish"], maxDelegationDepth: 0 });

  // Sanity: valid before revocation.
  const before = await verifyAccountAuthority({ expectedAccountIdentityPublicKeyB64: B.publicKeyB64, requiredCapability: "deviceSet.publish", opSignerPublicKeyB64: C2.publicKeyB64, certChain: [root, child], crypto: verifier, nowMs: NOW });
  assert.equal(before.ok, true);

  // Revoke the PARENT → the whole chain dies at the parent (recursive).
  const revoked = await verifyAccountAuthority({ expectedAccountIdentityPublicKeyB64: B.publicKeyB64, requiredCapability: "deviceSet.publish", opSignerPublicKeyB64: C2.publicKeyB64, certChain: [root, child], crypto: verifier, nowMs: NOW, revocationState: { revokedCertIds: [root.certId] } });
  assert.equal(revoked.ok, false);
  assert.match(revoked.reason, /revoked/);
  assert.equal(revoked.failedAt, 0);

  // Authority-epoch cutoff: a cert issued before minValidIssuedAtMs is rejected.
  const cutoff = await verifyAccountAuthority({ expectedAccountIdentityPublicKeyB64: B.publicKeyB64, requiredCapability: "deviceSet.publish", opSignerPublicKeyB64: C.publicKeyB64, certChain: [leafFor(C, ["deviceSet.publish"])], crypto: verifier, nowMs: NOW, revocationState: { minValidIssuedAtMs: NOW + 1 } });
  assert.equal(cutoff.ok, false);
  assert.match(cutoff.reason, /predates the account authority cutoff/);
});

// ── Revoke record ─────────────────────────────────────────────────────────────
test("AccountDeviceCapabilityRevokeV1 validates structurally and round-trips its signature", () => {
  const leaf = leafFor(C, ["deviceSet.publish"]);
  const body = {
    v: 1,
    purpose: "rez:account-device-capability-revoke:v1",
    accountIdentityPublicKeyB64: B.publicKeyB64,
    revokedCertId: leaf.certId,
    authorityEpoch: 7,
    issuedAtMs: NOW,
    signerPublicKeyB64: B.publicKeyB64,
  };
  const msg = AccountDeviceCapabilityRevokeV1.signableBytes(body);
  const sigB64 = Buffer.from(crypto.sign(null, Buffer.from(msg), B.privateKey)).toString("base64");
  const revoke = new AccountDeviceCapabilityRevokeV1({ ...body, sig: { alg: "ed25519", sigB64 } });
  assert.equal(revoke.revokedCertId, leaf.certId);

  const keyObj = crypto.createPublicKey({ key: Buffer.from(B.publicKeyB64, "base64"), format: "der", type: "spki" });
  assert.equal(crypto.verify(null, Buffer.from(AccountDeviceCapabilityRevokeV1.signableBytes(revoke)), keyObj, Buffer.from(revoke.sig.sigB64, "base64")), true);

  assert.throws(() => new AccountDeviceCapabilityRevokeV1({ ...body, revokedCertId: "not-a-cap-id", sig: { alg: "ed25519", sigB64 } }), /revokedCertId must be a canonical rez:cap/);
  // F3-remediation finding 2: a bare rez:cap: prefix is rejected (must be 64 lowercase hex).
  assert.throws(() => new AccountDeviceCapabilityRevokeV1({ ...body, revokedCertId: "rez:cap:revoked-leaf", sig: { alg: "ed25519", sigB64 } }), /revokedCertId must be a canonical rez:cap/);
});
