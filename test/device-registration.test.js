import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import { DeviceRegistrationV1, DEVICE_REGISTRATION_PURPOSE } from "../src/objects/device/DeviceRegistrationV1.js";
import { verifyDeviceRegistrationV1 } from "../src/objects/device/verifyDeviceRegistrationV1.js";

// Ed25519 verify provider. Device/account public keys are the full 44-byte SPKI
// DER encoding (the encoding DeviceRegistrationV1 enforces), imported directly.
const cryptoProvider = {
  async verify({ publicKey, msg, sig }) {
    const keyObj = crypto.createPublicKey({
      key: Buffer.from(publicKey),
      format: "der",
      type: "spki",
    });
    return crypto.verify(null, msg, keyObj, sig);
  },
};

// Public key = full SPKI DER (44 bytes); private = raw 32-byte seed (re-wrapped
// to PKCS8 by signWithAccount). The SPKI public is what the record stores +
// hashes into deviceId, matching the SDK's WebCrypto exportKey("spki").
function generateEd25519KeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    publicKey: new Uint8Array(publicKey.export({ format: "der", type: "spki" })),
    privateKey: new Uint8Array(privateKey.export({ format: "der", type: "pkcs8" }).subarray(16)),
  };
}

function b64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

// Sign exactly as the SDK device-registration signer will: Ed25519 (account
// identity key) over DeviceRegistrationV1.signableBytes(body); sig carried as
// the JSON-safe `{ alg, sigB64 }` shape the record stores.
function signWithAccount(body, accountPrivateKey) {
  const keyObj = crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(accountPrivateKey)]),
    format: "der",
    type: "pkcs8",
  });
  const bytes = DeviceRegistrationV1.signableBytes(body);
  const sig = new Uint8Array(crypto.sign(null, bytes, keyObj));
  return { alg: "ed25519", sigB64: Buffer.from(sig).toString("base64") };
}

const ISSUED = 1_700_000_000_000;
const EXPIRES = ISSUED + 30 * 24 * 60 * 60 * 1000; // 30 days

function makeRegistration({ account, device, overrides = {} } = {}) {
  const accountIdentityPublicKeyB64 = b64(account.publicKey);
  const devicePublicKeyB64 = b64(device.publicKey);
  const body = {
    v: 1,
    purpose: DEVICE_REGISTRATION_PURPOSE,
    accountIdentityPublicKeyB64,
    devicePublicKeyB64,
    deviceId: DeviceRegistrationV1.deviceIdFor(devicePublicKeyB64),
    issuedAtMs: ISSUED,
    expiresAtMs: EXPIRES,
    ...overrides,
  };
  const sig = signWithAccount(body, account.privateKey);
  return new DeviceRegistrationV1({ ...body, sig });
}

test("deviceIdFor is deterministic and self-certifying (rez:dev:<sha256>)", () => {
  const device = generateEd25519KeyPair();
  const pub = b64(device.publicKey);
  const id1 = DeviceRegistrationV1.deviceIdFor(pub);
  const id2 = DeviceRegistrationV1.deviceIdFor(pub);
  assert.equal(id1, id2, "deterministic");
  assert.match(id1, /^rez:dev:[0-9a-f]{64}$/, "rez:dev:<64 hex>");
  const other = DeviceRegistrationV1.deviceIdFor(b64(generateEd25519KeyPair().publicKey));
  assert.notEqual(id1, other, "distinct device keys → distinct ids");
});

test("non-canonical base64 keys are rejected (kills the deviceId trim collision)", () => {
  const device = generateEd25519KeyPair();
  const account = generateEd25519KeyPair();
  const clean = b64(device.publicKey);
  // base64ToBytes silently strips whitespace, so a padded key would decode to the
  // same bytes yet (formerly) hash to a different deviceId — reject it outright.
  assert.throws(() => DeviceRegistrationV1.deviceIdFor(clean + " "), /canonical/);
  assert.throws(() => DeviceRegistrationV1.deviceIdFor(" " + clean), /canonical/);
  // And the constructor rejects a non-canonical device key.
  assert.throws(() => makeRegistration({ account, device, overrides: { devicePublicKeyB64: clean + " " } }), /canonical|deviceId/);
});

test("non-SPKI / non-canonical keys are rejected (audit P2: length + prefix + round-trip)", () => {
  const device = generateEd25519KeyPair();
  // A RAW 32-byte Ed25519 key (the SPKI header stripped) is canonical base64 but
  // the wrong length — the contract is SPKI DER, so reject it.
  const raw32 = b64(device.publicKey.subarray(12));
  assert.throws(() => DeviceRegistrationV1.deviceIdFor(raw32), /SPKI|44-byte/);
  // Structurally-broken base64 the permissive regex used to wave through.
  assert.throws(() => DeviceRegistrationV1.deviceIdFor("A="), /base64/i);
  assert.throws(() => DeviceRegistrationV1.deviceIdFor("abcde"), /base64/i);
  // 44 bytes but NOT the Ed25519 SPKI prefix (here: all-zero DER) → rejected.
  assert.throws(() => DeviceRegistrationV1.deviceIdFor(b64(new Uint8Array(44))), /prefix/);
});

test("the constructor refuses a deviceId that does not match the device key", () => {
  const account = generateEd25519KeyPair();
  const device = generateEd25519KeyPair();
  const accountIdentityPublicKeyB64 = b64(account.publicKey);
  const devicePublicKeyB64 = b64(device.publicKey);
  const body = {
    v: 1,
    purpose: DEVICE_REGISTRATION_PURPOSE,
    accountIdentityPublicKeyB64,
    devicePublicKeyB64,
    deviceId: "rez:dev:" + "0".repeat(64), // wrong id
    issuedAtMs: ISSUED,
    expiresAtMs: EXPIRES,
  };
  const sig = signWithAccount(body, account.privateKey);
  assert.throws(() => new DeviceRegistrationV1({ ...body, sig }), /deviceId must equal/);
});

const VALID_NOW = ISSUED + 1000;
function verifyAs(registration, expectAccount, nowMs = VALID_NOW) {
  return verifyDeviceRegistrationV1({
    registration,
    expectedAccountIdentityPublicKeyB64: b64(expectAccount.publicKey),
    crypto: cryptoProvider,
    nowMs,
  });
}

test("a correctly account-signed registration verifies against the expected account", async () => {
  const account = generateEd25519KeyPair();
  const device = generateEd25519KeyPair();
  const reg = makeRegistration({ account, device });
  const res = await verifyAs(reg, account);
  assert.equal(res.ok, true, res.reason);
  assert.equal(res.deviceId, reg.deviceId);
});

test("TRUST ANCHOR: a signature-valid registration for the WRONG account is rejected", async () => {
  // Attacker mints a PERFECTLY valid registration for THEIR OWN account+device.
  const attacker = generateEd25519KeyPair();
  const attackerDevice = generateEd25519KeyPair();
  const evil = makeRegistration({ account: attacker, device: attackerDevice });
  // A caller expecting a device of `victim` must NOT accept it.
  const victim = generateEd25519KeyPair();
  const res = await verifyAs(evil, victim);
  assert.equal(res.ok, false);
  assert.equal(res.reason, "account mismatch (not the expected account)");
  // ...but it IS valid for its own account — proving the rejection is the anchor,
  // not some other defect.
  assert.equal((await verifyAs(evil, attacker)).ok, true);
});

test("a wrong purpose (domain separator) is rejected", async () => {
  const account = generateEd25519KeyPair();
  const device = generateEd25519KeyPair();
  const reg = makeRegistration({ account, device });
  const tampered = reg.toJSON();
  tampered.purpose = "rez:something-else:v1";
  const res = await verifyAs(tampered, account);
  assert.equal(res.ok, false);
  assert.equal(res.reason, "purpose mismatch");
});

test("the trust anchor is REQUIRED", async () => {
  const account = generateEd25519KeyPair();
  const reg = makeRegistration({ account, device: generateEd25519KeyPair() });
  const res = await verifyDeviceRegistrationV1({ registration: reg, crypto: cryptoProvider, nowMs: VALID_NOW });
  assert.equal(res.ok, false);
  assert.match(res.reason, /expectedAccountIdentityPublicKeyB64 required/);
});

test("nowMs is REQUIRED (no fail-open on expiry)", async () => {
  const account = generateEd25519KeyPair();
  const reg = makeRegistration({ account, device: generateEd25519KeyPair() });
  const res = await verifyDeviceRegistrationV1({
    registration: reg,
    expectedAccountIdentityPublicKeyB64: b64(account.publicKey),
    crypto: cryptoProvider,
  });
  assert.equal(res.ok, false);
  assert.match(res.reason, /nowMs required/);
});

test("round-trips through toJSON/fromJSON and still verifies", async () => {
  const account = generateEd25519KeyPair();
  const device = generateEd25519KeyPair();
  const reg = makeRegistration({ account, device });
  const back = DeviceRegistrationV1.fromJSON(reg.toJSON());
  assert.equal(back.deviceId, reg.deviceId);
  assert.equal(back.accountIdentityPublicKeyB64, reg.accountIdentityPublicKeyB64);
  assert.equal((await verifyAs(back, account)).ok, true);
});

test("tampering the signed body (expiresAtMs) fails verification", async () => {
  const account = generateEd25519KeyPair();
  const device = generateEd25519KeyPair();
  const reg = makeRegistration({ account, device });
  const tampered = reg.toJSON();
  tampered.expiresAtMs = EXPIRES + 365 * 24 * 60 * 60 * 1000; // extend lifetime, no re-sign
  const res = await verifyAs(tampered, account);
  assert.equal(res.ok, false);
  assert.equal(res.reason, "signature invalid");
});

test("a deviceId/device-key mismatch in raw JSON is rejected", async () => {
  const account = generateEd25519KeyPair();
  const device = generateEd25519KeyPair();
  const reg = makeRegistration({ account, device });
  const swapped = reg.toJSON();
  swapped.devicePublicKeyB64 = b64(generateEd25519KeyPair().publicKey); // different device, stale id
  const res = await verifyAs(swapped, account);
  assert.equal(res.ok, false);
  assert.equal(res.reason, "deviceId does not match device key");
});

test("a registration signed by the WRONG account key fails verification", async () => {
  const account = generateEd25519KeyPair();
  const attacker = generateEd25519KeyPair();
  const device = generateEd25519KeyPair();
  // Body claims `account` as the authorizer, but `attacker` signs it.
  const accountIdentityPublicKeyB64 = b64(account.publicKey);
  const devicePublicKeyB64 = b64(device.publicKey);
  const body = {
    v: 1,
    purpose: DEVICE_REGISTRATION_PURPOSE,
    accountIdentityPublicKeyB64,
    devicePublicKeyB64,
    deviceId: DeviceRegistrationV1.deviceIdFor(devicePublicKeyB64),
    issuedAtMs: ISSUED,
    expiresAtMs: EXPIRES,
  };
  const sig = signWithAccount(body, attacker.privateKey);
  const reg = new DeviceRegistrationV1({ ...body, sig });
  // Expect `account` (matches the body's claim) so it clears the anchor check
  // and fails on the SIGNATURE — proving the signer binding holds.
  const res = await verifyAs(reg, account);
  assert.equal(res.ok, false);
  assert.equal(res.reason, "signature invalid");
});

test("nowMs enforces the issued/expires window", async () => {
  const account = generateEd25519KeyPair();
  const device = generateEd25519KeyPair();
  const reg = makeRegistration({ account, device });

  assert.equal((await verifyAs(reg, account, ISSUED + 1000)).ok, true);

  const early = await verifyAs(reg, account, ISSUED - 1000);
  assert.equal(early.ok, false);
  assert.equal(early.reason, "not yet valid");

  const expired = await verifyAs(reg, account, EXPIRES + 1000);
  assert.equal(expired.ok, false);
  assert.equal(expired.reason, "expired");
});
