import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import { DeviceRegistrationV1 } from "../src/objects/device/DeviceRegistrationV1.js";
import { verifyDeviceRegistrationV1 } from "../src/objects/device/verifyDeviceRegistrationV1.js";

// Ed25519 verify provider matching the rez-core convention (raw 32-byte key →
// SPKI-wrapped), identical to the settlement-receipt tests.
const cryptoProvider = {
  async verify({ publicKey, msg, sig }) {
    const keyObj = crypto.createPublicKey({
      key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(publicKey)]),
      format: "der",
      type: "spki",
    });
    return crypto.verify(null, msg, keyObj, sig);
  },
};

function generateEd25519KeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    publicKey: new Uint8Array(publicKey.export({ format: "der", type: "spki" }).subarray(12)),
    privateKey: new Uint8Array(privateKey.export({ format: "der", type: "pkcs8" }).subarray(16)),
  };
}

function b64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

// Sign exactly as the SDK device-registration signer will: Ed25519 (account
// identity key) over DeviceRegistrationV1.signableBytes(body).
function signWithAccount(body, accountPrivateKey) {
  const keyObj = crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(accountPrivateKey)]),
    format: "der",
    type: "pkcs8",
  });
  const bytes = DeviceRegistrationV1.signableBytes(body);
  const sig = new Uint8Array(crypto.sign(null, bytes, keyObj));
  return { alg: "ed25519", sig };
}

const ISSUED = 1_700_000_000_000;
const EXPIRES = ISSUED + 30 * 24 * 60 * 60 * 1000; // 30 days

function makeRegistration({ account, device, overrides = {} } = {}) {
  const accountIdentityPublicKeyB64 = b64(account.publicKey);
  const devicePublicKeyB64 = b64(device.publicKey);
  const body = {
    v: 1,
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

test("the constructor refuses a deviceId that does not match the device key", () => {
  const account = generateEd25519KeyPair();
  const device = generateEd25519KeyPair();
  const accountIdentityPublicKeyB64 = b64(account.publicKey);
  const devicePublicKeyB64 = b64(device.publicKey);
  const body = {
    v: 1,
    accountIdentityPublicKeyB64,
    devicePublicKeyB64,
    deviceId: "rez:dev:" + "0".repeat(64), // wrong id
    issuedAtMs: ISSUED,
    expiresAtMs: EXPIRES,
  };
  const sig = signWithAccount(body, account.privateKey);
  assert.throws(() => new DeviceRegistrationV1({ ...body, sig }), /deviceId must equal/);
});

test("a correctly account-signed registration verifies and echoes the deviceId", async () => {
  const account = generateEd25519KeyPair();
  const device = generateEd25519KeyPair();
  const reg = makeRegistration({ account, device });
  const res = await verifyDeviceRegistrationV1({ registration: reg, crypto: cryptoProvider });
  assert.equal(res.ok, true, res.reason);
  assert.equal(res.deviceId, reg.deviceId);
});

test("round-trips through toJSON/fromJSON and still verifies", async () => {
  const account = generateEd25519KeyPair();
  const device = generateEd25519KeyPair();
  const reg = makeRegistration({ account, device });
  const back = DeviceRegistrationV1.fromJSON(reg.toJSON());
  assert.equal(back.deviceId, reg.deviceId);
  assert.equal(back.accountIdentityPublicKeyB64, reg.accountIdentityPublicKeyB64);
  const res = await verifyDeviceRegistrationV1({ registration: back, crypto: cryptoProvider });
  assert.equal(res.ok, true, res.reason);
});

test("tampering the signed body (expiresAtMs) fails verification", async () => {
  const account = generateEd25519KeyPair();
  const device = generateEd25519KeyPair();
  const reg = makeRegistration({ account, device });
  const tampered = reg.toJSON();
  tampered.expiresAtMs = EXPIRES + 365 * 24 * 60 * 60 * 1000; // extend lifetime, no re-sign
  const res = await verifyDeviceRegistrationV1({ registration: tampered, crypto: cryptoProvider });
  assert.equal(res.ok, false);
  assert.equal(res.reason, "signature invalid");
});

test("a deviceId/device-key mismatch in raw JSON is rejected before signature check", async () => {
  const account = generateEd25519KeyPair();
  const device = generateEd25519KeyPair();
  const reg = makeRegistration({ account, device });
  const swapped = reg.toJSON();
  swapped.devicePublicKeyB64 = b64(generateEd25519KeyPair().publicKey); // different device, stale id
  const res = await verifyDeviceRegistrationV1({ registration: swapped, crypto: cryptoProvider });
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
    accountIdentityPublicKeyB64,
    devicePublicKeyB64,
    deviceId: DeviceRegistrationV1.deviceIdFor(devicePublicKeyB64),
    issuedAtMs: ISSUED,
    expiresAtMs: EXPIRES,
  };
  const sig = signWithAccount(body, attacker.privateKey);
  const reg = new DeviceRegistrationV1({ ...body, sig });
  const res = await verifyDeviceRegistrationV1({ registration: reg, crypto: cryptoProvider });
  assert.equal(res.ok, false);
  assert.equal(res.reason, "signature invalid");
});

test("nowMs enforces the issued/expires window", async () => {
  const account = generateEd25519KeyPair();
  const device = generateEd25519KeyPair();
  const reg = makeRegistration({ account, device });

  const valid = await verifyDeviceRegistrationV1({ registration: reg, crypto: cryptoProvider, nowMs: ISSUED + 1000 });
  assert.equal(valid.ok, true, valid.reason);

  const early = await verifyDeviceRegistrationV1({ registration: reg, crypto: cryptoProvider, nowMs: ISSUED - 1000 });
  assert.equal(early.ok, false);
  assert.equal(early.reason, "not yet valid");

  const expired = await verifyDeviceRegistrationV1({ registration: reg, crypto: cryptoProvider, nowMs: EXPIRES + 1000 });
  assert.equal(expired.ok, false);
  assert.equal(expired.reason, "expired");
});
