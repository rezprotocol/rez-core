import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  DeviceRegistrationV1,
  DeviceInboxBindingV1,
  DeviceSetRecordV1,
  DeviceLinkRequestV1,
  DeviceLinkRequestV2,
  DEVICE_LINK_REQUEST_V2_VERSION,
  DEVICE_LINK_REQUEST_V2_PURPOSE,
  DevicePrekeyBundleV1,
} from "../src/objects/device/index.js";

// Ed25519 keypair: SPKI public (b64, the encoding the records pin) + a node
// KeyObject private for signing.
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
function rawKeyB64() {
  // A raw-32 Ed25519 key (canonical base64 but not SPKI) — must be rejected.
  return Buffer.from(crypto.randomBytes(32)).toString("base64");
}

const ISSUED = 1_700_000_000_000;
const EXPIRES = ISSUED + 30 * 24 * 60 * 60 * 1000;

// --- DeviceInboxBindingV1 (device-signed) ---

function makeBinding({ device, inboxId = "rez:inbox:abc", overrides = {} } = {}) {
  const body = {
    v: 1,
    purpose: "rez:device-inbox-binding:v1",
    devicePublicKeyB64: device.publicKeyB64,
    deviceId: deviceId(device.publicKeyB64),
    inboxId,
    issuedAtMs: ISSUED,
    expiresAtMs: EXPIRES,
    ...overrides,
  };
  const sig = sign(device.privateKey, DeviceInboxBindingV1.signableBytes(body));
  return new DeviceInboxBindingV1({ ...body, sig });
}

test("DeviceInboxBindingV1: device-signed binding constructs, verifies, round-trips", () => {
  const device = genKey();
  const rec = makeBinding({ device });
  assert.equal(rec.inboxId, "rez:inbox:abc");
  assert.equal(rec.deviceId, deviceId(device.publicKeyB64));
  assert.ok(verify(device.publicKeyB64, DeviceInboxBindingV1.signableBytes(rec.toJSON()), rec.sig), "device signature verifies over signableBytes");
  const back = DeviceInboxBindingV1.fromJSON(rec.toJSON());
  assert.equal(back.inboxId, rec.inboxId);
  assert.ok(verify(device.publicKeyB64, DeviceInboxBindingV1.signableBytes(back.toJSON()), back.sig));
});

test("DeviceInboxBindingV1: rejects deviceId/key mismatch, raw-32 key, blank inbox, bad sig", () => {
  const device = genKey();
  assert.throws(() => makeBinding({ device, overrides: { deviceId: "rez:dev:" + "0".repeat(64) } }), /must equal rez:dev:sha256/);
  assert.throws(() => makeBinding({ device, overrides: { devicePublicKeyB64: rawKeyB64() } }), /44-byte|deviceId|SPKI/);
  assert.throws(() => makeBinding({ device, inboxId: "" }), /inboxId/);
  assert.throws(() => new DeviceInboxBindingV1({
    v: 1, purpose: "rez:device-inbox-binding:v1", devicePublicKeyB64: device.publicKeyB64,
    deviceId: deviceId(device.publicKeyB64), inboxId: "x", issuedAtMs: ISSUED, expiresAtMs: EXPIRES,
    sig: { alg: "nacl", sigB64: "AAAA" },
  }), /alg must be "ed25519"/);
});

// --- DeviceSetRecordV1 (account-signed) ---

function makeDeviceSet({ account, devices, revision = 1, overrides = {} } = {}) {
  const entries = devices.map((d, i) => ({
    deviceId: deviceId(d.publicKeyB64),
    devicePublicKeyB64: d.publicKeyB64,
    inboxId: "rez:inbox:dev" + i,
  }));
  const body = {
    v: 1,
    purpose: "rez:device-set:v1",
    accountIdentityPublicKeyB64: account.publicKeyB64,
    revision,
    devices: entries,
    issuedAtMs: ISSUED,
    expiresAtMs: EXPIRES,
    ...overrides,
  };
  const sig = sign(account.privateKey, DeviceSetRecordV1.signableBytes(body));
  return new DeviceSetRecordV1({ ...body, sig });
}

test("DeviceSetRecordV1: account-signed multi-device set constructs, verifies, round-trips", () => {
  const account = genKey();
  const devices = [genKey(), genKey()];
  const rec = makeDeviceSet({ account, devices });
  assert.equal(rec.devices.length, 2);
  assert.equal(rec.revision, 1);
  assert.ok(verify(account.publicKeyB64, DeviceSetRecordV1.signableBytes(rec.toJSON()), rec.sig));
  const back = DeviceSetRecordV1.fromJSON(rec.toJSON());
  assert.equal(back.devices.length, 2);
  assert.ok(verify(account.publicKeyB64, DeviceSetRecordV1.signableBytes(back.toJSON()), back.sig));
});

test("DeviceSetRecordV1: rejects duplicate devices, bad revision, entry self-cert mismatch, empty set", () => {
  const account = genKey();
  const d = genKey();
  assert.throws(() => makeDeviceSet({ account, devices: [d, d] }), /duplicated/);
  assert.throws(() => makeDeviceSet({ account, devices: [genKey()], revision: 0 }), /positive integer/);
  assert.throws(() => makeDeviceSet({ account, devices: [genKey()], revision: 1.5 }), /positive integer/);
  assert.throws(() => makeDeviceSet({ account, devices: [genKey()], overrides: {
    devices: [{ deviceId: "rez:dev:" + "0".repeat(64), devicePublicKeyB64: genKey().publicKeyB64, inboxId: "rez:inbox:x" }],
  } }), /must equal rez:dev:sha256/);
  assert.throws(() => makeDeviceSet({ account, devices: [genKey()], overrides: { devices: [] } }), /non-empty array/);
});

// --- DeviceLinkRequestV1 (FROZEN) / DeviceLinkRequestV2 (produced) ---
// Two builders on purpose. V1's signed body must not contain deviceInboxBinding — that is the
// field whose unversioned addition audit #5 found — so a V1 fixture that quietly carried it would
// defeat the point of freezing the schema.

function makeLinkRequest({ account, newDevice, nonceB64 = Buffer.from(crypto.randomBytes(32)).toString("base64"), overrides = {} } = {}) {
  const body = {
    v: 1,
    purpose: "rez:device-link-request:v1",
    accountIdentityPublicKeyB64: account.publicKeyB64,
    newDevicePublicKeyB64: newDevice.publicKeyB64,
    newDeviceId: deviceId(newDevice.publicKeyB64),
    ceremonyNonceB64: nonceB64,
    issuedAtMs: ISSUED,
    expiresAtMs: EXPIRES,
    ...overrides,
  };
  const sig = sign(newDevice.privateKey, DeviceLinkRequestV1.signableBytes(body));
  return new DeviceLinkRequestV1({ ...body, sig });
}

function makeLinkRequestV2({ account, newDevice, nonceB64 = Buffer.from(crypto.randomBytes(32)).toString("base64"), overrides = {} } = {}) {
  const body = {
    v: DEVICE_LINK_REQUEST_V2_VERSION,
    purpose: DEVICE_LINK_REQUEST_V2_PURPOSE,
    accountIdentityPublicKeyB64: account.publicKeyB64,
    newDevicePublicKeyB64: newDevice.publicKeyB64,
    newDeviceId: deviceId(newDevice.publicKeyB64),
    // P1#2: the new device's own device-signed inbox binding (registration-before-release).
    deviceInboxBinding: makeBinding({ device: newDevice, inboxId: "rez:inbox:link" }).toJSON(),
    ceremonyNonceB64: nonceB64,
    issuedAtMs: ISSUED,
    expiresAtMs: EXPIRES,
    ...overrides,
  };
  const sig = sign(newDevice.privateKey, DeviceLinkRequestV2.signableBytes(body));
  return new DeviceLinkRequestV2({ ...body, sig });
}

test("DeviceLinkRequestV1: new-device-signed request constructs, verifies, round-trips", () => {
  const account = genKey();
  const newDevice = genKey();
  const rec = makeLinkRequest({ account, newDevice });
  assert.equal(rec.newDeviceId, deviceId(newDevice.publicKeyB64));
  // Signed by the NEW DEVICE key (proves control of the device being linked).
  assert.ok(verify(newDevice.publicKeyB64, DeviceLinkRequestV1.signableBytes(rec.toJSON()), rec.sig));
  const back = DeviceLinkRequestV1.fromJSON(rec.toJSON());
  assert.equal(back.ceremonyNonceB64, rec.ceremonyNonceB64);
});

test("DeviceLinkRequestV1: rejects newDeviceId mismatch and a missing ceremony nonce", () => {
  const account = genKey();
  const newDevice = genKey();
  assert.throws(() => makeLinkRequest({ account, newDevice, overrides: { newDeviceId: "rez:dev:" + "0".repeat(64) } }), /must equal rez:dev:sha256/);
  assert.throws(() => makeLinkRequest({ account, newDevice, nonceB64: "" }), /ceremonyNonceB64/);
  // S10 pin: the nonce is the PSK-derived 256-bit ceremony binding.
  assert.throws(() => makeLinkRequest({ account, newDevice, nonceB64: Buffer.from("short").toString("base64") }), /must decode to 32 bytes/);
});

test("DeviceLinkRequestV2: carries the device-signed inbox binding; a foreign-device binding is rejected", () => {
  const account = genKey();
  const newDevice = genKey();
  const rec = makeLinkRequestV2({ account, newDevice });
  assert.equal(rec.deviceInboxBinding.deviceId, deviceId(newDevice.publicKeyB64), "binding is for the linked device");
  assert.equal(rec.deviceInboxBinding.inboxId, "rez:inbox:link");
  // A binding minted by a DIFFERENT device is rejected (must match newDeviceId).
  const other = genKey();
  assert.throws(
    () => makeLinkRequestV2({ account, newDevice, overrides: { deviceInboxBinding: makeBinding({ device: other }).toJSON() } }),
    /must equal newDeviceId/,
  );
  // A missing binding is rejected.
  assert.throws(
    () => makeLinkRequestV2({ account, newDevice, overrides: { deviceInboxBinding: undefined } }),
    /deviceInboxBinding is invalid/,
  );
});

// --- DevicePrekeyBundleV1 (device-signed) ---

// A canonical base64 string of `n` random bytes — stands in for the X3DH
// sub-keys whose internal signatures are verified at session establishment, not
// here. (deviceB64 is a real 44-byte Ed25519 SPKI, used as the X25519-shaped
// fields' shape too — only canonical-base64 is required of them.)
function b64(n) {
  return Buffer.from(crypto.randomBytes(n)).toString("base64");
}

function makeBundleJson(devicePublicKeyB64, overrides = {}) {
  return {
    receiverId: "rez:acct:peer",
    identitySigningPublicKeyB64: devicePublicKeyB64, // = device key C
    identityDhPublicKeyB64: b64(44),
    identityDhSignatureB64: b64(64),
    signedPreKeyPublicB64: b64(44),
    signedPreKeySignatureB64: b64(64),
    accountIdentityPublicKeyB64: null,
    accountBindingSigB64: null,
    accountBindingIssuedAtMs: null,
    accountBindingExpiresAtMs: null,
    oneTimePreKeyPublicB64: b64(44),
    ...overrides,
  };
}

function makePrekeyBundle({ account, device, inboxId = "rez:inbox:dev", prekeyVersion = 1, bundleOverrides = {}, overrides = {} } = {}) {
  const body = {
    v: 1,
    purpose: "rez:device-prekey-bundle:v1",
    accountIdentityPublicKeyB64: account.publicKeyB64,
    devicePublicKeyB64: device.publicKeyB64,
    deviceId: deviceId(device.publicKeyB64),
    inboxId,
    prekeyVersion,
    bundleJson: makeBundleJson(device.publicKeyB64, bundleOverrides),
    issuedAtMs: ISSUED,
    expiresAtMs: EXPIRES,
    ...overrides,
  };
  // Signed by the DEVICE key (C) — the device signs its own prekeys.
  const sig = sign(device.privateKey, DevicePrekeyBundleV1.signableBytes(body));
  return new DevicePrekeyBundleV1({ ...body, sig });
}

test("DevicePrekeyBundleV1: device-signed bundle constructs, verifies, round-trips", () => {
  const account = genKey();
  const device = genKey();
  const rec = makePrekeyBundle({ account, device });
  assert.equal(rec.deviceId, deviceId(device.publicKeyB64));
  assert.equal(rec.bundleJson.identitySigningPublicKeyB64, device.publicKeyB64);
  // Signed by the device key C; verifier recomputes the canonical body.
  assert.ok(verify(device.publicKeyB64, DevicePrekeyBundleV1.signableBytes(rec.toJSON()), rec.sig));
  const back = DevicePrekeyBundleV1.fromJSON(rec.toJSON());
  assert.equal(back.prekeyVersion, rec.prekeyVersion);
  assert.deepEqual(back.bundleJson, rec.bundleJson);
});

test("DevicePrekeyBundleV1: rejects a bundle whose signing identity is NOT the bound device key (anti-substitution)", () => {
  const account = genKey();
  const device = genKey();
  const other = genKey();
  assert.throws(
    () => makePrekeyBundle({ account, device, bundleOverrides: { identitySigningPublicKeyB64: other.publicKeyB64 } }),
    /bundleJson.identitySigningPublicKeyB64 must equal the bound device key/,
  );
});

test("DevicePrekeyBundleV1: rejects deviceId mismatch, non-positive prekeyVersion, and a malformed bundle field", () => {
  const account = genKey();
  const device = genKey();
  assert.throws(() => makePrekeyBundle({ account, device, overrides: { deviceId: "rez:dev:" + "0".repeat(64) } }), /must equal rez:dev:sha256/);
  assert.throws(() => makePrekeyBundle({ account, device, prekeyVersion: 0 }), /prekeyVersion must be a positive integer/);
  assert.throws(() => makePrekeyBundle({ account, device, bundleOverrides: { identityDhPublicKeyB64: "not base64!!" } }), /identityDhPublicKeyB64/);
});

test("DevicePrekeyBundleV1: tamper with the signed body breaks verification", () => {
  const account = genKey();
  const device = genKey();
  const rec = makePrekeyBundle({ account, device });
  const tampered = { ...rec.toJSON(), inboxId: "rez:inbox:evil" };
  assert.equal(verify(device.publicKeyB64, DevicePrekeyBundleV1.signableBytes(tampered), rec.sig), false);
});
