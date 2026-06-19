import test from "node:test";
import assert from "node:assert/strict";

import {
  KeystoreStore,
  createKeystoreAccount,
  unlockKeystoreAccount,
  createKeystoreEnvelope,
  getDefaultKdfParams,
  deriveUnlockKey,
  encryptKeystore,
  decryptKeystore,
  toBase64,
  randomBytes,
} from "../src/keystore/index.js";
import { Identity } from "../src/identity/index.js";
import { DeviceRegistrationV1 } from "../src/objects/device/DeviceRegistrationV1.js";

const CRYPTO = globalThis.crypto;

function createMemoryStorage() {
  const map = new Map();
  return {
    get(key) {
      return map.has(key) ? map.get(key) : null;
    },
    put(key, value) {
      map.set(key, value);
    },
    del(key) {
      map.delete(key);
    },
  };
}

// Hand-build a v1 keystore envelope (the pre-device-key payload shape: random
// unsigned deviceId, NO device key) so the lazy v1→v2 migration can be exercised.
async function writeV1Keystore({ store, password, identity, deviceId, profileName = "Legacy", now = Date.now() }) {
  const v1Payload = {
    keystoreVersion: 1,
    createdAtMs: now,
    updatedAtMs: now,
    identity: identity.toObject(),
    accountId: identity.getAccountId(),
    deviceId,
    profileName,
  };
  const saltBytes = randomBytes(16, CRYPTO);
  const kdfParams = getDefaultKdfParams(CRYPTO);
  const unlockKeyBytes = await deriveUnlockKey({ password, saltBytes, kdfParams, cryptoProvider: CRYPTO });
  const plaintextJsonBytes = new TextEncoder().encode(JSON.stringify(v1Payload));
  const { ciphertextBytes } = await encryptKeystore({ unlockKeyBytes, plaintextJsonBytes, cryptoProvider: CRYPTO });
  const envelope = createKeystoreEnvelope({
    kdfParams,
    saltB64: toBase64(saltBytes),
    ciphertextB64: toBase64(ciphertextBytes),
    createdAtMs: now,
    updatedAtMs: now,
  });
  await store.putKeystoreEnvelope(envelope);
}

// Decrypt the persisted envelope back to its payload JSON (to assert what was
// actually written to disk after a migration).
async function readStoredPayload({ store, password }) {
  const envelope = await store.getKeystoreEnvelope();
  const saltBytes = Uint8Array.from(Buffer.from(envelope.saltB64, "base64"));
  const unlockKeyBytes = await deriveUnlockKey({ password, saltBytes, kdfParams: envelope.kdfParams, cryptoProvider: CRYPTO });
  const plaintextBytes = await decryptKeystore({ unlockKeyBytes, envelope, cryptoProvider: CRYPTO });
  return JSON.parse(new TextDecoder().decode(plaintextBytes));
}

test("createKeystoreAccount mints a device key and a self-certifying deviceId (v2)", async () => {
  const store = new KeystoreStore({ storageProvider: createMemoryStorage(), key: "a" });
  const created = await createKeystoreAccount({ password: "pw", profileName: "Z", keystoreStore: store, cryptoProvider: CRYPTO });

  // deviceId is bound to the device key, not a random string.
  assert.match(created.deviceId, /^rez:dev:[0-9a-f]{64}$/);
  assert.equal(created.deviceId, DeviceRegistrationV1.deviceIdFor(created.deviceKeyPublicKeyB64));

  const unlocked = await unlockKeystoreAccount({ password: "pw", keystoreStore: store, cryptoProvider: CRYPTO });
  assert.equal(unlocked.deviceId, created.deviceId);
  // Unlock exposes the persisted device keypair for downstream signing.
  assert.equal(typeof unlocked.deviceKeyPair.publicKeyB64, "string");
  assert.equal(typeof unlocked.deviceKeyPair.privateKeyB64, "string");
  assert.ok(unlocked.deviceKeyPair.publicKeyB64.length > 0);
  assert.ok(unlocked.deviceKeyPair.privateKeyB64.length > 0);
  assert.equal(unlocked.deviceKeyPair.publicKeyB64, created.deviceKeyPublicKeyB64);
});

test("device public key is canonical 44-byte Ed25519 SPKI", async () => {
  const store = new KeystoreStore({ storageProvider: createMemoryStorage(), key: "b" });
  const created = await createKeystoreAccount({ password: "pw", keystoreStore: store, cryptoProvider: CRYPTO });
  const der = Buffer.from(created.deviceKeyPublicKeyB64, "base64");
  assert.equal(der.length, 44, "Ed25519 SPKI DER is 44 bytes");
  assert.equal(der.subarray(0, 12).toString("hex"), "302a300506032b6570032100", "Ed25519 SPKI prefix");
});

test("device key is device-local: distinct from the account identity, and NOT seed-recoverable", async () => {
  // Inject a recoverable account identity (the BIP39-rooted path). The device key
  // must STILL be freshly random, never derived from the account identity.
  const recoverableIdentity = await Identity.generate({ cryptoProvider: CRYPTO });
  const store = new KeystoreStore({ storageProvider: createMemoryStorage(), key: "c" });
  const created = await createKeystoreAccount({
    password: "pw",
    keystoreStore: store,
    cryptoProvider: CRYPTO,
    identity: recoverableIdentity,
  });
  assert.notEqual(created.deviceKeyPublicKeyB64, created.identityPublicKey);
  assert.notEqual(created.deviceKeyPublicKeyB64, recoverableIdentity.toObject().publicKeyB64);

  // A second account gets a wholly distinct device key + deviceId.
  const store2 = new KeystoreStore({ storageProvider: createMemoryStorage(), key: "c2" });
  const created2 = await createKeystoreAccount({ password: "pw", keystoreStore: store2, cryptoProvider: CRYPTO });
  assert.notEqual(created2.deviceKeyPublicKeyB64, created.deviceKeyPublicKeyB64);
  assert.notEqual(created2.deviceId, created.deviceId);
});

test("a v1 keystore lazily upgrades to v2 on unlock — self-certifying deviceId, re-sealed in place", async () => {
  const store = new KeystoreStore({ storageProvider: createMemoryStorage(), key: "d" });
  const identity = await Identity.generate({ cryptoProvider: CRYPTO });
  const legacyDeviceId = "rez:dev:LEGACYrandomBase64UrlId";
  await writeV1Keystore({ store, password: "pw", identity, deviceId: legacyDeviceId });

  const unlocked = await unlockKeystoreAccount({ password: "pw", keystoreStore: store, cryptoProvider: CRYPTO });
  // Same account, but the legacy random deviceId is discarded for a self-cert one.
  assert.equal(unlocked.accountId, identity.getAccountId());
  assert.notEqual(unlocked.deviceId, legacyDeviceId);
  assert.match(unlocked.deviceId, /^rez:dev:[0-9a-f]{64}$/);
  assert.equal(unlocked.deviceId, DeviceRegistrationV1.deviceIdFor(unlocked.deviceKeyPair.publicKeyB64));

  // The upgrade was persisted (re-sealed to v2 on disk).
  const stored = await readStoredPayload({ store, password: "pw" });
  assert.equal(stored.keystoreVersion, 2);
  assert.equal(stored.deviceKey.publicKeyB64, unlocked.deviceKeyPair.publicKeyB64);

  // Idempotent: a second unlock reads v2 directly and returns the SAME deviceId
  // (no re-migration / no device-key churn).
  const again = await unlockKeystoreAccount({ password: "pw", keystoreStore: store, cryptoProvider: CRYPTO });
  assert.equal(again.deviceId, unlocked.deviceId);
  assert.equal(again.deviceKeyPair.publicKeyB64, unlocked.deviceKeyPair.publicKeyB64);
});

test("v1 migration preserves the anti-tamper accountId check", async () => {
  const store = new KeystoreStore({ storageProvider: createMemoryStorage(), key: "e" });
  const identity = await Identity.generate({ cryptoProvider: CRYPTO });
  // Persist a v1 payload whose accountId does NOT match its identity key.
  const now = Date.now();
  const tampered = {
    keystoreVersion: 1,
    createdAtMs: now,
    updatedAtMs: now,
    identity: identity.toObject(),
    accountId: "rez:acct:NOTtheRightFingerprint",
    deviceId: "rez:dev:whatever",
    profileName: "T",
  };
  const saltBytes = randomBytes(16, CRYPTO);
  const kdfParams = getDefaultKdfParams(CRYPTO);
  const unlockKeyBytes = await deriveUnlockKey({ password: "pw", saltBytes, kdfParams, cryptoProvider: CRYPTO });
  const plaintextJsonBytes = new TextEncoder().encode(JSON.stringify(tampered));
  const { ciphertextBytes } = await encryptKeystore({ unlockKeyBytes, plaintextJsonBytes, cryptoProvider: CRYPTO });
  await store.putKeystoreEnvelope(createKeystoreEnvelope({
    kdfParams,
    saltB64: toBase64(saltBytes),
    ciphertextB64: toBase64(ciphertextBytes),
    createdAtMs: now,
    updatedAtMs: now,
  }));

  await assert.rejects(
    () => unlockKeystoreAccount({ password: "pw", keystoreStore: store, cryptoProvider: CRYPTO }),
    /accountId mismatch|tamper/i,
  );
});
