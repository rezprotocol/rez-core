import test from "node:test";
import assert from "node:assert/strict";
import {
  KeystoreStore,
  createKeystoreAccount,
  unlockKeystoreAccount,
  createKeystoreEnvelope,
  assertKeystoreEnvelope,
  KEYSTORE_ENVELOPE_VERSION,
} from "../src/keystore/index.js";
import { Identity } from "../src/identity/index.js";

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

test("assertKeystoreEnvelope rejects invalid shape", () => {
  assert.throws(() => assertKeystoreEnvelope(null), /must be an object/);
  assert.throws(() => assertKeystoreEnvelope({ version: 99 }), /Unsupported keystore envelope version/);
});

test("createKeystoreEnvelope returns valid envelope", () => {
  const envelope = createKeystoreEnvelope({
    kdfParams: { type: "pbkdf2-sha256", iterations: 210000, keyLength: 32 },
    saltB64: "dGVzdA==",
    ciphertextB64: "dGVzdA==",
    createdAtMs: 1,
    updatedAtMs: 1,
  });
  assert.equal(envelope.version, KEYSTORE_ENVELOPE_VERSION);
  assert.equal(envelope.saltB64, "dGVzdA==");
});

test("KeystoreStore hasKeystore/get/put/clear", async () => {
  const storage = createMemoryStorage();
  const store = new KeystoreStore({ storageProvider: storage, key: "k" });

  assert.equal(await store.hasKeystore(), false);
  assert.equal(await store.getKeystoreEnvelope(), null);

  const envelope = createKeystoreEnvelope({
    kdfParams: { type: "pbkdf2-sha256", iterations: 210000, keyLength: 32 },
    saltB64: "c2FsdA==",
    ciphertextB64: "Y2lwaA==",
    createdAtMs: 1,
    updatedAtMs: 1,
  });
  await store.putKeystoreEnvelope(envelope);
  assert.equal(await store.hasKeystore(), true);
  const got = await store.getKeystoreEnvelope();
  assert.equal(got.saltB64, "c2FsdA==");

  await store.clearKeystore();
  assert.equal(await store.hasKeystore(), false);
});

test("Identity accountId is deterministic", async () => {
  const identity = await Identity.generate({ cryptoProvider: globalThis.crypto });
  const obj = identity.toObject();
  const restored = Identity.fromObject(obj);
  assert.equal(restored.getAccountId(), identity.getAccountId());
});

test("createKeystoreAccount and unlockKeystoreAccount round-trip", async () => {
  const storage = createMemoryStorage();
  const store = new KeystoreStore({ storageProvider: storage, key: "acc" });

  const created = await createKeystoreAccount({
    password: "secret123",
    profileName: "Test",
    keystoreStore: store,
    cryptoProvider: globalThis.crypto,
  });
  assert.ok(created.accountId.startsWith("rez:acct:"));
  assert.ok(created.deviceId.startsWith("rez:dev:"));
  assert.equal(created.profileName, "Test");

  const unlocked = await unlockKeystoreAccount({
    password: "secret123",
    keystoreStore: store,
    cryptoProvider: globalThis.crypto,
  });
  assert.equal(unlocked.accountId, created.accountId);
  assert.equal(unlocked.deviceId, created.deviceId);
});

test("unlockKeystoreAccount fails on wrong password", async () => {
  const storage = createMemoryStorage();
  const store = new KeystoreStore({ storageProvider: storage, key: "wrong" });
  await createKeystoreAccount({
    password: "right",
    keystoreStore: store,
    cryptoProvider: globalThis.crypto,
  });
  await assert.rejects(
    () => unlockKeystoreAccount({ password: "wrong", keystoreStore: store, cryptoProvider: globalThis.crypto }),
    /decrypt|invalid|ciphertext|password|operation/i,
  );
});
