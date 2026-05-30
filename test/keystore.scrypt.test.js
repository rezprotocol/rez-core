/**
 * Tests for scrypt KDF support in KeystoreEnvelope, keystoreCrypto, and KeystoreAccount.
 * Uses Node.js native crypto.scrypt as the mock bridge (simulates the Electron IPC path).
 */
import test from "node:test";
import assert from "node:assert/strict";
import { scrypt } from "node:crypto";
import { promisify } from "node:util";

import {
  normalizeKdfParams,
  assertKeystoreEnvelope,
  createKeystoreEnvelope,
  KEYSTORE_ENVELOPE_VERSION,
} from "../src/keystore/KeystoreEnvelope.js";
import {
  getDefaultKdfParams,
  deriveUnlockKey,
} from "../src/keystore/keystoreCrypto.js";
import {
  KeystoreStore,
  createKeystoreAccount,
  unlockKeystoreAccount,
} from "../src/keystore/index.js";

const scryptAsync = promisify(scrypt);

// Use small N for test speed (N=1024 → 128 KiB memory; well within Node.js defaults).
const TEST_SCRYPT_PARAMS = { type: "scrypt", N: 1024, r: 8, p: 1, keyLength: 32 };

/**
 * Creates a mock cryptoProvider with a real scrypt bridge (via Node.js native crypto).
 * Simulates what the Electron IPC bridge provides at N=1024 for fast tests.
 *
 * NOTE: globalThis.crypto properties (subtle, getRandomValues) are non-enumerable getters
 * and are NOT copied by object spread. We must pass `crypto: globalThis.crypto` explicitly
 * so resolveCrypto() can reach subtle and getRandomValues via provider.crypto.
 */
function createMockScryptProvider() {
  return {
    crypto: globalThis.crypto,
    subtle: globalThis.crypto.subtle,
    getRandomValues: (buf) => globalThis.crypto.getRandomValues(buf),
    scrypt: async ({ password, salt, N, r, p, keyLen }) => {
      const maxmem = 2 * 128 * N * r;
      const keyBuffer = await scryptAsync(
        password,
        Buffer.from(salt),
        keyLen,
        { N, r, p, maxmem },
      );
      return new Uint8Array(keyBuffer);
    },
  };
}

function createMemoryStorage() {
  const map = new Map();
  return {
    get(key) { return map.has(key) ? map.get(key) : null; },
    put(key, value) { map.set(key, value); },
    del(key) { map.delete(key); },
  };
}

// ─── normalizeKdfParams: scrypt type ─────────────────────────────────────────

test("normalizeKdfParams accepts valid scrypt params", () => {
  const result = normalizeKdfParams({ type: "scrypt", N: 131072, r: 8, p: 1, keyLength: 32 });
  assert.equal(result.type, "scrypt");
  assert.equal(result.N, 131072);
  assert.equal(result.r, 8);
  assert.equal(result.p, 1);
  assert.equal(result.keyLength, 32);
});

test("normalizeKdfParams rejects non-power-of-two N", () => {
  assert.throws(
    () => normalizeKdfParams({ type: "scrypt", N: 65535, r: 8, p: 1, keyLength: 32 }),
    /Invalid scrypt N/,
  );
});

test("normalizeKdfParams rejects N below 1024", () => {
  assert.throws(
    () => normalizeKdfParams({ type: "scrypt", N: 512, r: 8, p: 1, keyLength: 32 }),
    /Invalid scrypt N/,
  );
});

test("normalizeKdfParams rejects invalid r", () => {
  assert.throws(
    () => normalizeKdfParams({ type: "scrypt", N: 1024, r: 0, p: 1, keyLength: 32 }),
    /Invalid scrypt r/,
  );
});

test("normalizeKdfParams rejects invalid p", () => {
  assert.throws(
    () => normalizeKdfParams({ type: "scrypt", N: 1024, r: 8, p: 0, keyLength: 32 }),
    /Invalid scrypt p/,
  );
});

test("normalizeKdfParams rejects invalid keyLength for scrypt", () => {
  assert.throws(
    () => normalizeKdfParams({ type: "scrypt", N: 1024, r: 8, p: 1, keyLength: 8 }),
    /Invalid keystore KDF keyLength/,
  );
});

// ─── createKeystoreEnvelope: accepts scrypt kdfParams ────────────────────────

test("createKeystoreEnvelope accepts scrypt kdfParams", () => {
  const envelope = createKeystoreEnvelope({
    kdfParams: TEST_SCRYPT_PARAMS,
    saltB64: "dGVzdHNhbHQ=",
    ciphertextB64: "dGVzdGNpcGhlcnRleHQ=",
    createdAtMs: 1_700_000_000_000,
    updatedAtMs: 1_700_000_000_000,
  });
  assert.equal(envelope.version, KEYSTORE_ENVELOPE_VERSION);
  assert.equal(envelope.kdfParams.type, "scrypt");
  assert.equal(envelope.kdfParams.N, 1024);
});

test("assertKeystoreEnvelope accepts scrypt kdfParams", () => {
  const result = assertKeystoreEnvelope({
    version: 1,
    kdfParams: { type: "scrypt", N: 131072, r: 8, p: 1, keyLength: 32 },
    saltB64: "c2FsdA==",
    ciphertextB64: "Y2lwaA==",
    createdAtMs: 1,
    updatedAtMs: 1,
  });
  assert.equal(result.kdfParams.type, "scrypt");
  assert.equal(result.kdfParams.N, 131072);
});

// ─── getDefaultKdfParams: scrypt dispatch ────────────────────────────────────

test("getDefaultKdfParams returns pbkdf2 when no cryptoProvider", () => {
  const params = getDefaultKdfParams();
  assert.equal(params.type, "pbkdf2-sha256");
  assert.ok(params.iterations >= 100000);
});

test("getDefaultKdfParams returns pbkdf2 when cryptoProvider has no scrypt", () => {
  const params = getDefaultKdfParams(globalThis.crypto);
  assert.equal(params.type, "pbkdf2-sha256");
});

test("getDefaultKdfParams returns scrypt when cryptoProvider.scrypt is a function", () => {
  const provider = createMockScryptProvider();
  const params = getDefaultKdfParams(provider);
  assert.equal(params.type, "scrypt");
  assert.equal(params.N, 131072); // default is 2^17
  assert.equal(params.r, 8);
});

// ─── deriveUnlockKey: scrypt dispatch ────────────────────────────────────────

test("deriveUnlockKey dispatches to cryptoProvider.scrypt when params.type === scrypt", async () => {
  const provider = createMockScryptProvider();
  const salt = new Uint8Array(16).fill(1);

  const key = await deriveUnlockKey({
    password: "test-password",
    saltBytes: salt,
    kdfParams: TEST_SCRYPT_PARAMS,
    cryptoProvider: provider,
  });

  assert.ok(key instanceof Uint8Array, "should return Uint8Array");
  assert.equal(key.length, 32);
});

test("deriveUnlockKey scrypt is deterministic for same inputs", async () => {
  const provider = createMockScryptProvider();
  const salt = new Uint8Array(16).fill(7);

  const key1 = await deriveUnlockKey({
    password: "same-password",
    saltBytes: salt,
    kdfParams: TEST_SCRYPT_PARAMS,
    cryptoProvider: provider,
  });
  const key2 = await deriveUnlockKey({
    password: "same-password",
    saltBytes: salt,
    kdfParams: TEST_SCRYPT_PARAMS,
    cryptoProvider: provider,
  });

  assert.deepEqual(key1, key2, "same inputs should produce same key");
});

test("deriveUnlockKey scrypt produces different keys for different passwords", async () => {
  const provider = createMockScryptProvider();
  const salt = new Uint8Array(16).fill(3);

  const key1 = await deriveUnlockKey({
    password: "password-one",
    saltBytes: salt,
    kdfParams: TEST_SCRYPT_PARAMS,
    cryptoProvider: provider,
  });
  const key2 = await deriveUnlockKey({
    password: "password-two",
    saltBytes: salt,
    kdfParams: TEST_SCRYPT_PARAMS,
    cryptoProvider: provider,
  });

  let diff = false;
  for (let i = 0; i < key1.length; i++) {
    if (key1[i] !== key2[i]) { diff = true; break; }
  }
  assert.ok(diff, "different passwords should produce different keys");
});

test("deriveUnlockKey throws when params.type === scrypt and cryptoProvider.scrypt missing", async () => {
  const salt = new Uint8Array(16).fill(1);
  await assert.rejects(
    () => deriveUnlockKey({
      password: "password",
      saltBytes: salt,
      kdfParams: TEST_SCRYPT_PARAMS,
      cryptoProvider: globalThis.crypto, // no .scrypt on browser WebCrypto
    }),
    /scrypt KDF requires a native scrypt bridge/,
  );
});

test("deriveUnlockKey uses PBKDF2 when params.type === pbkdf2-sha256 even if scrypt present", async () => {
  const provider = createMockScryptProvider();
  let scryptCalled = false;
  const spy = {
    crypto: globalThis.crypto,
    subtle: globalThis.crypto.subtle,
    getRandomValues: (buf) => globalThis.crypto.getRandomValues(buf),
    scrypt: async (opts) => {
      scryptCalled = true;
      return provider.scrypt(opts);
    },
  };
  const salt = new Uint8Array(16).fill(5);

  await deriveUnlockKey({
    password: "password",
    saltBytes: salt,
    kdfParams: { type: "pbkdf2-sha256", iterations: 100000, keyLength: 32 },
    cryptoProvider: spy,
  });

  assert.equal(scryptCalled, false, "scrypt should not be called for PBKDF2 params");
});

// ─── End-to-end: create + unlock with scrypt ─────────────────────────────────

test("createKeystoreAccount uses scrypt when provider.scrypt available, unlockKeystoreAccount decrypts", async () => {
  const provider = createMockScryptProvider();
  const storage = createMemoryStorage();
  const store = new KeystoreStore({ storageProvider: storage, key: "scrypt-acc" });

  const created = await createKeystoreAccount({
    password: "strong-passphrase",
    profileName: "ScryptUser",
    keystoreStore: store,
    cryptoProvider: provider,
  });

  assert.ok(created.accountId.startsWith("rez:acct:"));

  // Verify envelope uses scrypt kdfParams with OWASP default N=2^17
  const envelope = await store.getKeystoreEnvelope();
  assert.equal(envelope.kdfParams.type, "scrypt");
  assert.equal(envelope.kdfParams.N, 131072);

  // Unlock should work
  const unlocked = await unlockKeystoreAccount({
    password: "strong-passphrase",
    keystoreStore: store,
    cryptoProvider: provider,
  });
  assert.equal(unlocked.accountId, created.accountId);
  assert.equal(unlocked.deviceId, created.deviceId);
});

test("unlockKeystoreAccount fails with wrong password on scrypt keystore", async () => {
  const provider = createMockScryptProvider();
  const storage = createMemoryStorage();
  const store = new KeystoreStore({ storageProvider: storage, key: "scrypt-wrong" });

  await createKeystoreAccount({
    password: "correct",
    profileName: "Test",
    keystoreStore: store,
    cryptoProvider: provider,
  });

  await assert.rejects(
    () => unlockKeystoreAccount({ password: "incorrect", keystoreStore: store, cryptoProvider: provider }),
    /decrypt|invalid|ciphertext|password|operation/i,
  );
});

test("createKeystoreAccount uses pbkdf2 when provider.scrypt not available", async () => {
  const storage = createMemoryStorage();
  const store = new KeystoreStore({ storageProvider: storage, key: "pbkdf2-acc" });

  await createKeystoreAccount({
    password: "password123",
    profileName: "PbkdfUser",
    keystoreStore: store,
    cryptoProvider: globalThis.crypto, // no .scrypt
  });

  const envelope = await store.getKeystoreEnvelope();
  assert.equal(envelope.kdfParams.type, "pbkdf2-sha256");
});
