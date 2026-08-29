import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  KeystoreStore,
  createKeystoreAccount,
  createDelegatedKeystoreAccount,
  unlockKeystoreAccount,
  createKeystoreEnvelope,
  getDefaultKdfParams,
  deriveUnlockKey,
  encryptKeystore,
  decryptKeystore,
  toBase64,
  randomBytes,
} from "../src/keystore/index.js";
import { Identity, deriveAccountIdFromPublicKey } from "../src/identity/index.js";
import {
  AccountDeviceCapabilityV1,
  ACCOUNT_DEVICE_CAPABILITY_PURPOSE,
  DeviceRegistrationV1,
  DeviceSetRecordV1,
  verifyAccountAuthority,
} from "../src/objects/device/index.js";

// S2.5 S9 K1 — the SEEDLESS delegated keystore (payload v3). Real crypto
// throughout: node:crypto Ed25519/X25519 (SPKI/PKCS8 — the exact encodings the
// records pin) + WebCrypto for the keystore sealing. v3 is a MODE, not a
// migration target: v1 still upgrades to v2, v2 stays byte-identical, and the
// unlock result's hasAdminRoot is DERIVED from the payload shape, never stored.

const CRYPTO = globalThis.crypto;
const NOW = Date.now();
const FAR = NOW + 3_600_000;

function genKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const spki = new Uint8Array(publicKey.export({ format: "der", type: "spki" }));
  return { publicKeyB64: Buffer.from(spki).toString("base64"), privateKey };
}

function genX25519() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519");
  return {
    publicKeyB64: Buffer.from(publicKey.export({ format: "der", type: "spki" })).toString("base64"),
    privateKeyB64: Buffer.from(privateKey.export({ format: "der", type: "pkcs8" })).toString("base64"),
  };
}

const nodeVerifier = {
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

function buildDeviceSet({ account, devices, revision = 1 }) {
  const body = {
    v: 1,
    purpose: "rez:device-set:v1",
    accountIdentityPublicKeyB64: account.publicKeyB64,
    revision,
    devices: devices.map((d, i) => ({
      deviceId: DeviceRegistrationV1.deviceIdFor(d.publicKeyB64),
      devicePublicKeyB64: d.publicKeyB64,
      inboxId: "rez:inbox:dev" + i,
    })),
    issuedAtMs: NOW,
    expiresAtMs: FAR,
  };
  const sigB64 = Buffer.from(crypto.sign(null, Buffer.from(DeviceSetRecordV1.signableBytes(body)), account.privateKey)).toString("base64");
  return new DeviceSetRecordV1({ ...body, sig: { alg: "ed25519", sigB64 } });
}

// A device key C as the ceremony would hand it over: minted locally, PKCS8 priv.
function genDeviceKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    publicKeyB64: Buffer.from(publicKey.export({ format: "der", type: "spki" })).toString("base64"),
    privateKeyB64: Buffer.from(privateKey.export({ format: "der", type: "pkcs8" })).toString("base64"),
  };
}

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

function makeStore(key) {
  return new KeystoreStore({ storageProvider: createMemoryStorage(), key });
}

// Everything a valid delegation bundle carries. Callers override pieces to
// build the rejection cases.
function makeDelegation({ withDeviceSet = true } = {}) {
  const B = genKey();
  const Bdh = genX25519();
  const deviceKeyPair = genDeviceKeyPair();
  const leaf = buildCert({
    account: B.publicKeyB64,
    signer: B,
    granteePub: deviceKeyPair.publicKeyB64,
    capabilities: ["peerLink.create", "deviceSet.publish"],
  });
  const cachedDeviceSet = withDeviceSet
    ? buildDeviceSet({ account: B, devices: [{ publicKeyB64: deviceKeyPair.publicKeyB64 }] }).toJSON()
    : null;
  return {
    B,
    delegation: {
      accountSignPublicKeyB64: B.publicKeyB64,
      accountDhKeyPair: { publicKeyB64: Bdh.publicKeyB64, privateKeyB64: Bdh.privateKeyB64 },
      deviceKeyPair,
      certChain: [leaf.toJSON()],
      cachedDeviceSet,
    },
  };
}

async function createDelegated(store, delegation, profileName = "Delegated") {
  return createDelegatedKeystoreAccount({
    password: "pw",
    profileName,
    keystoreStore: store,
    cryptoProvider: CRYPTO,
    delegation,
  });
}

async function readStoredPayload({ store, password }) {
  const envelope = await store.getKeystoreEnvelope();
  const saltBytes = Uint8Array.from(Buffer.from(envelope.saltB64, "base64"));
  const unlockKeyBytes = await deriveUnlockKey({ password, saltBytes, kdfParams: envelope.kdfParams, cryptoProvider: CRYPTO });
  const plaintextBytes = await decryptKeystore({ unlockKeyBytes, envelope, cryptoProvider: CRYPTO });
  return JSON.parse(new TextDecoder().decode(plaintextBytes));
}

// Hand-seal an arbitrary v3-shaped payload so tampered payloads can be exercised
// through the REAL unlock path.
async function writeRawKeystore({ store, password, payload, now = Date.now() }) {
  const saltBytes = randomBytes(16, CRYPTO);
  const kdfParams = getDefaultKdfParams(CRYPTO);
  const unlockKeyBytes = await deriveUnlockKey({ password, saltBytes, kdfParams, cryptoProvider: CRYPTO });
  const plaintextJsonBytes = new TextEncoder().encode(JSON.stringify(payload));
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

test("create + unlock round-trip: seedless payload, C accepted not minted, all delegated fields surface", async () => {
  const store = makeStore("rt");
  const { B, delegation } = makeDelegation();
  const created = await createDelegated(store, delegation);

  assert.equal(created.hasAdminRoot, false);
  assert.equal(created.accountId, deriveAccountIdFromPublicKey(Uint8Array.from(Buffer.from(B.publicKeyB64, "base64"))));
  assert.equal(created.deviceId, DeviceRegistrationV1.deviceIdFor(delegation.deviceKeyPair.publicKeyB64));
  // C is accepted, never minted.
  assert.equal(created.deviceKeyPublicKeyB64, delegation.deviceKeyPair.publicKeyB64);
  assert.equal(created.identityPublicKey, B.publicKeyB64);

  const unlocked = await unlockKeystoreAccount({ password: "pw", keystoreStore: store, cryptoProvider: CRYPTO });
  assert.equal(unlocked.hasAdminRoot, false);
  assert.equal(unlocked.accountId, created.accountId);
  assert.equal(unlocked.deviceId, created.deviceId);
  assert.equal(unlocked.identityPublicKey, B.publicKeyB64);
  // No admin root: the account signing keypair is explicitly null — reading a
  // private key off it throws instead of silently signing with the wrong key.
  assert.equal(unlocked.identityKeyPair, null);
  assert.deepEqual(unlocked.deviceKeyPair, delegation.deviceKeyPair);
  assert.deepEqual(unlocked.accountIdentityDhKeyPair, delegation.accountDhKeyPair);
  assert.deepEqual(unlocked.certChain, delegation.certChain);
  assert.deepEqual(unlocked.cachedDeviceSet, delegation.cachedDeviceSet);
  assert.equal(unlocked.profileName, "Delegated");

  // The sealed payload is v3 and carries NO admin-root material.
  const stored = await readStoredPayload({ store, password: "pw" });
  assert.equal(stored.keystoreVersion, 3);
  assert.equal(stored.identity, undefined);
  assert.equal(stored.account.signPrivateKeyB64, undefined);
  assert.equal(stored.mnemonic, undefined);
});

test("P1#2 L3.5 / R3: the delegated keystore persists + surfaces the ceremony BOOTSTRAP inbox; legacy → null; noncanonical rejected", async () => {
  const bootstrapInboxId = "inbox:" + "b".repeat(24);
  const withInbox = makeDelegation();
  const store = makeStore("inbox-persist");
  await createDelegated(store, { ...withInbox.delegation, bootstrapInboxId });
  const unlocked = await unlockKeystoreAccount({ password: "pw", keystoreStore: store, cryptoProvider: CRYPTO });
  assert.equal(unlocked.bootstrapInboxId, bootstrapInboxId, "the ceremony bootstrap inbox round-trips through the sealed keystore");
  assert.equal(unlocked.inboxId, undefined, "the generically-named field is gone from the unlock result (R3)");

  // R3: the sealed payload carries the honest field name ONLY — never both.
  const stored = await readStoredPayload({ store, password: "pw" });
  assert.equal(stored.bootstrapInboxId, bootstrapInboxId);
  assert.equal(stored.inboxId, undefined, "new envelopes never write the legacy field");

  // A legacy delegated keystore (no inbox at all) surfaces null — backward compatible.
  const legacy = makeDelegation();
  const store2 = makeStore("inbox-legacy");
  await createDelegated(store2, legacy.delegation);
  const unlocked2 = await unlockKeystoreAccount({ password: "pw", keystoreStore: store2, cryptoProvider: CRYPTO });
  assert.equal(unlocked2.bootstrapInboxId, null, "a delegated keystore without an inbox surfaces null");

  // A noncanonical inbox is rejected at create (fail loud).
  const bad = makeDelegation();
  await assert.rejects(
    () => createDelegated(makeStore("inbox-bad"), { ...bad.delegation, bootstrapInboxId: "not-an-inbox" }),
    /canonical/,
  );

  // R3: the create API REFUSES the legacy spelling — silently sealing an
  // envelope with no bootstrap inbox while the caller believed it persisted
  // one is exactly the drift this guard exists for.
  const legacyParam = makeDelegation();
  await assert.rejects(
    () => createDelegated(makeStore("inbox-legacy-param"), { ...legacyParam.delegation, inboxId: bootstrapInboxId }),
    /bootstrapInboxId \(R3\)/,
  );
});

test("R3: a LEGACY stored envelope's inboxId deserializes AS bootstrapInboxId; both-names-different is refused", async () => {
  const bootstrapInboxId = "inbox:" + "c".repeat(24);
  const { delegation } = makeDelegation();
  const store = makeStore("inbox-migrate");
  await createDelegated(store, { ...delegation, bootstrapInboxId });

  // Rewrite the sealed payload to the LEGACY shape (generic inboxId) — the
  // parse path must adopt it under the honest name without rewriting bytes.
  const payload = await readStoredPayload({ store, password: "pw" });
  const legacyShaped = { ...payload, inboxId: payload.bootstrapInboxId };
  delete legacyShaped.bootstrapInboxId;
  await writeRawKeystore({ store, password: "pw", payload: legacyShaped });
  const unlocked = await unlockKeystoreAccount({ password: "pw", keystoreStore: store, cryptoProvider: CRYPTO });
  assert.equal(unlocked.bootstrapInboxId, bootstrapInboxId, "legacy inboxId deserializes as bootstrapInboxId");

  // Both names with DIFFERENT values is ambiguous authorship — fail loud.
  const conflicted = { ...payload, inboxId: "inbox:" + "d".repeat(24) };
  await writeRawKeystore({ store, password: "pw", payload: conflicted });
  await assert.rejects(
    () => unlockKeystoreAccount({ password: "pw", keystoreStore: store, cryptoProvider: CRYPTO }),
    /refusing to guess/,
  );
});

test("the persisted chain is usable end-to-end: verifyAccountAuthority accepts it in delegated mode", async () => {
  const store = makeStore("authz");
  const { B, delegation } = makeDelegation();
  await createDelegated(store, delegation);
  const unlocked = await unlockKeystoreAccount({ password: "pw", keystoreStore: store, cryptoProvider: CRYPTO });

  const res = await verifyAccountAuthority({
    expectedAccountIdentityPublicKeyB64: B.publicKeyB64,
    requiredCapability: "peerLink.create",
    opSignerPublicKeyB64: unlocked.deviceKeyPair.publicKeyB64,
    certChain: unlocked.certChain,
    crypto: nodeVerifier,
    nowMs: Date.now(),
  });
  assert.equal(res.ok, true, res.reason);
  assert.equal(res.mode, "delegated");
});

test("rejects a chain granted to a different device key than the stored C", async () => {
  const { delegation } = makeDelegation();
  const otherDevice = genDeviceKeyPair();
  await assert.rejects(
    () => createDelegated(makeStore("g1"), { ...delegation, deviceKeyPair: otherDevice }),
    /leaf grantee does not match the device key/,
  );
});

test("rejects a chain anchored to a different account than accountSignPublicKeyB64", async () => {
  const { delegation } = makeDelegation();
  const strangerB = genKey();
  await assert.rejects(
    () => createDelegated(makeStore("g2"), { ...delegation, accountSignPublicKeyB64: strangerB.publicKeyB64 }),
    /does not anchor to the account signing key/,
  );
});

test("missing-input matrix: delegation, account key, dh pair, device pair, chain", async () => {
  const { delegation } = makeDelegation();
  await assert.rejects(
    () => createDelegatedKeystoreAccount({ password: "pw", keystoreStore: makeStore("m0"), cryptoProvider: CRYPTO }),
    /requires delegation/,
  );
  await assert.rejects(
    () => createDelegated(makeStore("m1"), { ...delegation, accountSignPublicKeyB64: "" }),
    /requires delegation\.accountSignPublicKeyB64/,
  );
  await assert.rejects(
    () => createDelegated(makeStore("m2"), { ...delegation, accountDhKeyPair: { publicKeyB64: delegation.accountDhKeyPair.publicKeyB64 } }),
    /requires delegation\.accountDhKeyPair with publicKeyB64 and privateKeyB64/,
  );
  await assert.rejects(
    () => createDelegated(makeStore("m3"), { ...delegation, deviceKeyPair: null }),
    /requires delegation\.deviceKeyPair with publicKeyB64 and privateKeyB64/,
  );
  await assert.rejects(
    () => createDelegated(makeStore("m4"), { ...delegation, certChain: [] }),
    /requires a non-empty certChain/,
  );
});

test("seedless invariants fail loud: smuggled admin-root or seed material is rejected at create AND unlock", async () => {
  const { delegation } = makeDelegation();
  const adminKey = genDeviceKeyPair();
  await assert.rejects(
    () => createDelegated(makeStore("s1"), { ...delegation, accountSignPrivateKeyB64: adminKey.privateKeyB64 }),
    /must not contain an account signing private key/,
  );
  await assert.rejects(
    () => createDelegated(makeStore("s2"), { ...delegation, mnemonic: "abandon abandon ..." }),
    /must not contain seed material/,
  );

  // A hand-sealed v3 payload that parked an `identity` (admin-root keypair)
  // inside must be rejected by the unlock parse, not silently surfaced.
  const store = makeStore("s3");
  const good = makeDelegation();
  await createDelegated(store, good.delegation);
  const stored = await readStoredPayload({ store, password: "pw" });
  const identity = await Identity.generate({ cryptoProvider: CRYPTO });
  const smuggled = { ...stored, identity: identity.toObject() };
  const store2 = makeStore("s3b");
  await writeRawKeystore({ store: store2, password: "pw", payload: smuggled });
  await assert.rejects(
    () => unlockKeystoreAccount({ password: "pw", keystoreStore: store2, cryptoProvider: CRYPTO }),
    /must not contain an account signing private key/,
  );
});

test("a structurally corrupt cert (wrong certId) is rejected with its chain index", async () => {
  const { delegation } = makeDelegation();
  const corrupt = { ...delegation.certChain[0], certId: "rez:cap:" + "0".repeat(64) };
  await assert.rejects(
    () => createDelegated(makeStore("c1"), { ...delegation, certChain: [corrupt] }),
    /certChain\[0\] is invalid/,
  );
});

test("anti-tamper on unlock: accountId and deviceId are re-derived against the sealed keys", async () => {
  const base = makeDelegation();
  const store = makeStore("t0");
  await createDelegated(store, base.delegation);
  const stored = await readStoredPayload({ store, password: "pw" });

  const wrongAccount = { ...stored, accountId: "rez:acct:NOTtheRightFingerprint" };
  const storeA = makeStore("t1");
  await writeRawKeystore({ store: storeA, password: "pw", payload: wrongAccount });
  await assert.rejects(
    () => unlockKeystoreAccount({ password: "pw", keystoreStore: storeA, cryptoProvider: CRYPTO }),
    /accountId does not match account signing key fingerprint/,
  );

  const wrongDevice = { ...stored, deviceId: "rez:dev:" + "0".repeat(64) };
  const storeB = makeStore("t2");
  await writeRawKeystore({ store: storeB, password: "pw", payload: wrongDevice });
  await assert.rejects(
    () => unlockKeystoreAccount({ password: "pw", keystoreStore: storeB, cryptoProvider: CRYPTO }),
    /deviceId does not match device key/,
  );
});

test("the account DH public key is pinned to X25519 SPKI (an Ed25519 key is rejected)", async () => {
  const { delegation } = makeDelegation();
  const ed = genKey();
  await assert.rejects(
    () => createDelegated(makeStore("x1"), {
      ...delegation,
      accountDhKeyPair: { publicKeyB64: ed.publicKeyB64, privateKeyB64: delegation.accountDhKeyPair.privateKeyB64 },
    }),
    /must be a 44-byte X25519 SPKI DER public key/,
  );
});

test("cachedDeviceSet: null is accepted; a set signed for a different account is rejected", async () => {
  const noSet = makeDelegation({ withDeviceSet: false });
  const store = makeStore("d1");
  await createDelegated(store, noSet.delegation);
  const unlocked = await unlockKeystoreAccount({ password: "pw", keystoreStore: store, cryptoProvider: CRYPTO });
  assert.equal(unlocked.cachedDeviceSet, null);

  const { delegation } = makeDelegation();
  const strangerB = genKey();
  const foreignSet = buildDeviceSet({ account: strangerB, devices: [{ publicKeyB64: delegation.deviceKeyPair.publicKeyB64 }] }).toJSON();
  await assert.rejects(
    () => createDelegated(makeStore("d2"), { ...delegation, cachedDeviceSet: foreignSet }),
    /cachedDeviceSet does not belong to the account/,
  );
});

test("v2 stays the admin-root mode: hasAdminRoot true, payload version stable across unlocks; v1 still migrates to 2", async () => {
  const store = makeStore("v2");
  const created = await createKeystoreAccount({ password: "pw", profileName: "Admin", keystoreStore: store, cryptoProvider: CRYPTO });
  assert.equal(created.hasAdminRoot, true);

  const unlocked = await unlockKeystoreAccount({ password: "pw", keystoreStore: store, cryptoProvider: CRYPTO });
  assert.equal(unlocked.hasAdminRoot, true);
  assert.equal(typeof unlocked.identityKeyPair.privateKeyB64, "string");
  assert.ok(unlocked.identityKeyPair.privateKeyB64.length > 0);

  const again = await unlockKeystoreAccount({ password: "pw", keystoreStore: store, cryptoProvider: CRYPTO });
  assert.equal(again.hasAdminRoot, true);
  const stored = await readStoredPayload({ store, password: "pw" });
  assert.equal(stored.keystoreVersion, 2);

  // v1 upgrades to 2 (the admin-root current version), NEVER to 3.
  const legacyStore = makeStore("v1");
  const identity = await Identity.generate({ cryptoProvider: CRYPTO });
  await writeRawKeystore({
    store: legacyStore,
    password: "pw",
    payload: {
      keystoreVersion: 1,
      createdAtMs: Date.now(),
      updatedAtMs: Date.now(),
      identity: identity.toObject(),
      accountId: identity.getAccountId(),
      deviceId: "rez:dev:LEGACYrandom",
      profileName: "Legacy",
    },
  });
  const migrated = await unlockKeystoreAccount({ password: "pw", keystoreStore: legacyStore, cryptoProvider: CRYPTO });
  assert.equal(migrated.hasAdminRoot, true);
  const migratedStored = await readStoredPayload({ store: legacyStore, password: "pw" });
  assert.equal(migratedStored.keystoreVersion, 2);
});

test("createDelegatedKeystoreAccount refuses to overwrite an existing keystore", async () => {
  const store = makeStore("o1");
  const first = makeDelegation();
  await createDelegated(store, first.delegation);
  const second = makeDelegation();
  await assert.rejects(
    () => createDelegated(store, second.delegation),
    /Keystore already exists/,
  );
});
