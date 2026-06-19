import { Identity, deriveAccountIdFromPublicKey } from "../identity/index.js";
import { DeviceRegistrationV1 } from "../objects/device/DeviceRegistrationV1.js";
import { createKeystoreEnvelope } from "./KeystoreEnvelope.js";
import {
  getDefaultKdfParams,
  randomBytes,
  deriveUnlockKey,
  encryptKeystore,
  decryptKeystore,
  toBase64,
  fromBase64,
} from "./keystoreCrypto.js";

// v1: random unsigned deviceId, no persisted device key.
// v2: persisted device-local Ed25519 keypair + self-certifying
//     deviceId = rez:dev:sha256(devicePublicKeyB64) (DeviceRegistrationV1.deviceIdFor).
export const KEYSTORE_PAYLOAD_VERSION = 2;

function normalizeProfileName(value) {
  const out = String(value || "").trim();
  return out || null;
}

// The deviceId is bound to the device public key (SSOT derivation lives in
// DeviceRegistrationV1; it also enforces canonical 44-byte Ed25519 SPKI, so a
// malformed device key fails loud here rather than persisting).
function deriveDeviceId(devicePublicKeyB64) {
  return DeviceRegistrationV1.deviceIdFor(devicePublicKeyB64);
}

function normalizeDeviceKey(value) {
  const src = value && typeof value === "object" ? value : {};
  const publicKeyB64 = String(src.publicKeyB64 || "").trim();
  const privateKeyB64 = String(src.privateKeyB64 || "").trim();
  if (!publicKeyB64) throw new Error("Keystore payload missing device publicKeyB64");
  if (!privateKeyB64) throw new Error("Keystore payload missing device privateKeyB64");
  return { publicKeyB64, privateKeyB64 };
}

function serializePayload(payload) {
  const src = payload && typeof payload === "object" ? payload : {};
  const identity = src.identity instanceof Identity
    ? src.identity
    : Identity.fromObject(src.identity || {});

  const accountId = String(src.accountId || identity.getAccountId()).trim();
  const derivedAccountId = identity.getAccountId();
  if (!accountId) throw new Error("Keystore payload missing accountId");
  if (accountId !== derivedAccountId) {
    throw new Error("Keystore accountId does not match identity public key fingerprint");
  }

  const deviceKey = normalizeDeviceKey(src.deviceKey);
  const expectedDeviceId = deriveDeviceId(deviceKey.publicKeyB64);
  const deviceId = String(src.deviceId || "").trim();
  if (!deviceId) throw new Error("Keystore payload missing deviceId");
  if (deviceId !== expectedDeviceId) {
    throw new Error("Keystore deviceId does not match device key (must be self-certifying)");
  }

  const createdAtMs = Number(src.createdAtMs);
  const updatedAtMs = Number(src.updatedAtMs);
  if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) {
    throw new Error("Keystore payload createdAtMs must be a positive number");
  }
  if (!Number.isFinite(updatedAtMs) || updatedAtMs <= 0) {
    throw new Error("Keystore payload updatedAtMs must be a positive number");
  }

  const keystoreVersion = Number(src.keystoreVersion);
  if (!Number.isInteger(keystoreVersion) || keystoreVersion !== KEYSTORE_PAYLOAD_VERSION) {
    throw new Error(`Unsupported keystore payload version: ${String(src.keystoreVersion || "")}`);
  }

  return {
    keystoreVersion,
    createdAtMs,
    updatedAtMs,
    identity,
    accountId,
    deviceId,
    deviceKey,
    profileName: normalizeProfileName(src.profileName),
  };
}

function payloadToJson(payload) {
  const normalized = serializePayload(payload);
  return {
    keystoreVersion: normalized.keystoreVersion,
    createdAtMs: normalized.createdAtMs,
    updatedAtMs: normalized.updatedAtMs,
    identity: normalized.identity.toObject(),
    accountId: normalized.accountId,
    deviceId: normalized.deviceId,
    deviceKey: {
      publicKeyB64: normalized.deviceKey.publicKeyB64,
      privateKeyB64: normalized.deviceKey.privateKeyB64,
    },
    profileName: normalized.profileName,
  };
}

function parsePayloadJson(payload) {
  const src = payload && typeof payload === "object" ? payload : {};
  const identity = Identity.fromObject(src.identity || {});
  const accountId = String(src.accountId || "").trim();
  const derivedAccountId = deriveAccountIdFromPublicKey(identity.getPublicKeyBytes());
  if (!accountId) throw new Error("Keystore payload missing accountId");
  if (accountId !== derivedAccountId) {
    throw new Error("Keystore accountId mismatch; payload may be tampered");
  }

  return serializePayload({
    keystoreVersion: src.keystoreVersion,
    createdAtMs: src.createdAtMs,
    updatedAtMs: src.updatedAtMs,
    identity,
    accountId,
    deviceId: src.deviceId,
    deviceKey: src.deviceKey,
    profileName: src.profileName,
  });
}

// Decrypt the envelope to its raw payload JSON, returning the password-derived
// unlock key so a v1→v2 migration can re-seal in place without re-deriving it.
async function decryptKeystoreToJson({ password, envelope, cryptoProvider = null } = {}) {
  const saltBytes = fromBase64(envelope.saltB64);
  const unlockKeyBytes = await deriveUnlockKey({
    password,
    saltBytes,
    kdfParams: envelope.kdfParams,
    cryptoProvider,
  });
  const plaintextBytes = await decryptKeystore({
    unlockKeyBytes,
    envelope,
    cryptoProvider,
  });
  const json = JSON.parse(new TextDecoder().decode(plaintextBytes));
  return { json, unlockKeyBytes };
}

// Lazy upgrade of a v1 payload (random unsigned deviceId, no device key) to v2:
// mint a DEVICE-LOCAL Ed25519 key (not seed-recoverable — a reinstalled vault is
// a new device), derive the self-certifying deviceId, and re-seal in place under
// the SAME password-derived key (salt + kdf unchanged). The v1 random deviceId is
// discarded. A write failure propagates: we must never hand back a deviceId we
// could not persist, or the next unlock would mint a different device key and
// churn the id.
async function migrateV1ToV2({ json, envelope, unlockKeyBytes, keystoreStore, cryptoProvider }) {
  const identity = Identity.fromObject(json.identity || {});
  const accountId = String(json.accountId || "").trim();
  const derivedAccountId = deriveAccountIdFromPublicKey(identity.getPublicKeyBytes());
  if (!accountId) throw new Error("Keystore payload missing accountId");
  if (accountId !== derivedAccountId) {
    throw new Error("Keystore accountId mismatch; payload may be tampered");
  }
  const createdAtMs = Number(json.createdAtMs);
  if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) {
    throw new Error("Keystore payload createdAtMs must be a positive number");
  }

  const deviceIdentity = await Identity.generate({ cryptoProvider });
  const deviceKey = normalizeDeviceKey(deviceIdentity.toObject());
  const now = Date.now();

  const payload = serializePayload({
    keystoreVersion: KEYSTORE_PAYLOAD_VERSION,
    createdAtMs,
    updatedAtMs: now,
    identity,
    accountId,
    deviceId: deriveDeviceId(deviceKey.publicKeyB64),
    deviceKey,
    profileName: json.profileName,
  });

  const plaintextJsonBytes = new TextEncoder().encode(JSON.stringify(payloadToJson(payload)));
  const { ciphertextBytes } = await encryptKeystore({
    unlockKeyBytes,
    plaintextJsonBytes,
    cryptoProvider,
  });
  const upgraded = createKeystoreEnvelope({
    kdfParams: envelope.kdfParams,
    saltB64: envelope.saltB64,
    ciphertextB64: toBase64(ciphertextBytes),
    createdAtMs: envelope.createdAtMs,
    updatedAtMs: now,
  });
  await keystoreStore.putKeystoreEnvelope(upgraded);
  return { payload, updatedAtMs: now };
}

export async function createKeystoreAccount({
  password = "",
  profileName = "",
  keystoreStore,
  cryptoProvider = null,
  identity: providedIdentity = null,
} = {}) {
  const pwd = String(password || "");
  if (!pwd) throw new Error("Password is required");
  if (!keystoreStore) throw new Error("createKeystoreAccount requires keystoreStore");

  const has = await keystoreStore.hasKeystore();
  if (has) throw new Error("Keystore already exists. Unlock with your password.");

  const now = Date.now();
  // Caller may inject a pre-derived identity (e.g., BIP39-seed-rooted via
  // SeedKeys.deriveEd25519) — this is the recoverable path. If absent we fall
  // back to random Identity.generate(), which is non-recoverable and only used
  // for tests / non-recoverable bootstrap.
  const identity = providedIdentity instanceof Identity
    ? providedIdentity
    : await Identity.generate({ cryptoProvider });
  // The device key is ALWAYS device-local random (never the injected/recoverable
  // account identity) — per-device compromise isolation: a leaked seed must not
  // reconstruct past device keys.
  const deviceIdentity = await Identity.generate({ cryptoProvider });
  const deviceKey = normalizeDeviceKey(deviceIdentity.toObject());
  const payload = serializePayload({
    keystoreVersion: KEYSTORE_PAYLOAD_VERSION,
    createdAtMs: now,
    updatedAtMs: now,
    identity,
    accountId: identity.getAccountId(),
    deviceId: deriveDeviceId(deviceKey.publicKeyB64),
    deviceKey,
    profileName,
  });

  const saltBytes = randomBytes(16, cryptoProvider);
  const kdfParams = getDefaultKdfParams(cryptoProvider);
  const unlockKeyBytes = await deriveUnlockKey({
    password: pwd,
    saltBytes,
    kdfParams,
    cryptoProvider,
  });

  const plaintextJsonBytes = new TextEncoder().encode(JSON.stringify(payloadToJson(payload)));
  const { ciphertextBytes } = await encryptKeystore({
    unlockKeyBytes,
    plaintextJsonBytes,
    cryptoProvider,
  });

  const envelope = createKeystoreEnvelope({
    kdfParams,
    saltB64: toBase64(saltBytes),
    ciphertextB64: toBase64(ciphertextBytes),
    createdAtMs: now,
    updatedAtMs: now,
  });

  await keystoreStore.putKeystoreEnvelope(envelope);
  return {
    accountId: payload.accountId,
    deviceId: payload.deviceId,
    identityPublicKey: payload.identity.toObject().publicKeyB64,
    deviceKeyPublicKeyB64: payload.deviceKey.publicKeyB64,
    profileName: payload.profileName,
    keystoreMeta: {
      version: envelope.version,
      updatedAtMs: envelope.updatedAtMs,
    },
  };
}

export async function unlockKeystoreAccount({
  password = "",
  keystoreStore,
  cryptoProvider = null,
} = {}) {
  const pwd = String(password || "");
  if (!pwd) throw new Error("Password is required");
  if (!keystoreStore) throw new Error("unlockKeystoreAccount requires keystoreStore");

  const envelope = await keystoreStore.getKeystoreEnvelope();
  if (!envelope) throw new Error("No keystore found. Create an account first.");

  const { json, unlockKeyBytes } = await decryptKeystoreToJson({ password: pwd, envelope, cryptoProvider });

  // A v1 payload predates the persisted device key — upgrade it in place (lazy
  // migration). Anything else is parsed/validated as the current version.
  const rawVersion = Number(json.keystoreVersion);
  let payload;
  let metaUpdatedAtMs = envelope.updatedAtMs;
  if (rawVersion === 1) {
    const migrated = await migrateV1ToV2({ json, envelope, unlockKeyBytes, keystoreStore, cryptoProvider });
    payload = migrated.payload;
    metaUpdatedAtMs = migrated.updatedAtMs;
  } else {
    payload = parsePayloadJson(json);
  }

  const identityObj = payload.identity.toObject();
  return {
    accountId: payload.accountId,
    deviceId: payload.deviceId,
    identityPublicKey: identityObj.publicKeyB64,
    identityKeyPair: {
      publicKeyB64: identityObj.publicKeyB64,
      privateKeyB64: identityObj.privateKeyB64,
    },
    deviceKeyPair: {
      publicKeyB64: payload.deviceKey.publicKeyB64,
      privateKeyB64: payload.deviceKey.privateKeyB64,
    },
    profileName: payload.profileName,
    keystoreMeta: {
      version: envelope.version,
      updatedAtMs: metaUpdatedAtMs,
    },
  };
}
