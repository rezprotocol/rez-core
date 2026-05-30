import { Identity, deriveAccountIdFromPublicKey } from "../identity/index.js";
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

export const KEYSTORE_PAYLOAD_VERSION = 1;

function toBase64Url(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new Error("toBase64Url requires Uint8Array");
  const b64 = toBase64(bytes);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function normalizeProfileName(value) {
  const out = String(value || "").trim();
  return out || null;
}

function createDeviceId(cryptoProvider = null) {
  const bytes = randomBytes(16, cryptoProvider);
  return `rez:dev:${toBase64Url(bytes)}`;
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

  const deviceId = String(src.deviceId || "").trim();
  if (!deviceId) throw new Error("Keystore payload missing deviceId");

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
    profileName: src.profileName,
  });
}

async function decryptPayload({ password, envelope, cryptoProvider = null } = {}) {
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
  const payload = JSON.parse(new TextDecoder().decode(plaintextBytes));
  return parsePayloadJson(payload);
}

export async function createKeystoreAccount({
  password = "",
  profileName = "",
  keystoreStore,
  cryptoProvider = null,
} = {}) {
  const pwd = String(password || "");
  if (!pwd) throw new Error("Password is required");
  if (!keystoreStore) throw new Error("createKeystoreAccount requires keystoreStore");

  const has = await keystoreStore.hasKeystore();
  if (has) throw new Error("Keystore already exists. Unlock with your password.");

  const now = Date.now();
  const identity = await Identity.generate({ cryptoProvider });
  const payload = serializePayload({
    keystoreVersion: KEYSTORE_PAYLOAD_VERSION,
    createdAtMs: now,
    updatedAtMs: now,
    identity,
    accountId: identity.getAccountId(),
    deviceId: createDeviceId(cryptoProvider),
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

  const payload = await decryptPayload({ password: pwd, envelope, cryptoProvider });
  const identityObj = payload.identity.toObject();
  return {
    accountId: payload.accountId,
    deviceId: payload.deviceId,
    identityPublicKey: identityObj.publicKeyB64,
    identityKeyPair: {
      publicKeyB64: identityObj.publicKeyB64,
      privateKeyB64: identityObj.privateKeyB64,
    },
    profileName: payload.profileName,
    keystoreMeta: {
      version: envelope.version,
      updatedAtMs: envelope.updatedAtMs,
    },
  };
}
