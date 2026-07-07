import { Identity, deriveAccountIdFromPublicKey } from "../identity/index.js";
import { DeviceRegistrationV1 } from "../objects/device/DeviceRegistrationV1.js";
import { AccountDeviceCapabilityV1 } from "../objects/device/AccountDeviceCapabilityV1.js";
import { DeviceSetRecordV1 } from "../objects/device/DeviceSetRecordV1.js";
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

// v3: the SEEDLESS delegated keystore — a different MODE, not an upgrade target
// (v2 never migrates to v3). Holds the account signing PUBLIC key only (no
// admin root), the account X25519 DH keypair, the device key C, the
// AccountDeviceCapabilityV1 chain C←…←B, and an optional cached device set.
// No mnemonic, no seed, no account signing private key — ever.
export const KEYSTORE_PAYLOAD_VERSION_DELEGATED = 3;

// X25519 SPKI DER prefix (RFC 8410): 30 2a 30 05 06 03 2b 65 6e 03 21 00.
// Keystore-private pinning for the account DH public key — the device-record
// family pins Ed25519 SPKI; the DH key is the one X25519 key the keystore holds.
const X25519_SPKI_PREFIX = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00]);
const X25519_SPKI_LENGTH = 44;

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

function requireX25519SpkiB64(value, label) {
  const trimmed = String(value || "").trim();
  if (!trimmed) throw new Error(`Keystore payload missing ${label}`);
  let bytes;
  try {
    bytes = fromBase64(trimmed);
  } catch (err) {
    throw new Error(`${label} must be a 44-byte X25519 SPKI DER public key (bad base64: ${err.message})`);
  }
  if (bytes.length !== X25519_SPKI_LENGTH) {
    throw new Error(`${label} must be a 44-byte X25519 SPKI DER public key`);
  }
  for (let i = 0; i < X25519_SPKI_PREFIX.length; i += 1) {
    if (bytes[i] !== X25519_SPKI_PREFIX[i]) {
      throw new Error(`${label} must be a 44-byte X25519 SPKI DER public key`);
    }
  }
  return trimmed;
}

// Structural chain validation for the sealed v3 payload — construction of each
// AccountDeviceCapabilityV1 gives deterministic-certId + SPKI pinning for free;
// linkage/anchoring is pure field comparison. NO signature verification here:
// the keystore cryptoProvider is often bare WebCrypto (no verify() shape), and
// a cert valid at seal time can be expired/revoked by first use — every use
// site verifies through verifyAccountAuthority with fresh nowMs + revocation
// state. Order: root first, leaf last.
function normalizeDelegatedCertChain(value, accountSignPublicKeyB64, deviceKeyPublicKeyB64) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error("Delegated keystore requires a non-empty certChain");
  }
  const certs = [];
  for (let i = 0; i < value.length; i += 1) {
    const raw = value[i];
    const json = raw && typeof raw.toJSON === "function" ? raw.toJSON() : raw;
    let cert;
    try {
      cert = new AccountDeviceCapabilityV1(json && typeof json === "object" ? json : {});
    } catch (err) {
      throw new Error(`Delegated keystore certChain[${i}] is invalid: ${err.message}`);
    }
    certs.push(cert);
  }
  for (let i = 0; i < certs.length; i += 1) {
    if (certs[i].accountIdentityPublicKeyB64 !== accountSignPublicKeyB64) {
      throw new Error("Delegated keystore certChain does not anchor to the account signing key");
    }
  }
  if (certs[0].parentCertId !== null || certs[0].signerPublicKeyB64 !== accountSignPublicKeyB64) {
    throw new Error("Delegated keystore certChain root must be issued by the account signing key");
  }
  for (let i = 1; i < certs.length; i += 1) {
    const chainsToParent = certs[i].parentCertId === certs[i - 1].certId
      && certs[i].signerPublicKeyB64 === certs[i - 1].granteeDevicePublicKeyB64;
    if (!chainsToParent) {
      throw new Error("Delegated keystore certChain link does not chain to its parent");
    }
  }
  if (certs[certs.length - 1].granteeDevicePublicKeyB64 !== deviceKeyPublicKeyB64) {
    throw new Error("Delegated keystore certChain leaf grantee does not match the device key");
  }
  return certs.map((cert) => cert.toJSON());
}

function normalizeCachedDeviceSet(value, accountSignPublicKeyB64) {
  if (value === null || value === undefined) return null;
  const json = value && typeof value.toJSON === "function" ? value.toJSON() : value;
  let record;
  try {
    record = new DeviceSetRecordV1(json && typeof json === "object" ? json : {});
  } catch (err) {
    throw new Error(`Delegated keystore cachedDeviceSet is invalid: ${err.message}`);
  }
  if (record.accountIdentityPublicKeyB64 !== accountSignPublicKeyB64) {
    throw new Error("Delegated keystore cachedDeviceSet does not belong to the account");
  }
  return record.toJSON();
}

// Validate + normalize a v3 (seedless delegated) payload. Runs on create AND on
// every unlock (the parse path re-derives accountId/deviceId — anti-tamper).
// Returns a plain JSON-safe object: the normalized form IS the sealed shape.
function serializeDelegatedPayload(payload) {
  const src = payload && typeof payload === "object" ? payload : {};

  const keystoreVersion = Number(src.keystoreVersion);
  if (!Number.isInteger(keystoreVersion) || keystoreVersion !== KEYSTORE_PAYLOAD_VERSION_DELEGATED) {
    throw new Error(`Unsupported keystore payload version: ${String(src.keystoreVersion || "")}`);
  }

  const createdAtMs = Number(src.createdAtMs);
  const updatedAtMs = Number(src.updatedAtMs);
  if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) {
    throw new Error("Keystore payload createdAtMs must be a positive number");
  }
  if (!Number.isFinite(updatedAtMs) || updatedAtMs <= 0) {
    throw new Error("Keystore payload updatedAtMs must be a positive number");
  }

  // Seedless invariants — a v3 payload must be UNABLE to smuggle admin-root
  // material. Fail loud on any field a confused writer could park it in.
  if (src.identity !== undefined && src.identity !== null) {
    throw new Error("Delegated keystore must not contain an account signing private key");
  }
  if (src.mnemonic !== undefined || src.seed !== undefined) {
    throw new Error("Delegated keystore must not contain seed material");
  }

  const account = src.account && typeof src.account === "object" ? src.account : {};
  if (account.signPrivateKeyB64 !== undefined || account.signKeyPair !== undefined) {
    throw new Error("Delegated keystore must not contain an account signing private key");
  }
  const signPublicKeyB64 = String(account.signPublicKeyB64 || "").trim();
  if (!signPublicKeyB64) throw new Error("Keystore payload missing account signPublicKeyB64");

  const accountId = String(src.accountId || "").trim();
  if (!accountId) throw new Error("Keystore payload missing accountId");
  const derivedAccountId = deriveAccountIdFromPublicKey(fromBase64(signPublicKeyB64));
  if (accountId !== derivedAccountId) {
    throw new Error("Keystore accountId does not match account signing key fingerprint");
  }

  const dhSrc = account.dhKeyPair && typeof account.dhKeyPair === "object" ? account.dhKeyPair : {};
  const dhPublicKeyB64 = requireX25519SpkiB64(dhSrc.publicKeyB64, "account dhKeyPair publicKeyB64");
  const dhPrivateKeyB64 = String(dhSrc.privateKeyB64 || "").trim();
  if (!dhPrivateKeyB64) throw new Error("Keystore payload missing account dhKeyPair privateKeyB64");

  const deviceKey = normalizeDeviceKey(src.deviceKey);
  const expectedDeviceId = deriveDeviceId(deviceKey.publicKeyB64);
  const deviceId = String(src.deviceId || "").trim();
  if (!deviceId) throw new Error("Keystore payload missing deviceId");
  if (deviceId !== expectedDeviceId) {
    throw new Error("Keystore deviceId does not match device key (must be self-certifying)");
  }

  const certChain = normalizeDelegatedCertChain(src.certChain, signPublicKeyB64, deviceKey.publicKeyB64);
  const cachedDeviceSet = normalizeCachedDeviceSet(
    src.cachedDeviceSet === undefined ? null : src.cachedDeviceSet,
    signPublicKeyB64,
  );

  return {
    keystoreVersion,
    createdAtMs,
    updatedAtMs,
    accountId,
    account: {
      signPublicKeyB64,
      dhKeyPair: { publicKeyB64: dhPublicKeyB64, privateKeyB64: dhPrivateKeyB64 },
    },
    deviceId,
    deviceKey,
    certChain,
    cachedDeviceSet,
    profileName: normalizeProfileName(src.profileName),
  };
}

// Anti-tamper parse of a decrypted v3 payload — the full validation (including
// accountId/deviceId re-derivation) lives in serializeDelegatedPayload.
function parseDelegatedPayloadJson(json) {
  return serializeDelegatedPayload(json);
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

// Shared sealing tail for BOTH create paths (v2 and v3) — one code path from
// payload JSON to the persisted envelope so the two modes cannot drift.
async function sealNewKeystore({ password, payloadJson, keystoreStore, cryptoProvider, now }) {
  const saltBytes = randomBytes(16, cryptoProvider);
  const kdfParams = getDefaultKdfParams(cryptoProvider);
  const unlockKeyBytes = await deriveUnlockKey({
    password,
    saltBytes,
    kdfParams,
    cryptoProvider,
  });

  const plaintextJsonBytes = new TextEncoder().encode(JSON.stringify(payloadJson));
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
  return envelope;
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

  const envelope = await sealNewKeystore({
    password: pwd,
    payloadJson: payloadToJson(payload),
    keystoreStore,
    cryptoProvider,
    now,
  });
  return {
    hasAdminRoot: true,
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

/**
 * Create the SEEDLESS delegated keystore (payload v3). The device key C is
 * ACCEPTED, never minted: the delegation chain's leaf grantee was fixed when
 * the account root signed the cert, so a key minted here could never match.
 *
 * `delegation` is the candidate DelegationBundleV1 body — the S10 PSK ceremony
 * lifts these field names verbatim as the sealed bundle it transports:
 *   {
 *     accountSignPublicKeyB64,                            // B-sign PUBLIC only
 *     accountDhKeyPair: { publicKeyB64, privateKeyB64 },  // B-dh (X25519)
 *     deviceKeyPair:    { publicKeyB64, privateKeyB64 },  // C (pre-existing)
 *     certChain: [ ...AccountDeviceCapabilityV1 JSON, root first ],
 *     cachedDeviceSet: <DeviceSetRecordV1 JSON> | null,
 *   }
 */
export async function createDelegatedKeystoreAccount({
  password = "",
  profileName = "",
  keystoreStore,
  cryptoProvider = null,
  delegation = null,
} = {}) {
  const pwd = String(password || "");
  if (!pwd) throw new Error("Password is required");
  if (!keystoreStore) throw new Error("createDelegatedKeystoreAccount requires keystoreStore");
  if (!delegation || typeof delegation !== "object") {
    throw new Error("createDelegatedKeystoreAccount requires delegation");
  }

  const has = await keystoreStore.hasKeystore();
  if (has) throw new Error("Keystore already exists. Unlock with your password.");

  if (delegation.accountSignPrivateKeyB64 !== undefined || delegation.accountSignKeyPair !== undefined) {
    throw new Error("Delegated keystore must not contain an account signing private key");
  }
  if (delegation.mnemonic !== undefined || delegation.seed !== undefined) {
    throw new Error("Delegated keystore must not contain seed material");
  }

  const accountSignPublicKeyB64 = String(delegation.accountSignPublicKeyB64 || "").trim();
  if (!accountSignPublicKeyB64) {
    throw new Error("Delegated keystore requires delegation.accountSignPublicKeyB64");
  }
  const dhSrc = delegation.accountDhKeyPair && typeof delegation.accountDhKeyPair === "object"
    ? delegation.accountDhKeyPair
    : {};
  if (!String(dhSrc.publicKeyB64 || "").trim() || !String(dhSrc.privateKeyB64 || "").trim()) {
    throw new Error("Delegated keystore requires delegation.accountDhKeyPair with publicKeyB64 and privateKeyB64");
  }
  const deviceSrc = delegation.deviceKeyPair && typeof delegation.deviceKeyPair === "object"
    ? delegation.deviceKeyPair
    : {};
  if (!String(deviceSrc.publicKeyB64 || "").trim() || !String(deviceSrc.privateKeyB64 || "").trim()) {
    throw new Error("Delegated keystore requires delegation.deviceKeyPair with publicKeyB64 and privateKeyB64");
  }

  const now = Date.now();
  const deviceKey = normalizeDeviceKey(deviceSrc);
  const payloadJson = serializeDelegatedPayload({
    keystoreVersion: KEYSTORE_PAYLOAD_VERSION_DELEGATED,
    createdAtMs: now,
    updatedAtMs: now,
    accountId: deriveAccountIdFromPublicKey(fromBase64(accountSignPublicKeyB64)),
    account: {
      signPublicKeyB64: accountSignPublicKeyB64,
      dhKeyPair: {
        publicKeyB64: String(dhSrc.publicKeyB64 || "").trim(),
        privateKeyB64: String(dhSrc.privateKeyB64 || "").trim(),
      },
    },
    deviceId: deriveDeviceId(deviceKey.publicKeyB64),
    deviceKey,
    certChain: delegation.certChain,
    cachedDeviceSet: delegation.cachedDeviceSet === undefined ? null : delegation.cachedDeviceSet,
    profileName,
  });

  const envelope = await sealNewKeystore({
    password: pwd,
    payloadJson,
    keystoreStore,
    cryptoProvider,
    now,
  });
  return {
    hasAdminRoot: false,
    accountId: payloadJson.accountId,
    deviceId: payloadJson.deviceId,
    identityPublicKey: payloadJson.account.signPublicKeyB64,
    deviceKeyPublicKeyB64: payloadJson.deviceKey.publicKeyB64,
    profileName: payloadJson.profileName,
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
  // migration). v3 is the seedless DELEGATED mode (never a migration target).
  // Anything else is parsed/validated as the current admin-root version.
  // `hasAdminRoot` is DERIVED from the payload shape, never stored — a v3
  // payload cannot claim an admin root it does not hold.
  const rawVersion = Number(json.keystoreVersion);
  if (rawVersion === KEYSTORE_PAYLOAD_VERSION_DELEGATED) {
    const delegated = parseDelegatedPayloadJson(json);
    return {
      hasAdminRoot: false,
      accountId: delegated.accountId,
      deviceId: delegated.deviceId,
      identityPublicKey: delegated.account.signPublicKeyB64,
      // Explicit null: no admin root. Reading .privateKeyB64 off it throws —
      // any consumer expecting to sign with the account key fails loud.
      identityKeyPair: null,
      deviceKeyPair: {
        publicKeyB64: delegated.deviceKey.publicKeyB64,
        privateKeyB64: delegated.deviceKey.privateKeyB64,
      },
      accountIdentityDhKeyPair: {
        publicKeyB64: delegated.account.dhKeyPair.publicKeyB64,
        privateKeyB64: delegated.account.dhKeyPair.privateKeyB64,
      },
      certChain: delegated.certChain,
      cachedDeviceSet: delegated.cachedDeviceSet,
      profileName: delegated.profileName,
      keystoreMeta: {
        version: envelope.version,
        updatedAtMs: envelope.updatedAtMs,
      },
    };
  }

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
    hasAdminRoot: true,
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
