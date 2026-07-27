import { Hash } from "../base/util/Hash.js";
import { canonicalJSONStringify } from "../util/canonicalize.js";
import { bytesToBase64, base64ToBytes } from "../util/bytes.js";
import { bytesToBase32, base32ToBytes } from "../util/base32.js";
import { concatBytes } from "../crypto/util/bytes.js";
import { encryptAes256Gcm, decryptAes256Gcm } from "../crypto/aead/AeadAes256Gcm.js";
import { buildDurableRecordV1, durableRecordSignableBytes, DURABLE_RECORD_VERSION } from "./durableRecordV1.js";
import { DEVICE_LINK_REQUEST_VERSION } from "../objects/device/DeviceLinkRequestV1.js";
import { DeviceLinkRequestV2, DEVICE_LINK_REQUEST_V2_VERSION, DEVICE_LINK_REQUEST_V2_PURPOSE } from "../objects/device/DeviceLinkRequestV2.js";
import { DeviceRegistrationV1 } from "../objects/device/DeviceRegistrationV1.js";
import {
  requireCanonicalSpkiB64,
  requireCanonicalX25519SpkiB64,
  requireCanonicalB64,
} from "../objects/device/deviceRecordShared.js";

/**
 * Device-link ceremony v1 (S2.5 S10, audit F8) — the PSK-authenticated
 * provisioning protocol that carries a delegation bundle from the PRIMARY
 * device (holds the account root B) to a NEW device (holds only its
 * freshly-minted device key C and the PSK read off the primary's screen).
 *
 * Everything here is PURE: crypto arrives as an injected RCryptoProvider,
 * time as an explicit nowMs. Transport (durable-record put/get + polling)
 * is the SDK's job; this module is the SSOT for the code format, the HKDF
 * discipline, the transcript, and the record slot coordinates.
 *
 * Protocol shape (three durable records, all published under the PSK-derived
 * rendezvous key R — only PSK holders can write to or locate the slots):
 *
 *   request  = AEAD_{K_req}( { linkRequest: DeviceLinkRequestV2, eA } )
 *   response = AEAD_{K_resp}( { delegationBundle } ), K_resp from
 *              HKDF( DH(eA,eB) || psk )  — PSK-authenticated EPHEMERAL DH:
 *              a photographed code (psk) cannot decrypt an intercepted
 *              response, because the ephemeral privates never leave the
 *              devices and are discarded after the ceremony (forward
 *              secrecy, the audit's F8 requirement).
 *   confirm  = key-confirmation tag (PRF output of the master secret over
 *              the full transcript) — proves the RIGHT device derived K.
 *
 * Transcript chaining: thRequest (hash of the request AAD+nonce+ciphertext)
 * is folded into BOTH the master-secret derivation and the response AAD;
 * thResponse is folded into the confirm derivation. Every AAD carries the
 * ceremony context (account B + rendezvous R + step), so no ciphertext can
 * be replayed across accounts, ceremonies, or steps.
 *
 * NOTE: the rendezvous SEED is derived here, but seed→Ed25519-keypair uses
 * SeedKeys (node:crypto) and lives in rez-sdk (src/device-link/rendezvous.js)
 * — this module must stay importable from the browser-safe core barrel.
 */

export const DEVICE_LINK_CODE_PREFIX = "rez:link:v1:";
export const DEVICE_LINK_CEREMONY_PURPOSE = "rez:device-link-ceremony:v1";
export const DEVICE_LINK_RECORD_KIND = "device-link";
export const DEVICE_LINK_RECORD_ID_REQUEST = "request";
export const DEVICE_LINK_RECORD_ID_RESPONSE = "response";
export const DEVICE_LINK_RECORD_ID_CONFIRM = "confirm";
export const DEVICE_LINK_PSK_BYTES = 32;
// SeedKeys label the SDK uses to turn the derived rendezvous seed into the
// Ed25519 keypair R. Exported so the derivation contract stays single-sourced.
export const DEVICE_LINK_RENDEZVOUS_KEY_LABEL = "rez/link/rendezvous/v1";
// payloadB64 budget: the node caps records at 16384 chars; leave headroom for
// the durable-record envelope fields.
export const DEVICE_LINK_MAX_PAYLOAD_B64 = 15000;

const HKDF_SALT = new TextEncoder().encode("rez:link:v1");
const INFO_RENDEZVOUS_SEED = new TextEncoder().encode("rez:link:v1:rendezvous-seed");
const INFO_CEREMONY_NONCE = new TextEncoder().encode("rez:link:v1:ceremony-nonce");
const INFO_REQUEST_KEY = new TextEncoder().encode("rez:link:v1:request-key");
const INFO_RESPONSE_KEY = new TextEncoder().encode("rez:link:v1:response-key");

function utf8(text) {
  return new TextEncoder().encode(text);
}

function requireCrypto(crypto, fn) {
  if (!crypto || typeof crypto !== "object") {
    throw new Error("deviceLinkV1." + fn + " requires a crypto provider");
  }
  return crypto;
}

function requirePsk(psk, fn) {
  if (!(psk instanceof Uint8Array) || psk.length !== DEVICE_LINK_PSK_BYTES) {
    throw new Error("deviceLinkV1." + fn + " requires a " + DEVICE_LINK_PSK_BYTES + "-byte psk Uint8Array");
  }
  return psk;
}

function requireNowMs(nowMs, fn) {
  if (typeof nowMs !== "number" || !Number.isFinite(nowMs)) {
    throw new Error("deviceLinkV1." + fn + " requires a finite nowMs");
  }
  return nowMs;
}

// Constant-time byte comparison (OR-accumulate — does not leak WHERE the
// mismatch is). Length mismatch returns false without early exit on content.
function constantTimeEqualBytes(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  if (a.length !== b.length) return false;
  let acc = 0;
  for (let i = 0; i < a.length; i += 1) acc |= a[i] ^ b[i];
  return acc === 0;
}

// RFC 7748 contributory-behaviour check (mirrors X3DHService.assertSecretBytes):
// WebCrypto X25519 does not reject low-order public keys, whose DH output is
// all-zero — a peer substituting one would force a known-constant secret.
function assertSharedSecret(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new Error("deviceLinkV1: shared secret must be 32 bytes");
  }
  let acc = 0;
  for (let i = 0; i < bytes.length; i += 1) acc |= bytes[i];
  if (acc === 0) {
    throw new Error("deviceLinkV1: rejects all-zero (contributory) shared secret");
  }
}

// The ceremony context every AAD carries. `step` disambiguates request from
// response so a ciphertext can never be replayed into the other slot.
function aadBytes({ accountSignPublicKeyB64, rendezvousPublicKeyB64, step, extra = {} }) {
  return utf8(canonicalJSONStringify({
    v: 1,
    purpose: DEVICE_LINK_CEREMONY_PURPOSE,
    accountSignPublicKeyB64,
    rendezvousPublicKeyB64,
    step,
    ...extra,
  }));
}

function transcriptHashB64(aad, nonceBytes, ciphertextBytes) {
  return bytesToBase64(Hash.sha256(concatBytes(aad, nonceBytes, ciphertextBytes)));
}

// ---------------------------------------------------------------------------
// Link code
// ---------------------------------------------------------------------------

export function generateDeviceLinkPsk({ crypto } = {}) {
  requireCrypto(crypto, "generateDeviceLinkPsk");
  const psk = crypto.randomBytes(DEVICE_LINK_PSK_BYTES);
  if (!(psk instanceof Uint8Array) || psk.length !== DEVICE_LINK_PSK_BYTES) {
    throw new Error("deviceLinkV1.generateDeviceLinkPsk: crypto.randomBytes returned an unexpected shape");
  }
  return psk;
}

export function encodeDeviceLinkCodeV1({ psk, accountSignPublicKeyB64 } = {}) {
  requirePsk(psk, "encodeDeviceLinkCodeV1");
  requireCanonicalSpkiB64(accountSignPublicKeyB64, "encodeDeviceLinkCodeV1.accountSignPublicKeyB64");
  return DEVICE_LINK_CODE_PREFIX + bytesToBase32(psk) + "." + accountSignPublicKeyB64;
}

export function isDeviceLinkCodeV1(code) {
  return typeof code === "string" && code.startsWith(DEVICE_LINK_CODE_PREFIX);
}

export function parseDeviceLinkCodeV1(code) {
  const fail = (detail) => {
    const err = new Error("invalid device-link code: " + detail);
    err.code = "LINK_V1_INVALID_FORMAT";
    return err;
  };
  if (!isDeviceLinkCodeV1(code)) throw fail("missing rez:link:v1: prefix");
  const body = code.slice(DEVICE_LINK_CODE_PREFIX.length).trim();
  const dot = body.indexOf(".");
  if (dot <= 0 || dot === body.length - 1) throw fail("expected <psk>.<accountPublicKey>");
  const pskText = body.slice(0, dot);
  const accountSignPublicKeyB64 = body.slice(dot + 1);
  let psk;
  try {
    psk = base32ToBytes(pskText);
  } catch (err) {
    throw fail("psk segment: " + (err && err.message ? err.message : "undecodable"));
  }
  if (psk.length !== DEVICE_LINK_PSK_BYTES) throw fail("psk must be " + DEVICE_LINK_PSK_BYTES + " bytes");
  try {
    requireCanonicalSpkiB64(accountSignPublicKeyB64, "account public key");
  } catch (err) {
    throw fail(err && err.message ? err.message : "bad account public key");
  }
  return { psk, accountSignPublicKeyB64 };
}

// ---------------------------------------------------------------------------
// Derivations
// ---------------------------------------------------------------------------

/**
 * The PSK-derived family (distinct HKDF info labels; the PSK itself is never
 * used directly as a key):
 *   rendezvousSeed — fed to SeedKeys.deriveEd25519 (SDK side) → keypair R
 *   ceremonyNonceB64 — DeviceLinkRequestV2.ceremonyNonceB64 (cross-ceremony
 *     replay is structurally dead: a different psk derives a different nonce)
 *   requestKey — AEAD key for the request payload (overlay privacy: C's
 *     public key and the ephemeral point are invisible to observers)
 */
export async function deriveCeremonySecrets({ crypto, psk } = {}) {
  requireCrypto(crypto, "deriveCeremonySecrets");
  requirePsk(psk, "deriveCeremonySecrets");
  const rendezvousSeed = await crypto.hkdfSha256(psk, { salt: HKDF_SALT, info: INFO_RENDEZVOUS_SEED, length: 32 });
  const nonce = await crypto.hkdfSha256(psk, { salt: HKDF_SALT, info: INFO_CEREMONY_NONCE, length: 32 });
  const requestKey = await crypto.hkdfSha256(psk, { salt: HKDF_SALT, info: INFO_REQUEST_KEY, length: 32 });
  return {
    rendezvousSeed,
    ceremonyNonceB64: bytesToBase64(nonce),
    requestKey,
  };
}

// PSK-authenticated ephemeral DH → master secret. Secrets go into HKDF's IKM
// (house X3DH concat pattern); the request transcript hash goes into the info
// label so the master secret is bound to exactly one observed request.
async function deriveMasterSecret({ crypto, psk, dhSecret, thRequestB64 }) {
  assertSharedSecret(dhSecret);
  const ikm = concatBytes(dhSecret, psk);
  return crypto.hkdfSha256(ikm, {
    salt: HKDF_SALT,
    info: utf8("rez:link:v1:master:" + thRequestB64),
    length: 32,
  });
}

async function deriveResponseKey({ crypto, masterSecret }) {
  return crypto.hkdfSha256(masterSecret, { salt: new Uint8Array(0), info: INFO_RESPONSE_KEY, length: 32 });
}

async function deriveConfirmTag({ crypto, masterSecret, thResponseB64 }) {
  return crypto.hkdfSha256(masterSecret, {
    salt: new Uint8Array(0),
    info: utf8("rez:link:v1:confirm:" + thResponseB64),
    length: 32,
  });
}

// ---------------------------------------------------------------------------
// Fingerprint (the human cross-check surface for the approve tap)
// ---------------------------------------------------------------------------

export function deviceLinkFingerprint(newDeviceId) {
  const id = String(newDeviceId || "");
  const match = /^rez:dev:([0-9a-f]{64})$/.exec(id);
  if (!match) {
    throw new Error("deviceLinkFingerprint requires a rez:dev:<sha256 hex> device id");
  }
  // First 80 bits, grouped for reading aloud / eyeballing across two screens.
  const hex = match[1].slice(0, 20);
  const groups = [];
  for (let i = 0; i < hex.length; i += 4) groups.push(hex.slice(i, i + 4));
  return groups.join("-");
}

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

export async function buildCeremonyRequest({
  crypto,
  nowMs,
  psk,
  accountSignPublicKeyB64,
  rendezvousPublicKeyB64,
  deviceKeyPair,
  deviceInboxBinding,
  ephemeralKeyPair = null,
  requestTtlMs = 10 * 60_000,
} = {}) {
  requireCrypto(crypto, "buildCeremonyRequest");
  requireNowMs(nowMs, "buildCeremonyRequest");
  requirePsk(psk, "buildCeremonyRequest");
  requireCanonicalSpkiB64(accountSignPublicKeyB64, "buildCeremonyRequest.accountSignPublicKeyB64");
  requireCanonicalSpkiB64(rendezvousPublicKeyB64, "buildCeremonyRequest.rendezvousPublicKeyB64");
  if (!deviceKeyPair || !deviceKeyPair.publicKeyB64 || !deviceKeyPair.privateKeyB64) {
    throw new Error("buildCeremonyRequest requires deviceKeyPair with publicKeyB64 and privateKeyB64 (the new device key C)");
  }
  // P1#2: the new device's self-chosen, device-signed inbox binding, carried in the signed
  // request so the approver can register it (device.add) before releasing the leaf cert.
  if (!deviceInboxBinding || typeof deviceInboxBinding !== "object") {
    throw new Error("buildCeremonyRequest requires deviceInboxBinding (the new device's device-signed DeviceInboxBindingV1 for its self-chosen inbox)");
  }

  const secrets = await deriveCeremonySecrets({ crypto, psk });
  const eph = ephemeralKeyPair || await crypto.dhGenerateKeyPair({ alg: "X25519", fmt: "spki" });
  const ephemeralDhPublicKeyB64 = bytesToBase64(eph.publicKey);
  requireCanonicalX25519SpkiB64(ephemeralDhPublicKeyB64, "buildCeremonyRequest ephemeral public key");

  const newDeviceId = DeviceRegistrationV1.deviceIdFor(deviceKeyPair.publicKeyB64);
  const body = {
    // V2 ONLY (audit #5). Hardcoded literals here were how the v1 schema drifted in the first
    // place — the constants come from the record class so the two cannot disagree.
    v: DEVICE_LINK_REQUEST_V2_VERSION,
    purpose: DEVICE_LINK_REQUEST_V2_PURPOSE,
    accountIdentityPublicKeyB64: accountSignPublicKeyB64,
    newDevicePublicKeyB64: deviceKeyPair.publicKeyB64,
    newDeviceId,
    deviceInboxBinding,
    ceremonyNonceB64: secrets.ceremonyNonceB64,
    issuedAtMs: nowMs,
    expiresAtMs: nowMs + requestTtlMs,
  };
  const sigBytes = await crypto.sign({
    privateKey: base64ToBytes(deviceKeyPair.privateKeyB64),
    msg: DeviceLinkRequestV2.signableBytes(body),
  });
  const linkRequest = new DeviceLinkRequestV2({ ...body, sig: { alg: "ed25519", sigB64: bytesToBase64(sigBytes) } });

  const aad = aadBytes({ accountSignPublicKeyB64, rendezvousPublicKeyB64, step: "request" });
  const plaintext = utf8(canonicalJSONStringify({
    linkRequest: linkRequest.toJSON(),
    ephemeralDhPublicKeyB64,
  }));
  const nonce = crypto.randomBytes(12);
  const ciphertext = await encryptAes256Gcm(crypto, secrets.requestKey, nonce, plaintext, aad);
  const payload = {
    v: 1,
    step: "request",
    nonceB64: bytesToBase64(nonce),
    ciphertextB64: bytesToBase64(ciphertext),
  };
  return {
    payload,
    payloadB64: bytesToBase64(utf8(JSON.stringify(payload))),
    linkRequest,
    ephemeralKeyPair: eph,
    thRequestB64: transcriptHashB64(aad, nonce, ciphertext),
    fingerprint: deviceLinkFingerprint(newDeviceId),
  };
}

/**
 * The device-link request VERSION GATE (audit #5).
 *
 * There is no handshake between two client devices — the request arrives as a sealed record at a
 * rendezvous coordinate — so nothing negotiated schema support beforehand and CONTRACT_VERSION
 * (a node↔client concern) cannot gate it. The check therefore lives on the decrypted body, and it
 * is TYPED so the approver can tell a terminal version mismatch apart from ordinary slot
 * corruption, which it keeps polling through.
 *
 * A v1 request is refused rather than upgraded: it carries no device-signed inbox binding, so the
 * approver would have nothing to register with `device.add` before releasing the leaf — exactly the
 * registration-before-release window the ceremony exists to close. Linking is safer refused.
 *
 * @throws {Error & {code:"DEVICE_LINK_UPGRADE_REQUIRED"}}
 */
export function assertSupportedLinkRequestVersion(rawRequest) {
  const v = rawRequest && typeof rawRequest === "object" ? rawRequest.v : undefined;
  if (v !== DEVICE_LINK_REQUEST_VERSION) return;
  const err = new Error(
    "this device sent a v" + DEVICE_LINK_REQUEST_VERSION + " device-link request, which cannot be"
      + " registered before its authority is released; update it and link again",
  );
  err.code = "DEVICE_LINK_UPGRADE_REQUIRED";
  err.requiredVersion = DEVICE_LINK_REQUEST_V2_VERSION;
  err.requiredPurpose = DEVICE_LINK_REQUEST_V2_PURPOSE;
  throw err;
}

export async function openCeremonyRequest({
  crypto,
  nowMs,
  psk,
  accountSignPublicKeyB64,
  rendezvousPublicKeyB64,
  payload,
  maxFutureSkewMs = 5 * 60_000,
} = {}) {
  requireCrypto(crypto, "openCeremonyRequest");
  requireNowMs(nowMs, "openCeremonyRequest");
  requirePsk(psk, "openCeremonyRequest");
  requireCanonicalSpkiB64(accountSignPublicKeyB64, "openCeremonyRequest.accountSignPublicKeyB64");
  requireCanonicalSpkiB64(rendezvousPublicKeyB64, "openCeremonyRequest.rendezvousPublicKeyB64");
  const src = payload && typeof payload === "object" ? payload : {};
  if (src.v !== 1 || src.step !== "request") {
    throw new Error("openCeremonyRequest: payload is not a v1 request");
  }
  const nonce = base64ToBytes(requireCanonicalB64(src.nonceB64, "openCeremonyRequest.nonceB64", { length: 12 }));
  const ciphertext = base64ToBytes(requireCanonicalB64(src.ciphertextB64, "openCeremonyRequest.ciphertextB64"));

  const secrets = await deriveCeremonySecrets({ crypto, psk });
  const aad = aadBytes({ accountSignPublicKeyB64, rendezvousPublicKeyB64, step: "request" });
  const plaintext = await decryptAes256Gcm(crypto, secrets.requestKey, nonce, ciphertext, aad);
  let inner;
  try {
    inner = JSON.parse(new TextDecoder().decode(plaintext));
  } catch (err) {
    throw new Error("openCeremonyRequest: request plaintext is not JSON: " + (err && err.message ? err.message : "unknown"));
  }

  // Structural validation happens at construction; then the C signature, the
  // account binding, the PSK-derived nonce, and the time window.
  const rawRequest = inner && typeof inner === "object" && inner.linkRequest && typeof inner.linkRequest === "object"
    ? inner.linkRequest
    : {};
  assertSupportedLinkRequestVersion(rawRequest);
  const linkRequest = new DeviceLinkRequestV2(rawRequest);
  const sigOk = await crypto.verify({
    publicKey: base64ToBytes(linkRequest.newDevicePublicKeyB64),
    msg: DeviceLinkRequestV2.signableBytes(linkRequest.toJSON()),
    sig: base64ToBytes(linkRequest.sig.sigB64),
  });
  if (sigOk !== true) {
    throw new Error("openCeremonyRequest: link request signature is invalid");
  }
  if (linkRequest.accountIdentityPublicKeyB64 !== accountSignPublicKeyB64) {
    throw new Error("openCeremonyRequest: link request targets a different account");
  }
  if (!constantTimeEqualBytes(base64ToBytes(linkRequest.ceremonyNonceB64), base64ToBytes(secrets.ceremonyNonceB64))) {
    throw new Error("openCeremonyRequest: ceremony nonce mismatch (request from a different ceremony)");
  }
  if (linkRequest.expiresAtMs <= nowMs) {
    throw new Error("openCeremonyRequest: link request expired");
  }
  if (linkRequest.issuedAtMs > nowMs + maxFutureSkewMs) {
    throw new Error("openCeremonyRequest: link request issued too far in the future");
  }
  const ephemeralDhPublicKeyB64 = requireCanonicalX25519SpkiB64(
    inner.ephemeralDhPublicKeyB64,
    "openCeremonyRequest.ephemeralDhPublicKeyB64",
  );

  return {
    linkRequest,
    ephemeralDhPublicKeyB64,
    thRequestB64: transcriptHashB64(aad, nonce, ciphertext),
    newDeviceId: linkRequest.newDeviceId,
    fingerprint: deviceLinkFingerprint(linkRequest.newDeviceId),
  };
}

// ---------------------------------------------------------------------------
// Response (the sealed delegation bundle)
// ---------------------------------------------------------------------------

// The wire bundle is the createDelegatedKeystoreAccount `delegation` shape
// MINUS deviceKeyPair (C's private key is minted on and never leaves the new
// device). Field names ride VERBATIM (drift guard in KeystoreAccount.js).
function validateWireBundle(bundle, accountSignPublicKeyB64, fn) {
  const src = bundle && typeof bundle === "object" ? bundle : null;
  if (!src) throw new Error(fn + " requires a delegationBundle object");
  const forbidden = ["deviceKeyPair", "accountSignPrivateKeyB64", "accountSignKeyPair", "mnemonic", "seed"];
  for (const key of forbidden) {
    if (src[key] !== undefined) {
      throw new Error(fn + ": delegationBundle must not contain " + key);
    }
  }
  if (src.accountSignPublicKeyB64 !== accountSignPublicKeyB64) {
    throw new Error(fn + ": delegationBundle.accountSignPublicKeyB64 does not match the ceremony account");
  }
  const dh = src.accountDhKeyPair && typeof src.accountDhKeyPair === "object" ? src.accountDhKeyPair : null;
  if (!dh) throw new Error(fn + ": delegationBundle requires accountDhKeyPair");
  requireCanonicalX25519SpkiB64(dh.publicKeyB64, fn + ".accountDhKeyPair.publicKeyB64");
  requireCanonicalB64(dh.privateKeyB64, fn + ".accountDhKeyPair.privateKeyB64");
  if (!Array.isArray(src.certChain) || src.certChain.length === 0) {
    throw new Error(fn + ": delegationBundle requires a non-empty certChain");
  }
  const cached = src.cachedDeviceSet === undefined ? null : src.cachedDeviceSet;
  if (cached !== null && (typeof cached !== "object" || Array.isArray(cached))) {
    throw new Error(fn + ": delegationBundle.cachedDeviceSet must be an object or null");
  }
  return {
    accountSignPublicKeyB64: src.accountSignPublicKeyB64,
    accountDhKeyPair: { publicKeyB64: dh.publicKeyB64, privateKeyB64: dh.privateKeyB64 },
    certChain: src.certChain,
    cachedDeviceSet: cached,
  };
}

export async function buildCeremonyResponse({
  crypto,
  psk,
  accountSignPublicKeyB64,
  rendezvousPublicKeyB64,
  thRequestB64,
  ephemeralDhPublicKeyB64,
  delegationBundle,
  ephemeralKeyPair = null,
} = {}) {
  requireCrypto(crypto, "buildCeremonyResponse");
  requirePsk(psk, "buildCeremonyResponse");
  requireCanonicalSpkiB64(accountSignPublicKeyB64, "buildCeremonyResponse.accountSignPublicKeyB64");
  requireCanonicalSpkiB64(rendezvousPublicKeyB64, "buildCeremonyResponse.rendezvousPublicKeyB64");
  requireCanonicalB64(thRequestB64, "buildCeremonyResponse.thRequestB64", { length: 32 });
  requireCanonicalX25519SpkiB64(ephemeralDhPublicKeyB64, "buildCeremonyResponse.ephemeralDhPublicKeyB64");
  const bundle = validateWireBundle(delegationBundle, accountSignPublicKeyB64, "buildCeremonyResponse");

  const eph = ephemeralKeyPair || await crypto.dhGenerateKeyPair({ alg: "X25519", fmt: "spki" });
  const eBPublicKeyB64 = bytesToBase64(eph.publicKey);
  const dhSecret = await crypto.dhDerive({
    privateKey: eph.privateKey,
    publicKey: base64ToBytes(ephemeralDhPublicKeyB64),
    alg: "X25519",
    fmt: "spki",
  });
  const masterSecret = await deriveMasterSecret({ crypto, psk, dhSecret, thRequestB64 });
  const responseKey = await deriveResponseKey({ crypto, masterSecret });

  const sealOnce = async (bundleToSeal) => {
    const aad = aadBytes({
      accountSignPublicKeyB64,
      rendezvousPublicKeyB64,
      step: "response",
      extra: { thRequestB64, ephemeralDhPublicKeyB64: eBPublicKeyB64 },
    });
    const plaintext = utf8(canonicalJSONStringify({ delegationBundle: bundleToSeal }));
    const nonce = crypto.randomBytes(12);
    const ciphertext = await encryptAes256Gcm(crypto, responseKey, nonce, plaintext, aad);
    const payload = {
      v: 1,
      step: "response",
      ephemeralDhPublicKeyB64: eBPublicKeyB64,
      nonceB64: bytesToBase64(nonce),
      ciphertextB64: bytesToBase64(ciphertext),
    };
    return {
      payload,
      payloadB64: bytesToBase64(utf8(JSON.stringify(payload))),
      thResponseB64: transcriptHashB64(aad, nonce, ciphertext),
    };
  };

  let sealed = await sealOnce(bundle);
  if (sealed.payloadB64.length > DEVICE_LINK_MAX_PAYLOAD_B64 && bundle.cachedDeviceSet !== null) {
    // The cached device set is a convenience, not a requirement — drop it
    // before failing the ceremony on size.
    sealed = await sealOnce({ ...bundle, cachedDeviceSet: null });
  }
  if (sealed.payloadB64.length > DEVICE_LINK_MAX_PAYLOAD_B64) {
    throw new Error("buildCeremonyResponse: sealed bundle exceeds the durable-record payload budget");
  }
  // The EXPECTED confirmation tag, derived here so a caller can persist it (P1#2a) without
  // persisting `masterSecret`. A registration that must survive a crash needs to recognise the
  // new device's confirmation later; storing this tag is sufficient for that, whereas storing the
  // master secret would put a key capable of decrypting the sealed response at rest.
  const confirmTagB64 = bytesToBase64(
    await deriveConfirmTag({ crypto, masterSecret, thResponseB64: sealed.thResponseB64 }),
  );
  return { ...sealed, masterSecret, confirmTagB64 };
}

export async function openCeremonyResponse({
  crypto,
  psk,
  accountSignPublicKeyB64,
  rendezvousPublicKeyB64,
  thRequestB64,
  ephemeralKeyPair,
  payload,
} = {}) {
  requireCrypto(crypto, "openCeremonyResponse");
  requirePsk(psk, "openCeremonyResponse");
  requireCanonicalSpkiB64(accountSignPublicKeyB64, "openCeremonyResponse.accountSignPublicKeyB64");
  requireCanonicalSpkiB64(rendezvousPublicKeyB64, "openCeremonyResponse.rendezvousPublicKeyB64");
  requireCanonicalB64(thRequestB64, "openCeremonyResponse.thRequestB64", { length: 32 });
  if (!ephemeralKeyPair || !(ephemeralKeyPair.privateKey instanceof Uint8Array)) {
    throw new Error("openCeremonyResponse requires the requester's ephemeralKeyPair (forward secrecy: the psk alone cannot open the response)");
  }
  const src = payload && typeof payload === "object" ? payload : {};
  if (src.v !== 1 || src.step !== "response") {
    throw new Error("openCeremonyResponse: payload is not a v1 response");
  }
  const eBPublicKeyB64 = requireCanonicalX25519SpkiB64(src.ephemeralDhPublicKeyB64, "openCeremonyResponse.ephemeralDhPublicKeyB64");
  const nonce = base64ToBytes(requireCanonicalB64(src.nonceB64, "openCeremonyResponse.nonceB64", { length: 12 }));
  const ciphertext = base64ToBytes(requireCanonicalB64(src.ciphertextB64, "openCeremonyResponse.ciphertextB64"));

  const dhSecret = await crypto.dhDerive({
    privateKey: ephemeralKeyPair.privateKey,
    publicKey: base64ToBytes(eBPublicKeyB64),
    alg: "X25519",
    fmt: "spki",
  });
  const masterSecret = await deriveMasterSecret({ crypto, psk, dhSecret, thRequestB64 });
  const responseKey = await deriveResponseKey({ crypto, masterSecret });
  const aad = aadBytes({
    accountSignPublicKeyB64,
    rendezvousPublicKeyB64,
    step: "response",
    extra: { thRequestB64, ephemeralDhPublicKeyB64: eBPublicKeyB64 },
  });
  const plaintext = await decryptAes256Gcm(crypto, responseKey, nonce, ciphertext, aad);
  let inner;
  try {
    inner = JSON.parse(new TextDecoder().decode(plaintext));
  } catch (err) {
    throw new Error("openCeremonyResponse: response plaintext is not JSON: " + (err && err.message ? err.message : "unknown"));
  }
  const delegationBundle = validateWireBundle(
    inner && typeof inner === "object" ? inner.delegationBundle : null,
    accountSignPublicKeyB64,
    "openCeremonyResponse",
  );
  return {
    delegationBundle,
    masterSecret,
    thResponseB64: transcriptHashB64(aad, nonce, ciphertext),
  };
}

// ---------------------------------------------------------------------------
// Key confirmation
// ---------------------------------------------------------------------------

export async function buildCeremonyConfirm({ crypto, masterSecret, thResponseB64 } = {}) {
  requireCrypto(crypto, "buildCeremonyConfirm");
  if (!(masterSecret instanceof Uint8Array) || masterSecret.length !== 32) {
    throw new Error("buildCeremonyConfirm requires the 32-byte masterSecret");
  }
  requireCanonicalB64(thResponseB64, "buildCeremonyConfirm.thResponseB64", { length: 32 });
  const tag = await deriveConfirmTag({ crypto, masterSecret, thResponseB64 });
  const payload = { v: 1, step: "confirm", tagB64: bytesToBase64(tag) };
  return { payload, payloadB64: bytesToBase64(utf8(JSON.stringify(payload))) };
}

export async function verifyCeremonyConfirm({ crypto, masterSecret, thResponseB64, payload } = {}) {
  requireCrypto(crypto, "verifyCeremonyConfirm");
  if (!(masterSecret instanceof Uint8Array) || masterSecret.length !== 32) {
    throw new Error("verifyCeremonyConfirm requires the 32-byte masterSecret");
  }
  requireCanonicalB64(thResponseB64, "verifyCeremonyConfirm.thResponseB64", { length: 32 });
  const src = payload && typeof payload === "object" ? payload : {};
  if (src.v !== 1 || src.step !== "confirm" || typeof src.tagB64 !== "string") return false;
  let claimed;
  try {
    claimed = base64ToBytes(src.tagB64);
  } catch (err) {
    return false;
  }
  const expected = await deriveConfirmTag({ crypto, masterSecret, thResponseB64 });
  return constantTimeEqualBytes(claimed, expected);
}

// ---------------------------------------------------------------------------
// Durable-record helpers (the slot-coordinate SSOT for both SDK machines)
// ---------------------------------------------------------------------------

export async function sealCeremonyRecord({ crypto, nowMs, rendezvousKeyPair, recordId, payloadB64, expiresAtMs } = {}) {
  requireCrypto(crypto, "sealCeremonyRecord");
  requireNowMs(nowMs, "sealCeremonyRecord");
  if (!rendezvousKeyPair || !rendezvousKeyPair.publicKeyB64 || !rendezvousKeyPair.privateKeyB64) {
    throw new Error("sealCeremonyRecord requires rendezvousKeyPair with publicKeyB64 and privateKeyB64");
  }
  if (typeof recordId !== "string" || recordId.length === 0) {
    throw new Error("sealCeremonyRecord requires recordId");
  }
  if (typeof payloadB64 !== "string" || payloadB64.length === 0) {
    throw new Error("sealCeremonyRecord requires payloadB64");
  }
  if (typeof expiresAtMs !== "number" || !Number.isFinite(expiresAtMs) || expiresAtMs <= nowMs) {
    throw new Error("sealCeremonyRecord requires expiresAtMs after nowMs");
  }
  const record = buildDurableRecordV1({
    recordKind: DEVICE_LINK_RECORD_KIND,
    recordId,
    publisherPublicKeyB64: rendezvousKeyPair.publicKeyB64,
    payloadB64,
    issuedAtMs: nowMs,
    expiresAtMs,
  });
  const sigBytes = await crypto.sign({
    privateKey: base64ToBytes(rendezvousKeyPair.privateKeyB64),
    msg: durableRecordSignableBytes(record),
  });
  record.sigB64 = bytesToBase64(sigBytes);
  return record;
}

// Fetched records are re-verified CLIENT-SIDE — the serving node is untrusted.
export async function verifyCeremonyRecord({ crypto, nowMs, record, rendezvousPublicKeyB64, recordId } = {}) {
  requireCrypto(crypto, "verifyCeremonyRecord");
  requireNowMs(nowMs, "verifyCeremonyRecord");
  requireCanonicalSpkiB64(rendezvousPublicKeyB64, "verifyCeremonyRecord.rendezvousPublicKeyB64");
  const src = record && typeof record === "object" ? record : null;
  if (!src) throw new Error("verifyCeremonyRecord requires a record");
  if (src.v !== DURABLE_RECORD_VERSION) throw new Error("verifyCeremonyRecord: not a DurableRecordV1");
  if (src.recordKind !== DEVICE_LINK_RECORD_KIND) throw new Error("verifyCeremonyRecord: wrong recordKind");
  if (src.recordId !== recordId) throw new Error("verifyCeremonyRecord: wrong recordId");
  if (src.publisherPublicKeyB64 !== rendezvousPublicKeyB64) {
    throw new Error("verifyCeremonyRecord: record is not published under this ceremony's rendezvous key");
  }
  if (!Number.isFinite(src.expiresAtMs) || src.expiresAtMs <= nowMs) {
    throw new Error("verifyCeremonyRecord: record expired");
  }
  const sigOk = await crypto.verify({
    publicKey: base64ToBytes(rendezvousPublicKeyB64),
    msg: durableRecordSignableBytes(src),
    sig: base64ToBytes(String(src.sigB64 || "")),
  });
  if (sigOk !== true) throw new Error("verifyCeremonyRecord: record signature is invalid");
  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(base64ToBytes(src.payloadB64)));
  } catch (err) {
    throw new Error("verifyCeremonyRecord: payload is not JSON: " + (err && err.message ? err.message : "unknown"));
  }
  return payload;
}
