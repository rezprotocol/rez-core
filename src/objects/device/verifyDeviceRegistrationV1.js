import { base64ToBytes } from "../../util/bytes.js";
import { DeviceRegistrationV1, DEVICE_REGISTRATION_PURPOSE } from "./DeviceRegistrationV1.js";

/**
 * Verify a DeviceRegistrationV1 AGAINST AN EXPECTED ACCOUNT.
 *
 * The signature alone only proves the registration is self-consistent — it is
 * signed by WHATEVER account key the body carries, so a self-consistent
 * registration for an ATTACKER's account verifies too. To use this as a trust
 * decision ("is this a device of the account I expect?") the caller MUST pass
 * the account they expect; verification fails on mismatch. There is no
 * "trust whatever the record claims" mode — if you only want to read the
 * claimed account, read `registration.accountIdentityPublicKeyB64` directly and
 * make that trust decision explicitly.
 *
 * Also enforces (1) the self-certifying deviceId matches the device key
 * (anti-substitution), and (2) the issued/expires window — `nowMs` is REQUIRED
 * (no fail-open on expiry for an authentication-grade record).
 *
 * @param {object} opts
 * @param {object} opts.registration — DeviceRegistrationV1 instance or its toJSON()
 * @param {string} opts.expectedAccountIdentityPublicKeyB64 — REQUIRED trust anchor: the account whose device this must be
 * @param {{ verify(args:{publicKey:Uint8Array,msg:Uint8Array,sig:Uint8Array}):Promise<boolean> }} opts.crypto
 * @param {number} opts.nowMs — REQUIRED finite epoch ms; rejects not-yet-valid / expired records
 * @returns {Promise<{ok:boolean, reason?:string, deviceId?:string}>}
 */
export async function verifyDeviceRegistrationV1({ registration, expectedAccountIdentityPublicKeyB64, crypto, nowMs } = {}) {
  if (!registration || typeof registration !== "object") {
    return { ok: false, reason: "invalid registration" };
  }
  if (!crypto || typeof crypto.verify !== "function") {
    return { ok: false, reason: "crypto.verify required" };
  }
  if (typeof expectedAccountIdentityPublicKeyB64 !== "string" || expectedAccountIdentityPublicKeyB64.trim().length === 0) {
    return { ok: false, reason: "expectedAccountIdentityPublicKeyB64 required (trust anchor)" };
  }
  if (typeof nowMs !== "number" || !Number.isFinite(nowMs)) {
    return { ok: false, reason: "nowMs required (finite) for expiry check" };
  }
  const json = typeof registration.toJSON === "function" ? registration.toJSON() : registration;

  if (json.v !== 1) {
    return { ok: false, reason: "unsupported version" };
  }
  // Domain separator (audit P2): refuse a signature minted for a different
  // record purpose. It is inside the signed body, so this is covered by the
  // signature too, but rejecting early gives a precise reason.
  if (json.purpose !== DEVICE_REGISTRATION_PURPOSE) {
    return { ok: false, reason: "purpose mismatch" };
  }

  const accountIdentityPublicKeyB64 = json.accountIdentityPublicKeyB64;
  const devicePublicKeyB64 = json.devicePublicKeyB64;
  if (typeof accountIdentityPublicKeyB64 !== "string" || accountIdentityPublicKeyB64.length === 0) {
    return { ok: false, reason: "missing accountIdentityPublicKeyB64" };
  }
  if (typeof devicePublicKeyB64 !== "string" || devicePublicKeyB64.length === 0) {
    return { ok: false, reason: "missing devicePublicKeyB64" };
  }

  // TRUST ANCHOR: the registration must vouch for a device of the EXPECTED
  // account, not just any self-consistent account (the impersonation gap).
  if (accountIdentityPublicKeyB64.trim() !== expectedAccountIdentityPublicKeyB64.trim()) {
    return { ok: false, reason: "account mismatch (not the expected account)" };
  }

  // Self-certifying deviceId must match the device key (anti-substitution): a
  // registration cannot vouch for one key while advertising another's id.
  let expectedDeviceId;
  try {
    expectedDeviceId = DeviceRegistrationV1.deviceIdFor(devicePublicKeyB64);
  } catch (err) {
    return { ok: false, reason: "device key not hashable: " + (err && err.message ? err.message : "unknown") };
  }
  if (json.deviceId !== expectedDeviceId) {
    return { ok: false, reason: "deviceId does not match device key" };
  }

  if (!json.sig || typeof json.sig !== "object" || json.sig.alg !== "ed25519" || typeof json.sig.sigB64 !== "string") {
    return { ok: false, reason: "missing or unsupported signature" };
  }

  let signature;
  let accountPub;
  try {
    signature = base64ToBytes(json.sig.sigB64);
    accountPub = base64ToBytes(accountIdentityPublicKeyB64);
  } catch (err) {
    return { ok: false, reason: "malformed signature or key bytes: " + (err && err.message ? err.message : "unknown") };
  }
  if (!(signature instanceof Uint8Array) || signature.length === 0) {
    return { ok: false, reason: "empty signature" };
  }

  const msg = DeviceRegistrationV1.signableBytes(json);
  const ok = await crypto.verify({ publicKey: accountPub, msg, sig: signature });
  if (!ok) {
    return { ok: false, reason: "signature invalid" };
  }

  // nowMs is guaranteed finite (required + validated above) — always enforce.
  if (nowMs < json.issuedAtMs) {
    return { ok: false, reason: "not yet valid" };
  }
  if (nowMs >= json.expiresAtMs) {
    return { ok: false, reason: "expired" };
  }

  return { ok: true, deviceId: json.deviceId };
}
