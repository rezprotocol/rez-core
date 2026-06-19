import { base64ToBytes } from "../../util/bytes.js";
import { DeviceRegistrationV1 } from "./DeviceRegistrationV1.js";

/**
 * Verify a DeviceRegistrationV1: the account identity key signed a binding that
 * vouches for the device key, AND the self-certifying deviceId matches the
 * device key. Self-contained — the signing key (accountIdentityPublicKeyB64) is
 * inside the signed body, so no external key lookup is needed (cf. durable
 * records). When `nowMs` is provided, the issued/expires window is enforced too.
 *
 * @param {object} opts
 * @param {object} opts.registration — DeviceRegistrationV1 instance or its toJSON()
 * @param {{ verify(args:{publicKey:Uint8Array,msg:Uint8Array,sig:Uint8Array}):Promise<boolean> }} opts.crypto
 * @param {number} [opts.nowMs] — when a finite number, reject not-yet-valid / expired records
 * @returns {Promise<{ok:boolean, reason?:string, deviceId?:string}>}
 */
export async function verifyDeviceRegistrationV1({ registration, crypto, nowMs } = {}) {
  if (!registration || typeof registration !== "object") {
    return { ok: false, reason: "invalid registration" };
  }
  if (!crypto || typeof crypto.verify !== "function") {
    return { ok: false, reason: "crypto.verify required" };
  }
  const json = typeof registration.toJSON === "function" ? registration.toJSON() : registration;

  if (json.v !== 1) {
    return { ok: false, reason: "unsupported version" };
  }

  const accountIdentityPublicKeyB64 = json.accountIdentityPublicKeyB64;
  const devicePublicKeyB64 = json.devicePublicKeyB64;
  if (typeof accountIdentityPublicKeyB64 !== "string" || accountIdentityPublicKeyB64.length === 0) {
    return { ok: false, reason: "missing accountIdentityPublicKeyB64" };
  }
  if (typeof devicePublicKeyB64 !== "string" || devicePublicKeyB64.length === 0) {
    return { ok: false, reason: "missing devicePublicKeyB64" };
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

  if (!json.sig || typeof json.sig !== "object" || json.sig.alg !== "ed25519") {
    return { ok: false, reason: "missing or unsupported signature" };
  }

  let signature;
  let accountPub;
  try {
    signature = json.sig.sig instanceof Uint8Array ? json.sig.sig : new Uint8Array(json.sig.sig);
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

  if (typeof nowMs === "number" && Number.isFinite(nowMs)) {
    if (nowMs < json.issuedAtMs) {
      return { ok: false, reason: "not yet valid" };
    }
    if (nowMs >= json.expiresAtMs) {
      return { ok: false, reason: "expired" };
    }
  }

  return { ok: true, deviceId: json.deviceId };
}
