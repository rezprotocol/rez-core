import { RRecord } from "../../base/index.js";
import { isNonEmptyString } from "../../util/strings.js";
import { canonicalJSONStringify } from "../../util/canonicalize.js";
import { DeviceRegistrationV1 } from "./DeviceRegistrationV1.js";
import {
  requireCanonicalB64,
  requireCanonicalSpkiB64,
  isFiniteNumber,
  normalizeSig,
  validateEd25519Sig,
} from "./deviceRecordShared.js";

export const DEVICE_PREKEY_BUNDLE_VERSION = 1;
export const DEVICE_PREKEY_BUNDLE_PURPOSE = "rez:device-prekey-bundle:v1";

/**
 * DevicePrekeyBundleV1 — a single device's X3DH prekey bundle, delivered to a
 * peer so the peer can establish a per-device ratchet session (S2.5 Slice 3).
 * Prekeys are NEVER published to a public directory — this record rides the
 * encrypted-to-peer device set (carried alongside DeviceSetRecordV1 in a
 * DurableRecordV1.payloadB64 at a peer-derived slot) and, on the initial link,
 * the invite.
 *
 * Signature root = the DEVICE key (C). The device signs its own prekey material;
 * the device→account chain (C belongs to account B) is supplied SEPARATELY by
 * DeviceRegistrationV1 (B signs over C) and the account-signed DeviceSetRecordV1
 * that lists this deviceId. A consumer establishing a session verifies BOTH:
 * the account vouches the device is in its set, and the device signs its prekeys.
 *
 * Anti-substitution (S2.5 fix P1): the C-signed body staples the account pubkey
 * (B), the device key (C) + self-cert deviceId, the device's inbox, a monotonic
 * prekey version, expiry, AND the whole wrapped `bundleJson` together — so a
 * bundle can't be lifted and re-stapled to a different account, device, inbox,
 * or prekey set without breaking the signature. `bundleJson` is the live
 * X3DHKeyExchange.serializeBundle output (PeerLinkService.buildDevicePreKeyBundle
 * → binding.x3dh), whose `identitySigningPublicKeyB64` IS the device key C.
 *
 * Signed body (everything except `sig`):
 *   { v, purpose, accountIdentityPublicKeyB64, devicePublicKeyB64, deviceId,
 *     inboxId, prekeyVersion, bundleJson, issuedAtMs, expiresAtMs }
 * sig = Ed25519 over canonicalJSONStringify(body) by the device key,
 * carried as `{ alg: "ed25519", sigB64 }`.
 */
export class DevicePrekeyBundleV1 extends RRecord {
  static type = "DevicePrekeyBundleV1";

  constructor({
    v = DEVICE_PREKEY_BUNDLE_VERSION,
    purpose = DEVICE_PREKEY_BUNDLE_PURPOSE,
    accountIdentityPublicKeyB64,
    devicePublicKeyB64,
    deviceId,
    inboxId,
    prekeyVersion,
    bundleJson,
    issuedAtMs,
    expiresAtMs,
    sig,
  } = {}) {
    super();
    this.v = v;
    this.purpose = purpose;
    this.accountIdentityPublicKeyB64 = accountIdentityPublicKeyB64;
    this.devicePublicKeyB64 = devicePublicKeyB64;
    this.deviceId = deviceId;
    this.inboxId = inboxId;
    this.prekeyVersion = prekeyVersion;
    this.bundleJson = normalizeBundleJson(bundleJson);
    this.issuedAtMs = issuedAtMs;
    this.expiresAtMs = expiresAtMs;
    this.sig = normalizeSig(sig);
    this._seal();
  }

  validate() {
    this.assert(this.v === DEVICE_PREKEY_BUNDLE_VERSION, "DevicePrekeyBundleV1.v must be 1", { v: this.v });
    this.assert(this.purpose === DEVICE_PREKEY_BUNDLE_PURPOSE, "DevicePrekeyBundleV1.purpose must be " + DEVICE_PREKEY_BUNDLE_PURPOSE, { purpose: this.purpose });
    requireCanonicalSpkiB64(this.accountIdentityPublicKeyB64, "DevicePrekeyBundleV1.accountIdentityPublicKeyB64");
    requireCanonicalSpkiB64(this.devicePublicKeyB64, "DevicePrekeyBundleV1.devicePublicKeyB64");
    this.assert(isNonEmptyString(this.deviceId), "DevicePrekeyBundleV1.deviceId must be non-empty string", { deviceId: this.deviceId });
    const expectedDeviceId = DeviceRegistrationV1.deviceIdFor(this.devicePublicKeyB64);
    this.assert(this.deviceId === expectedDeviceId, "DevicePrekeyBundleV1.deviceId must equal rez:dev:sha256(devicePublicKeyB64)", { deviceId: this.deviceId, expectedDeviceId });
    this.assert(isNonEmptyString(this.inboxId), "DevicePrekeyBundleV1.inboxId must be non-empty string", { inboxId: this.inboxId });
    this.assert(Number.isInteger(this.prekeyVersion) && this.prekeyVersion >= 1, "DevicePrekeyBundleV1.prekeyVersion must be a positive integer", { prekeyVersion: this.prekeyVersion });
    validateBundleJson(this.bundleJson, this.devicePublicKeyB64, (cond, msg, ctx) => this.assert(cond, msg, ctx));
    this.assert(isFiniteNumber(this.issuedAtMs), "DevicePrekeyBundleV1.issuedAtMs must be number", { issuedAtMs: this.issuedAtMs });
    this.assert(isFiniteNumber(this.expiresAtMs), "DevicePrekeyBundleV1.expiresAtMs must be number", { expiresAtMs: this.expiresAtMs });
    this.assert(this.expiresAtMs > this.issuedAtMs, "DevicePrekeyBundleV1.expiresAtMs must be after issuedAtMs", { issuedAtMs: this.issuedAtMs, expiresAtMs: this.expiresAtMs });
    validateEd25519Sig(this.sig, "DevicePrekeyBundleV1.sig");
  }

  /**
   * The exact bytes the device key signs and every verifier recomputes — the
   * signed body minus `sig`. `bundleJson` is projected to its canonical field
   * set so signer and verifier agree byte-for-byte regardless of key order.
   */
  static signableBytes({ v, purpose, accountIdentityPublicKeyB64, devicePublicKeyB64, deviceId, inboxId, prekeyVersion, bundleJson, issuedAtMs, expiresAtMs } = {}) {
    const body = {
      v,
      purpose,
      accountIdentityPublicKeyB64,
      devicePublicKeyB64,
      deviceId,
      inboxId,
      prekeyVersion,
      bundleJson: normalizeBundleJson(bundleJson),
      issuedAtMs,
      expiresAtMs,
    };
    return new TextEncoder().encode(canonicalJSONStringify(body));
  }
}

// Project the live X3DHKeyExchange.serializeBundle shape to a stable field set so
// signer/verifier canonicalize identically. Unknown fields are dropped (the
// wrapping record's signature covers exactly these).
function normalizeBundleJson(bundleJson) {
  if (!bundleJson || typeof bundleJson !== "object") return bundleJson;
  return {
    receiverId: bundleJson.receiverId,
    identitySigningPublicKeyB64: bundleJson.identitySigningPublicKeyB64,
    identityDhPublicKeyB64: bundleJson.identityDhPublicKeyB64,
    identityDhSignatureB64: bundleJson.identityDhSignatureB64,
    signedPreKeyPublicB64: bundleJson.signedPreKeyPublicB64,
    signedPreKeySignatureB64: bundleJson.signedPreKeySignatureB64,
    accountIdentityPublicKeyB64: bundleJson.accountIdentityPublicKeyB64 == null ? null : bundleJson.accountIdentityPublicKeyB64,
    accountBindingSigB64: bundleJson.accountBindingSigB64 == null ? null : bundleJson.accountBindingSigB64,
    accountBindingIssuedAtMs: bundleJson.accountBindingIssuedAtMs == null ? null : bundleJson.accountBindingIssuedAtMs,
    accountBindingExpiresAtMs: bundleJson.accountBindingExpiresAtMs == null ? null : bundleJson.accountBindingExpiresAtMs,
    oneTimePreKeyPublicB64: bundleJson.oneTimePreKeyPublicB64 == null ? null : bundleJson.oneTimePreKeyPublicB64,
  };
}

// Validate the wrapped X3DH bundle enough to fail loud on a malformed/substituted
// bundle. The full cryptographic verification (DH/prekey signatures) happens at
// session establishment; here we pin the anti-substitution anchor — the bundle's
// signing identity MUST be the device key C this record is bound to.
function validateBundleJson(bundleJson, devicePublicKeyB64, assertFn) {
  assertFn(bundleJson && typeof bundleJson === "object", "DevicePrekeyBundleV1.bundleJson must be an object", { bundleJson });
  requireCanonicalSpkiB64(bundleJson.identitySigningPublicKeyB64, "DevicePrekeyBundleV1.bundleJson.identitySigningPublicKeyB64");
  assertFn(
    bundleJson.identitySigningPublicKeyB64 === devicePublicKeyB64,
    "DevicePrekeyBundleV1.bundleJson.identitySigningPublicKeyB64 must equal the bound device key",
    { identitySigningPublicKeyB64: bundleJson.identitySigningPublicKeyB64, devicePublicKeyB64 },
  );
  requireCanonicalB64(bundleJson.identityDhPublicKeyB64, "DevicePrekeyBundleV1.bundleJson.identityDhPublicKeyB64");
  requireCanonicalB64(bundleJson.identityDhSignatureB64, "DevicePrekeyBundleV1.bundleJson.identityDhSignatureB64");
  requireCanonicalB64(bundleJson.signedPreKeyPublicB64, "DevicePrekeyBundleV1.bundleJson.signedPreKeyPublicB64");
  requireCanonicalB64(bundleJson.signedPreKeySignatureB64, "DevicePrekeyBundleV1.bundleJson.signedPreKeySignatureB64");
  if (bundleJson.oneTimePreKeyPublicB64 != null) {
    requireCanonicalB64(bundleJson.oneTimePreKeyPublicB64, "DevicePrekeyBundleV1.bundleJson.oneTimePreKeyPublicB64");
  }
}
