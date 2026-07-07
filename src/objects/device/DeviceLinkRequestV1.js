import { RRecord } from "../../base/index.js";
import { isNonEmptyString } from "../../util/strings.js";
import { canonicalJSONStringify } from "../../util/canonicalize.js";
import { DeviceRegistrationV1 } from "./DeviceRegistrationV1.js";
import {
  requireCanonicalSpkiB64,
  requireCanonicalB64,
  isFiniteNumber,
  normalizeSig,
  validateEd25519Sig,
} from "./deviceRecordShared.js";

export const DEVICE_LINK_REQUEST_VERSION = 1;
export const DEVICE_LINK_REQUEST_PURPOSE = "rez:device-link-request:v1";

/**
 * DeviceLinkRequestV1 — a NEW device's signed request to be linked to an account
 * (S2.5 device-linking ceremony). Signature root = the NEW DEVICE key: the
 * request proves the requester controls the device key it wants registered, and
 * binds that key to the target account + a ceremony nonce.
 *
 * This is the REQUEST half only. The AUTHORIZATION — an already-trusted device or
 * the account key approving the link, which yields the account-signed
 * DeviceRegistrationV1 — is the ceremony's second step (Slice 6). The
 * `ceremonyNonceB64` is an out-of-band secret (QR/PSK) exchanged between the new
 * device and the authorizer; carrying it in the signed body binds this request to
 * one specific ceremony so a captured request cannot be replayed into another.
 *
 * Signed body (everything except `sig`):
 *   { v, purpose, accountIdentityPublicKeyB64, newDevicePublicKeyB64,
 *     newDeviceId, ceremonyNonceB64, issuedAtMs, expiresAtMs }
 * `newDeviceId` is self-certifying from `newDevicePublicKeyB64`. sig = Ed25519
 * over canonicalJSONStringify(body) by the NEW device key.
 */
export class DeviceLinkRequestV1 extends RRecord {
  static type = "DeviceLinkRequestV1";

  constructor({
    v = DEVICE_LINK_REQUEST_VERSION,
    purpose = DEVICE_LINK_REQUEST_PURPOSE,
    accountIdentityPublicKeyB64,
    newDevicePublicKeyB64,
    newDeviceId,
    ceremonyNonceB64,
    issuedAtMs,
    expiresAtMs,
    sig,
  } = {}) {
    super();
    this.v = v;
    this.purpose = purpose;
    this.accountIdentityPublicKeyB64 = accountIdentityPublicKeyB64;
    this.newDevicePublicKeyB64 = newDevicePublicKeyB64;
    this.newDeviceId = newDeviceId;
    this.ceremonyNonceB64 = ceremonyNonceB64;
    this.issuedAtMs = issuedAtMs;
    this.expiresAtMs = expiresAtMs;
    this.sig = normalizeSig(sig);
    this._seal();
  }

  validate() {
    this.assert(this.v === DEVICE_LINK_REQUEST_VERSION, "DeviceLinkRequestV1.v must be 1", { v: this.v });
    this.assert(this.purpose === DEVICE_LINK_REQUEST_PURPOSE, "DeviceLinkRequestV1.purpose must be " + DEVICE_LINK_REQUEST_PURPOSE, { purpose: this.purpose });
    requireCanonicalSpkiB64(this.accountIdentityPublicKeyB64, "DeviceLinkRequestV1.accountIdentityPublicKeyB64");
    requireCanonicalSpkiB64(this.newDevicePublicKeyB64, "DeviceLinkRequestV1.newDevicePublicKeyB64");
    this.assert(isNonEmptyString(this.newDeviceId), "DeviceLinkRequestV1.newDeviceId must be non-empty string", { newDeviceId: this.newDeviceId });
    const expectedDeviceId = DeviceRegistrationV1.deviceIdFor(this.newDevicePublicKeyB64);
    this.assert(this.newDeviceId === expectedDeviceId, "DeviceLinkRequestV1.newDeviceId must equal rez:dev:sha256(newDevicePublicKeyB64)", { newDeviceId: this.newDeviceId, expectedDeviceId });
    // 256-bit pin (S10): the nonce is the PSK-derived ceremony binding — a
    // shorter value would weaken the replay binding it exists to provide.
    requireCanonicalB64(this.ceremonyNonceB64, "DeviceLinkRequestV1.ceremonyNonceB64", { length: 32 });
    this.assert(isFiniteNumber(this.issuedAtMs), "DeviceLinkRequestV1.issuedAtMs must be number", { issuedAtMs: this.issuedAtMs });
    this.assert(isFiniteNumber(this.expiresAtMs), "DeviceLinkRequestV1.expiresAtMs must be number", { expiresAtMs: this.expiresAtMs });
    this.assert(this.expiresAtMs > this.issuedAtMs, "DeviceLinkRequestV1.expiresAtMs must be after issuedAtMs", { issuedAtMs: this.issuedAtMs, expiresAtMs: this.expiresAtMs });
    validateEd25519Sig(this.sig, "DeviceLinkRequestV1.sig");
  }

  /**
   * The exact bytes the new device key signs and every verifier recomputes — the
   * signed body minus `sig`. Deterministic via canonical JSON.
   */
  static signableBytes({ v, purpose, accountIdentityPublicKeyB64, newDevicePublicKeyB64, newDeviceId, ceremonyNonceB64, issuedAtMs, expiresAtMs } = {}) {
    const body = { v, purpose, accountIdentityPublicKeyB64, newDevicePublicKeyB64, newDeviceId, ceremonyNonceB64, issuedAtMs, expiresAtMs };
    return new TextEncoder().encode(canonicalJSONStringify(body));
  }
}
