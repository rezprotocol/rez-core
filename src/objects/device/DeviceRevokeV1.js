import { RRecord } from "../../base/index.js";
import { isNonEmptyString } from "../../util/strings.js";
import { canonicalJSONStringify } from "../../util/canonicalize.js";
import { DeviceRegistrationV1 } from "./DeviceRegistrationV1.js";
import {
  requireCanonicalSpkiB64,
  isFiniteNumber,
  normalizeSig,
  validateEd25519Sig,
} from "./deviceRecordShared.js";

export const DEVICE_REVOKE_VERSION = 1;
export const DEVICE_REVOKE_PURPOSE = "rez:device-revoke:v1";

/**
 * DeviceRevokeV1 — removes a device from an account (S2.5 fix P1a). Signature
 * root = the ACCOUNT identity key (the canonical authority that also vouches for
 * devices via DeviceRegistrationV1). A trusted-device-signed revoke is a later
 * extension (Slice 7); the home's enforcement keys on the revoked deviceId either
 * way.
 *
 * Revocation is FAIL-CLOSED and HOME-ENFORCED because E2EE alone cannot claw back
 * keys already on the revoked device: a DeviceRevokeV1 invalidates that device's
 * DeviceInboxBindingV1 at the home, so the durable inbox rejects deposits to —
 * and reads/cursorAck from — the revoked device. Senders also drop it on the next
 * device-set refresh, but home enforcement is the backstop that makes a
 * partial-propagation revoke safe (a lagging sender cannot reach the device).
 *
 * Signed body (everything except `sig`):
 *   { v, purpose, accountIdentityPublicKeyB64, revokedDeviceId,
 *     revokedDevicePublicKeyB64, issuedAtMs, expiresAtMs }
 * `revokedDeviceId` is self-certifying from `revokedDevicePublicKeyB64`. sig =
 * Ed25519 over canonicalJSONStringify(body) by the account key.
 */
export class DeviceRevokeV1 extends RRecord {
  static type = "DeviceRevokeV1";

  constructor({
    v = DEVICE_REVOKE_VERSION,
    purpose = DEVICE_REVOKE_PURPOSE,
    accountIdentityPublicKeyB64,
    revokedDeviceId,
    revokedDevicePublicKeyB64,
    issuedAtMs,
    expiresAtMs,
    sig,
  } = {}) {
    super();
    this.v = v;
    this.purpose = purpose;
    this.accountIdentityPublicKeyB64 = accountIdentityPublicKeyB64;
    this.revokedDeviceId = revokedDeviceId;
    this.revokedDevicePublicKeyB64 = revokedDevicePublicKeyB64;
    this.issuedAtMs = issuedAtMs;
    this.expiresAtMs = expiresAtMs;
    this.sig = normalizeSig(sig);
    this._seal();
  }

  validate() {
    this.assert(this.v === DEVICE_REVOKE_VERSION, "DeviceRevokeV1.v must be 1", { v: this.v });
    this.assert(this.purpose === DEVICE_REVOKE_PURPOSE, "DeviceRevokeV1.purpose must be " + DEVICE_REVOKE_PURPOSE, { purpose: this.purpose });
    requireCanonicalSpkiB64(this.accountIdentityPublicKeyB64, "DeviceRevokeV1.accountIdentityPublicKeyB64");
    requireCanonicalSpkiB64(this.revokedDevicePublicKeyB64, "DeviceRevokeV1.revokedDevicePublicKeyB64");
    this.assert(isNonEmptyString(this.revokedDeviceId), "DeviceRevokeV1.revokedDeviceId must be non-empty string", { revokedDeviceId: this.revokedDeviceId });
    const expectedDeviceId = DeviceRegistrationV1.deviceIdFor(this.revokedDevicePublicKeyB64);
    this.assert(this.revokedDeviceId === expectedDeviceId, "DeviceRevokeV1.revokedDeviceId must equal rez:dev:sha256(revokedDevicePublicKeyB64)", { revokedDeviceId: this.revokedDeviceId, expectedDeviceId });
    this.assert(isFiniteNumber(this.issuedAtMs), "DeviceRevokeV1.issuedAtMs must be number", { issuedAtMs: this.issuedAtMs });
    this.assert(isFiniteNumber(this.expiresAtMs), "DeviceRevokeV1.expiresAtMs must be number", { expiresAtMs: this.expiresAtMs });
    this.assert(this.expiresAtMs > this.issuedAtMs, "DeviceRevokeV1.expiresAtMs must be after issuedAtMs", { issuedAtMs: this.issuedAtMs, expiresAtMs: this.expiresAtMs });
    validateEd25519Sig(this.sig, "DeviceRevokeV1.sig");
  }

  /**
   * The exact bytes the account key signs and every verifier recomputes — the
   * signed body minus `sig`. Deterministic via canonical JSON.
   */
  static signableBytes({ v, purpose, accountIdentityPublicKeyB64, revokedDeviceId, revokedDevicePublicKeyB64, issuedAtMs, expiresAtMs } = {}) {
    const body = { v, purpose, accountIdentityPublicKeyB64, revokedDeviceId, revokedDevicePublicKeyB64, issuedAtMs, expiresAtMs };
    return new TextEncoder().encode(canonicalJSONStringify(body));
  }
}
