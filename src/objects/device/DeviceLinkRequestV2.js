import { RRecord } from "../../base/index.js";
import { isNonEmptyString } from "../../util/strings.js";
import { canonicalJSONStringify } from "../../util/canonicalize.js";
import { DeviceRegistrationV1 } from "./DeviceRegistrationV1.js";
import { DeviceInboxBindingV1 } from "./DeviceInboxBindingV1.js";
import {
  requireCanonicalSpkiB64,
  requireCanonicalB64,
  isFiniteNumber,
  normalizeSig,
  validateEd25519Sig,
} from "./deviceRecordShared.js";

export const DEVICE_LINK_REQUEST_V2_VERSION = 2;
export const DEVICE_LINK_REQUEST_V2_PURPOSE = "rez:device-link-request:v2";

/**
 * DeviceLinkRequestV2 — a NEW device's signed request to be linked to an account, carrying the
 * device-signed inbox binding the approver needs BEFORE it releases any authority.
 *
 * WHY V2 EXISTS (audit #5, 2026-07-27). `deviceInboxBinding` was originally bolted onto
 * DeviceLinkRequestV1 — inside its `signableBytes` — with `v` and `purpose` left at 1/v1. Two
 * different signed shapes then claimed the same version: a verifier could not tell which body a
 * signature was made over, and an old signature silently stopped verifying. The field belongs to a
 * NEW schema, so this is it. V1 is frozen and restored to its original bytes.
 *
 * `deviceInboxBinding` (P1#2 registration-before-release) is the new device's OWN device-signed
 * DeviceInboxBindingV1 for a self-chosen inbox. It rides in the signed request so the approver can
 * submit `device.add {deviceInboxBinding, deviceCapability}` to the home — binding the leaf cert's
 * certId at the home BEFORE the leaf is released to the new device. Without it the approver has no
 * device-signed inbox proof to register, leaving a window where the cert is usable but not yet
 * revocable to off-home peers. The binding grants NOTHING on its own; it is a self-cert of "this
 * device receives at this inbox". Bound here to THIS request's device (same deviceId + key); the
 * account-signed leaf cert is minted by the approver.
 *
 * Signed body (everything except `sig`):
 *   { v, purpose, accountIdentityPublicKeyB64, newDevicePublicKeyB64,
 *     newDeviceId, deviceInboxBinding, ceremonyNonceB64, issuedAtMs, expiresAtMs }
 * `newDeviceId` is self-certifying from `newDevicePublicKeyB64`. sig = Ed25519 over
 * canonicalJSONStringify(body) by the NEW device key.
 */
export class DeviceLinkRequestV2 extends RRecord {
  static type = "DeviceLinkRequestV2";

  constructor({
    v = DEVICE_LINK_REQUEST_V2_VERSION,
    purpose = DEVICE_LINK_REQUEST_V2_PURPOSE,
    accountIdentityPublicKeyB64,
    newDevicePublicKeyB64,
    newDeviceId,
    deviceInboxBinding,
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
    this.deviceInboxBinding = deviceInboxBinding;
    this.ceremonyNonceB64 = ceremonyNonceB64;
    this.issuedAtMs = issuedAtMs;
    this.expiresAtMs = expiresAtMs;
    this.sig = normalizeSig(sig);
    this._seal();
  }

  validate() {
    this.assert(this.v === DEVICE_LINK_REQUEST_V2_VERSION, "DeviceLinkRequestV2.v must be 2", { v: this.v });
    this.assert(this.purpose === DEVICE_LINK_REQUEST_V2_PURPOSE, "DeviceLinkRequestV2.purpose must be " + DEVICE_LINK_REQUEST_V2_PURPOSE, { purpose: this.purpose });
    requireCanonicalSpkiB64(this.accountIdentityPublicKeyB64, "DeviceLinkRequestV2.accountIdentityPublicKeyB64");
    requireCanonicalSpkiB64(this.newDevicePublicKeyB64, "DeviceLinkRequestV2.newDevicePublicKeyB64");
    this.assert(isNonEmptyString(this.newDeviceId), "DeviceLinkRequestV2.newDeviceId must be non-empty string", { newDeviceId: this.newDeviceId });
    const expectedDeviceId = DeviceRegistrationV1.deviceIdFor(this.newDevicePublicKeyB64);
    this.assert(this.newDeviceId === expectedDeviceId, "DeviceLinkRequestV2.newDeviceId must equal rez:dev:sha256(newDevicePublicKeyB64)", { newDeviceId: this.newDeviceId, expectedDeviceId });
    // Structurally validated by constructing it (self-cert deviceId + SPKI + device sig envelope),
    // then bound to THIS request's device — the binding must be for the very device being linked,
    // never a substituted device/key. Its own device-signature is verified where it is consumed
    // (openCeremonyRequest verifies the enclosing request; the home re-verifies at device.add).
    let binding;
    try {
      binding = new DeviceInboxBindingV1(this.deviceInboxBinding && typeof this.deviceInboxBinding === "object" ? this.deviceInboxBinding : {});
    } catch (err) {
      this.assert(false, "DeviceLinkRequestV2.deviceInboxBinding is invalid: " + (err && err.message ? err.message : "unknown"), { deviceInboxBinding: this.deviceInboxBinding });
    }
    this.assert(binding.deviceId === this.newDeviceId, "DeviceLinkRequestV2.deviceInboxBinding.deviceId must equal newDeviceId (the binding must be for the device being linked)", { bindingDeviceId: binding.deviceId, newDeviceId: this.newDeviceId });
    this.assert(binding.devicePublicKeyB64 === this.newDevicePublicKeyB64, "DeviceLinkRequestV2.deviceInboxBinding.devicePublicKeyB64 must equal newDevicePublicKeyB64", { bindingKey: binding.devicePublicKeyB64, newDevicePublicKeyB64: this.newDevicePublicKeyB64 });
    // 256-bit pin (S10): the nonce is the PSK-derived ceremony binding — a
    // shorter value would weaken the replay binding it exists to provide.
    requireCanonicalB64(this.ceremonyNonceB64, "DeviceLinkRequestV2.ceremonyNonceB64", { length: 32 });
    this.assert(isFiniteNumber(this.issuedAtMs), "DeviceLinkRequestV2.issuedAtMs must be number", { issuedAtMs: this.issuedAtMs });
    this.assert(isFiniteNumber(this.expiresAtMs), "DeviceLinkRequestV2.expiresAtMs must be number", { expiresAtMs: this.expiresAtMs });
    this.assert(this.expiresAtMs > this.issuedAtMs, "DeviceLinkRequestV2.expiresAtMs must be after issuedAtMs", { issuedAtMs: this.issuedAtMs, expiresAtMs: this.expiresAtMs });
    validateEd25519Sig(this.sig, "DeviceLinkRequestV2.sig");
  }

  /**
   * The exact bytes the new device key signs and every verifier recomputes — the
   * signed body minus `sig`. Deterministic via canonical JSON.
   */
  static signableBytes({ v, purpose, accountIdentityPublicKeyB64, newDevicePublicKeyB64, newDeviceId, deviceInboxBinding, ceremonyNonceB64, issuedAtMs, expiresAtMs } = {}) {
    const body = { v, purpose, accountIdentityPublicKeyB64, newDevicePublicKeyB64, newDeviceId, deviceInboxBinding, ceremonyNonceB64, issuedAtMs, expiresAtMs };
    return new TextEncoder().encode(canonicalJSONStringify(body));
  }
}
