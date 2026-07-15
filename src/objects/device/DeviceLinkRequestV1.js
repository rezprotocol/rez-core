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
 * `deviceInboxBinding` (P1#2 registration-before-release) is the new device's OWN
 * device-signed DeviceInboxBindingV1 for a self-chosen inbox. It rides in the signed
 * request so the approver can submit `device.add {deviceInboxBinding, deviceCapability}`
 * to the home — binding the leaf cert's certId at the home BEFORE the leaf is released
 * to the new device. Without it the approver would have no device-signed inbox proof to
 * register (a device.add target requires one), leaving a window where the cert is usable
 * but not yet revocable to off-home peers. The binding grants NOTHING on its own; it is a
 * self-cert of "this device receives at this inbox". Bound here to THIS request's device
 * (same deviceId + key); the account-signed leaf cert is minted by the approver.
 *
 * Signed body (everything except `sig`):
 *   { v, purpose, accountIdentityPublicKeyB64, newDevicePublicKeyB64,
 *     newDeviceId, deviceInboxBinding, ceremonyNonceB64, issuedAtMs, expiresAtMs }
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
    this.assert(this.v === DEVICE_LINK_REQUEST_VERSION, "DeviceLinkRequestV1.v must be 1", { v: this.v });
    this.assert(this.purpose === DEVICE_LINK_REQUEST_PURPOSE, "DeviceLinkRequestV1.purpose must be " + DEVICE_LINK_REQUEST_PURPOSE, { purpose: this.purpose });
    requireCanonicalSpkiB64(this.accountIdentityPublicKeyB64, "DeviceLinkRequestV1.accountIdentityPublicKeyB64");
    requireCanonicalSpkiB64(this.newDevicePublicKeyB64, "DeviceLinkRequestV1.newDevicePublicKeyB64");
    this.assert(isNonEmptyString(this.newDeviceId), "DeviceLinkRequestV1.newDeviceId must be non-empty string", { newDeviceId: this.newDeviceId });
    const expectedDeviceId = DeviceRegistrationV1.deviceIdFor(this.newDevicePublicKeyB64);
    this.assert(this.newDeviceId === expectedDeviceId, "DeviceLinkRequestV1.newDeviceId must equal rez:dev:sha256(newDevicePublicKeyB64)", { newDeviceId: this.newDeviceId, expectedDeviceId });
    // P1#2: the self-chosen, device-signed inbox binding the approver registers via device.add.
    // Structurally validated by constructing it (self-cert deviceId + SPKI + device sig envelope),
    // then bound to THIS request's device — the binding must be for the very device being linked,
    // never a substituted device/key. Its own device-signature is verified where it is consumed
    // (openCeremonyRequest verifies the enclosing request; the home re-verifies at device.add).
    let binding;
    try {
      binding = new DeviceInboxBindingV1(this.deviceInboxBinding && typeof this.deviceInboxBinding === "object" ? this.deviceInboxBinding : {});
    } catch (err) {
      this.assert(false, "DeviceLinkRequestV1.deviceInboxBinding is invalid: " + (err && err.message ? err.message : "unknown"), { deviceInboxBinding: this.deviceInboxBinding });
    }
    this.assert(binding.deviceId === this.newDeviceId, "DeviceLinkRequestV1.deviceInboxBinding.deviceId must equal newDeviceId (the binding must be for the device being linked)", { bindingDeviceId: binding.deviceId, newDeviceId: this.newDeviceId });
    this.assert(binding.devicePublicKeyB64 === this.newDevicePublicKeyB64, "DeviceLinkRequestV1.deviceInboxBinding.devicePublicKeyB64 must equal newDevicePublicKeyB64", { bindingKey: binding.devicePublicKeyB64, newDevicePublicKeyB64: this.newDevicePublicKeyB64 });
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
  static signableBytes({ v, purpose, accountIdentityPublicKeyB64, newDevicePublicKeyB64, newDeviceId, deviceInboxBinding, ceremonyNonceB64, issuedAtMs, expiresAtMs } = {}) {
    const body = { v, purpose, accountIdentityPublicKeyB64, newDevicePublicKeyB64, newDeviceId, deviceInboxBinding, ceremonyNonceB64, issuedAtMs, expiresAtMs };
    return new TextEncoder().encode(canonicalJSONStringify(body));
  }
}
