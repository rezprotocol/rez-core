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

export const DEVICE_INBOX_BINDING_VERSION = 1;
export const DEVICE_INBOX_BINDING_PURPOSE = "rez:device-inbox-binding:v1";

/**
 * DeviceInboxBindingV1 — binds a device to the inbox it RECEIVES at (S2.5). A
 * sender fanning out to an account encrypts one ciphertext per recipient device
 * and deposits it at that device's inbox; this record is the per-device address
 * that resolves "which inbox is device D's".
 *
 * Signature root = the DEVICE key (the device asserts its own receiving inbox).
 * The device→account chain is established SEPARATELY by DeviceRegistrationV1
 * (the account vouches for the device key); keeping the account signature OUT of
 * the per-inbox binding lets a device rotate its inbox without account re-signing
 * and keeps the account out of per-inbox material. A consumer that needs the full
 * chain verifies BOTH this binding (device-signed) and the device's registration
 * (account-signed) — the prekey bundle staples them under one device→account root.
 *
 * Home enforcement (S2.5 fix P1a): the durable inbox keys revocation on the
 * device — a DeviceRevokeV1 invalidates this binding at the home, after which
 * append/read/cursorAck fail closed for the device's inbox.
 *
 * Signed body (everything except `sig`):
 *   { v, purpose, devicePublicKeyB64, deviceId, inboxId, issuedAtMs, expiresAtMs }
 * sig = Ed25519 over canonicalJSONStringify(body) by the device key,
 * carried as `{ alg: "ed25519", sigB64 }`. `deviceId` is self-certifying
 * (rez:dev:sha256(devicePublicKeyB64)) and re-derived by every verifier.
 */
export class DeviceInboxBindingV1 extends RRecord {
  static type = "DeviceInboxBindingV1";

  constructor({
    v = DEVICE_INBOX_BINDING_VERSION,
    purpose = DEVICE_INBOX_BINDING_PURPOSE,
    devicePublicKeyB64,
    deviceId,
    inboxId,
    issuedAtMs,
    expiresAtMs,
    sig,
  } = {}) {
    super();
    this.v = v;
    this.purpose = purpose;
    this.devicePublicKeyB64 = devicePublicKeyB64;
    this.deviceId = deviceId;
    this.inboxId = inboxId;
    this.issuedAtMs = issuedAtMs;
    this.expiresAtMs = expiresAtMs;
    this.sig = normalizeSig(sig);
    this._seal();
  }

  validate() {
    this.assert(this.v === DEVICE_INBOX_BINDING_VERSION, "DeviceInboxBindingV1.v must be 1", { v: this.v });
    this.assert(this.purpose === DEVICE_INBOX_BINDING_PURPOSE, "DeviceInboxBindingV1.purpose must be " + DEVICE_INBOX_BINDING_PURPOSE, { purpose: this.purpose });
    requireCanonicalSpkiB64(this.devicePublicKeyB64, "DeviceInboxBindingV1.devicePublicKeyB64");
    this.assert(isNonEmptyString(this.deviceId), "DeviceInboxBindingV1.deviceId must be non-empty string", { deviceId: this.deviceId });
    const expectedDeviceId = DeviceRegistrationV1.deviceIdFor(this.devicePublicKeyB64);
    this.assert(this.deviceId === expectedDeviceId, "DeviceInboxBindingV1.deviceId must equal rez:dev:sha256(devicePublicKeyB64)", { deviceId: this.deviceId, expectedDeviceId });
    this.assert(isNonEmptyString(this.inboxId), "DeviceInboxBindingV1.inboxId must be non-empty string", { inboxId: this.inboxId });
    this.assert(isFiniteNumber(this.issuedAtMs), "DeviceInboxBindingV1.issuedAtMs must be number", { issuedAtMs: this.issuedAtMs });
    this.assert(isFiniteNumber(this.expiresAtMs), "DeviceInboxBindingV1.expiresAtMs must be number", { expiresAtMs: this.expiresAtMs });
    this.assert(this.expiresAtMs > this.issuedAtMs, "DeviceInboxBindingV1.expiresAtMs must be after issuedAtMs", { issuedAtMs: this.issuedAtMs, expiresAtMs: this.expiresAtMs });
    validateEd25519Sig(this.sig, "DeviceInboxBindingV1.sig");
  }

  /**
   * The exact bytes the device key signs and every verifier recomputes — the
   * signed body minus `sig`. Deterministic via canonical JSON.
   */
  static signableBytes({ v, purpose, devicePublicKeyB64, deviceId, inboxId, issuedAtMs, expiresAtMs } = {}) {
    const body = { v, purpose, devicePublicKeyB64, deviceId, inboxId, issuedAtMs, expiresAtMs };
    return new TextEncoder().encode(canonicalJSONStringify(body));
  }
}
