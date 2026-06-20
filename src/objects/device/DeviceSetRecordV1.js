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

export const DEVICE_SET_VERSION = 1;
export const DEVICE_SET_PURPOSE = "rez:device-set:v1";

/**
 * DeviceSetRecordV1 — the authoritative set of devices an account fans out to
 * (S2.5). A sender resolves a peer's current devices from this record, then
 * encrypts once per device. Signature root = the ACCOUNT identity key: the set
 * is an account-level claim ("these are MY devices"), so only the account can
 * add/remove a device.
 *
 * This is the PLAINTEXT inner record. In delivery (Slice 3) it is encrypted
 * to the peer-link and carried as a DurableRecordV1.payloadB64 with a
 * peer-derived slot, so a non-peer can neither read nor enumerate the set. The
 * account signature here means a peer that decrypts the payload still verifies
 * the set is authentically the account's, independent of the overlay.
 *
 * `revision` is a MONOTONIC counter (not a wall clock): peers honor the highest
 * revision and treat a lower one as stale. A sender that sees an older set
 * treats unknown devices as absent rather than failing; home revoke enforcement
 * (DeviceRevokeV1 / DeviceInboxBindingV1) is the backstop that makes a lagging
 * set safe.
 *
 * Signed body (everything except `sig`):
 *   { v, purpose, accountIdentityPublicKeyB64, revision,
 *     devices: [{ deviceId, devicePublicKeyB64, inboxId }], issuedAtMs, expiresAtMs }
 * Each device entry's deviceId is self-certifying. sig = Ed25519 over
 * canonicalJSONStringify(body) by the account key, as `{ alg:"ed25519", sigB64 }`.
 */
export class DeviceSetRecordV1 extends RRecord {
  static type = "DeviceSetRecordV1";

  constructor({
    v = DEVICE_SET_VERSION,
    purpose = DEVICE_SET_PURPOSE,
    accountIdentityPublicKeyB64,
    revision,
    devices,
    issuedAtMs,
    expiresAtMs,
    sig,
  } = {}) {
    super();
    this.v = v;
    this.purpose = purpose;
    this.accountIdentityPublicKeyB64 = accountIdentityPublicKeyB64;
    this.revision = revision;
    this.devices = normalizeDevices(devices);
    this.issuedAtMs = issuedAtMs;
    this.expiresAtMs = expiresAtMs;
    this.sig = normalizeSig(sig);
    this._seal();
  }

  validate() {
    this.assert(this.v === DEVICE_SET_VERSION, "DeviceSetRecordV1.v must be 1", { v: this.v });
    this.assert(this.purpose === DEVICE_SET_PURPOSE, "DeviceSetRecordV1.purpose must be " + DEVICE_SET_PURPOSE, { purpose: this.purpose });
    requireCanonicalSpkiB64(this.accountIdentityPublicKeyB64, "DeviceSetRecordV1.accountIdentityPublicKeyB64");
    this.assert(Number.isInteger(this.revision) && this.revision >= 1, "DeviceSetRecordV1.revision must be a positive integer", { revision: this.revision });
    this.assert(Array.isArray(this.devices) && this.devices.length >= 1, "DeviceSetRecordV1.devices must be a non-empty array", { count: Array.isArray(this.devices) ? this.devices.length : null });

    const seen = new Set();
    for (let i = 0; i < this.devices.length; i++) {
      const d = this.devices[i];
      const at = "DeviceSetRecordV1.devices[" + i + "]";
      this.assert(d && typeof d === "object", at + " must be an object", { entry: d });
      requireCanonicalSpkiB64(d.devicePublicKeyB64, at + ".devicePublicKeyB64");
      this.assert(isNonEmptyString(d.deviceId), at + ".deviceId must be non-empty string", { deviceId: d.deviceId });
      const expectedDeviceId = DeviceRegistrationV1.deviceIdFor(d.devicePublicKeyB64);
      this.assert(d.deviceId === expectedDeviceId, at + ".deviceId must equal rez:dev:sha256(devicePublicKeyB64)", { deviceId: d.deviceId, expectedDeviceId });
      this.assert(isNonEmptyString(d.inboxId), at + ".inboxId must be non-empty string", { inboxId: d.inboxId });
      this.assert(!seen.has(d.deviceId), at + ".deviceId is duplicated in the set", { deviceId: d.deviceId });
      seen.add(d.deviceId);
    }

    this.assert(isFiniteNumber(this.issuedAtMs), "DeviceSetRecordV1.issuedAtMs must be number", { issuedAtMs: this.issuedAtMs });
    this.assert(isFiniteNumber(this.expiresAtMs), "DeviceSetRecordV1.expiresAtMs must be number", { expiresAtMs: this.expiresAtMs });
    this.assert(this.expiresAtMs > this.issuedAtMs, "DeviceSetRecordV1.expiresAtMs must be after issuedAtMs", { issuedAtMs: this.issuedAtMs, expiresAtMs: this.expiresAtMs });
    validateEd25519Sig(this.sig, "DeviceSetRecordV1.sig");
  }

  /**
   * The exact bytes the account key signs and every verifier recomputes — the
   * signed body minus `sig`. Device entries are projected to their canonical
   * field order so signer and verifier agree byte-for-byte.
   */
  static signableBytes({ v, purpose, accountIdentityPublicKeyB64, revision, devices, issuedAtMs, expiresAtMs } = {}) {
    const body = {
      v,
      purpose,
      accountIdentityPublicKeyB64,
      revision,
      devices: normalizeDevices(devices).map((d) => ({
        deviceId: d.deviceId,
        devicePublicKeyB64: d.devicePublicKeyB64,
        inboxId: d.inboxId,
      })),
      issuedAtMs,
      expiresAtMs,
    };
    return new TextEncoder().encode(canonicalJSONStringify(body));
  }
}

function normalizeDevices(devices) {
  if (!Array.isArray(devices)) return [];
  return devices.map((d) => {
    const src = d && typeof d === "object" ? d : {};
    return {
      deviceId: src.deviceId,
      devicePublicKeyB64: src.devicePublicKeyB64,
      inboxId: src.inboxId,
    };
  });
}
