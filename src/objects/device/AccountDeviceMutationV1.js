import { RRecord } from "../../base/index.js";
import { isNonEmptyString } from "../../util/strings.js";
import { canonicalJSONStringify } from "../../util/canonicalize.js";
import { DeviceInboxBindingV1 } from "./DeviceInboxBindingV1.js";
import {
  requireCanonicalSpkiB64,
  isFiniteNumber,
  normalizeSig,
  validateEd25519Sig,
} from "./deviceRecordShared.js";
import { ACCOUNT_CAPABILITY_CERT_ID_PREFIX } from "./accountCapabilityShared.js";

export const ACCOUNT_DEVICE_MUTATION_VERSION = 1;
export const ACCOUNT_DEVICE_MUTATION_PURPOSE = "rez:account-device-mutation:v1";

// The two mutation verbs. LOCAL to this record — NOT the capability vocabulary
// (though they share names with the capabilities that authorize them).
export const ACCOUNT_DEVICE_MUTATION_ACTIONS = Object.freeze(["device.add", "device.revoke"]);

/**
 * AccountDeviceMutationV1 (S2.5 S11) — a device's signed request to the account's
 * AUTHORITY HOME to mutate the account device set (add or revoke a sibling
 * device). The home serializes it under a per-account lock, folds canonical
 * state, and bumps a monotonic epoch.
 *
 * The submitter's per-op AUTHORITY is proven by the AUTHENTICATED session (the
 * home checks `sessionAuthority.grantedCapabilities` — device.add / device.revoke
 * — exactly as the shipped device.revoke handler does), so the envelope carries
 * NO cert chain: it is a bare signed statement bound to the session by
 * `signerPublicKeyB64` (B on a primary, C on a delegated device). `opId` is a
 * client-chosen idempotency key; `expectedRevision` is optimistic concurrency
 * against the home's current epoch (a mismatch returns the latest state, no
 * clobber).
 *
 * `target` is action-tagged:
 *   device.add    → { deviceInboxBinding: <DeviceInboxBindingV1 json> }
 *                   (the sibling's device-signed, self-certifying inbox+key proof)
 *   device.revoke → { revokedDeviceId, revokedCertId? }
 *                   (revokedDeviceId self-cert; revokedCertId optional — adds to
 *                    the account revoked-cert set)
 *
 * Signed body (everything except `sig`):
 *   { v, purpose, opId, accountIdentityPublicKeyB64, expectedRevision, action,
 *     target, signerPublicKeyB64, issuedAtMs, expiresAtMs }
 */
export class AccountDeviceMutationV1 extends RRecord {
  static type = "AccountDeviceMutationV1";

  constructor({
    v = ACCOUNT_DEVICE_MUTATION_VERSION,
    purpose = ACCOUNT_DEVICE_MUTATION_PURPOSE,
    opId,
    accountIdentityPublicKeyB64,
    expectedRevision,
    action,
    target,
    signerPublicKeyB64,
    issuedAtMs,
    expiresAtMs,
    sig,
  } = {}) {
    super();
    this.v = v;
    this.purpose = purpose;
    this.opId = opId;
    this.accountIdentityPublicKeyB64 = accountIdentityPublicKeyB64;
    this.expectedRevision = expectedRevision;
    this.action = action;
    this.target = target;
    this.signerPublicKeyB64 = signerPublicKeyB64;
    this.issuedAtMs = issuedAtMs;
    this.expiresAtMs = expiresAtMs;
    this.sig = normalizeSig(sig);
    this._seal();
  }

  validate() {
    this.assert(this.v === ACCOUNT_DEVICE_MUTATION_VERSION, "AccountDeviceMutationV1.v must be 1", { v: this.v });
    this.assert(this.purpose === ACCOUNT_DEVICE_MUTATION_PURPOSE, "AccountDeviceMutationV1.purpose must be " + ACCOUNT_DEVICE_MUTATION_PURPOSE, { purpose: this.purpose });
    this.assert(isNonEmptyString(this.opId), "AccountDeviceMutationV1.opId must be a non-empty string", { opId: this.opId });
    requireCanonicalSpkiB64(this.accountIdentityPublicKeyB64, "AccountDeviceMutationV1.accountIdentityPublicKeyB64");
    this.assert(
      Number.isInteger(this.expectedRevision) && this.expectedRevision >= 0,
      "AccountDeviceMutationV1.expectedRevision must be a non-negative integer",
      { expectedRevision: this.expectedRevision },
    );
    this.assert(
      ACCOUNT_DEVICE_MUTATION_ACTIONS.includes(this.action),
      'AccountDeviceMutationV1.action must be "device.add" or "device.revoke"',
      { action: this.action },
    );
    requireCanonicalSpkiB64(this.signerPublicKeyB64, "AccountDeviceMutationV1.signerPublicKeyB64");
    this.assert(isFiniteNumber(this.issuedAtMs), "AccountDeviceMutationV1.issuedAtMs must be number", { issuedAtMs: this.issuedAtMs });
    this.assert(isFiniteNumber(this.expiresAtMs), "AccountDeviceMutationV1.expiresAtMs must be number", { expiresAtMs: this.expiresAtMs });
    this.assert(this.expiresAtMs > this.issuedAtMs, "AccountDeviceMutationV1.expiresAtMs must be after issuedAtMs", { issuedAtMs: this.issuedAtMs, expiresAtMs: this.expiresAtMs });
    this.#validateTarget();
    validateEd25519Sig(this.sig, "AccountDeviceMutationV1.sig");
  }

  #validateTarget() {
    const target = this.target;
    this.assert(target && typeof target === "object" && !Array.isArray(target), "AccountDeviceMutationV1.target must be an object", { target });
    if (this.action === "device.add") {
      // The sibling's device-signed inbox binding — structurally validated by
      // constructing it (self-cert deviceId + SPKI + sig envelope pinned there).
      let binding;
      try {
        binding = new DeviceInboxBindingV1(target.deviceInboxBinding && typeof target.deviceInboxBinding === "object" ? target.deviceInboxBinding : {});
      } catch (err) {
        this.assert(false, "AccountDeviceMutationV1 device.add target.deviceInboxBinding is invalid: " + (err && err.message ? err.message : "unknown"), { target });
      }
      // Keep the constructed record from being GC-flagged as unused.
      this.assert(isNonEmptyString(binding.deviceId), "AccountDeviceMutationV1 device.add binding must carry a deviceId", { deviceId: binding.deviceId });
    } else {
      // device.revoke: a self-cert deviceId, and an optional revoked cert id.
      this.assert(isNonEmptyString(target.revokedDeviceId), "AccountDeviceMutationV1 device.revoke target.revokedDeviceId must be a non-empty string", { target });
      this.assert(
        String(target.revokedDeviceId).startsWith("rez:dev:"),
        "AccountDeviceMutationV1 device.revoke target.revokedDeviceId must be a rez:dev: id",
        { revokedDeviceId: target.revokedDeviceId },
      );
      if (target.revokedCertId !== undefined && target.revokedCertId !== null) {
        this.assert(
          isNonEmptyString(target.revokedCertId) && String(target.revokedCertId).startsWith(ACCOUNT_CAPABILITY_CERT_ID_PREFIX),
          "AccountDeviceMutationV1 device.revoke target.revokedCertId must be a rez:cap: id or omitted",
          { revokedCertId: target.revokedCertId },
        );
      }
    }
  }

  /**
   * The exact bytes the signer signs and the home recomputes — the signed body
   * minus `sig`. Deterministic via canonical JSON (canonicalizes the nested
   * target too).
   */
  static signableBytes({ v, purpose, opId, accountIdentityPublicKeyB64, expectedRevision, action, target, signerPublicKeyB64, issuedAtMs, expiresAtMs } = {}) {
    const body = { v, purpose, opId, accountIdentityPublicKeyB64, expectedRevision, action, target, signerPublicKeyB64, issuedAtMs, expiresAtMs };
    return new TextEncoder().encode(canonicalJSONStringify(body));
  }
}
