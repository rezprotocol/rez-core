import { RRecord } from "../../base/index.js";
import { isNonEmptyString } from "../../util/strings.js";
import { canonicalJSONStringify } from "../../util/canonicalize.js";
import { DeviceInboxBindingV1 } from "./DeviceInboxBindingV1.js";
import { isCanonicalDeviceId } from "./DeviceRegistrationV1.js";
import {
  requireCanonicalSpkiB64,
  isFiniteNumber,
  normalizeSig,
  validateEd25519Sig,
} from "./deviceRecordShared.js";
import { isCanonicalAccountCapabilityCertId } from "./accountCapabilityShared.js";
import { AccountDeviceCapabilityV1 } from "./AccountDeviceCapabilityV1.js";
// The action set is SHARED, not redefined: two copies could drift and let one version accept an
// action the other rejects.
import { ACCOUNT_DEVICE_MUTATION_ACTIONS } from "./AccountDeviceMutationV1.js";

export const ACCOUNT_DEVICE_MUTATION_V2_VERSION = 2;
export const ACCOUNT_DEVICE_MUTATION_V2_PURPOSE = "rez:account-device-mutation:v2";

// The two mutation verbs. LOCAL to this record — NOT the capability vocabulary
// (though they share names with the capabilities that authorize them).

/**
 * AccountDeviceMutationV2 — a device's signed request to the account's AUTHORITY HOME to mutate
 * the account device set (add or revoke a sibling device). The home serializes it under a
 * per-account lock, folds canonical state, and bumps a monotonic epoch.
 *
 * WHY V2 EXISTS (audit #5, 2026-07-27). `device.add` gained a required `deviceCapability` inside
 * its `target` while `v`/`purpose` stayed at 1/v1. `signableBytes` covers `target` wholesale, so
 * that silently redefined what a v1 device.add signature attests to. The field belongs to a new
 * schema; V1 is frozen with its original target, and a v1 device.add is refused outright (it
 * carries no certId for the home to bind, so a later revoke cannot kill the device's leaf for
 * off-home peers). `device.revoke` is UNCHANGED between the versions — same target shape, same
 * meaning — so v1 revokes remain acceptable.
 *
 * The submitter's per-op AUTHORITY is proven by the AUTHENTICATED session (the home checks
 * `sessionAuthority.grantedCapabilities`), so the envelope carries NO cert chain: it is a bare
 * signed statement bound to the session by `signerPublicKeyB64`. `opId` is a client-chosen
 * idempotency key; `expectedRevision` is optimistic concurrency against the home's current epoch.
 *
 * `target` is action-tagged:
 *   device.add    → { deviceInboxBinding: <DeviceInboxBindingV1 json>,
 *                     deviceCapability: <AccountDeviceCapabilityV1 json> }
 *   device.revoke → { revokedDeviceId, revokedCertId? }
 *                   (revokedCertId is NOT an arbitrary add to the revoked-cert set: the home
 *                    auto-revokes the target device's OWN registry-bound cert, and a supplied
 *                    revokedCertId is only a redundant assertion that must EQUAL that bound cert.)
 *
 * Signed body (everything except `sig`):
 *   { v, purpose, opId, accountIdentityPublicKeyB64, expectedRevision, action,
 *     target, signerPublicKeyB64, issuedAtMs, expiresAtMs }
 */
export class AccountDeviceMutationV2 extends RRecord {
  static type = "AccountDeviceMutationV2";

  constructor({
    v = ACCOUNT_DEVICE_MUTATION_V2_VERSION,
    purpose = ACCOUNT_DEVICE_MUTATION_V2_PURPOSE,
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
    this.assert(this.v === ACCOUNT_DEVICE_MUTATION_V2_VERSION, "AccountDeviceMutationV2.v must be 2", { v: this.v });
    this.assert(this.purpose === ACCOUNT_DEVICE_MUTATION_V2_PURPOSE, "AccountDeviceMutationV2.purpose must be " + ACCOUNT_DEVICE_MUTATION_V2_PURPOSE, { purpose: this.purpose });
    this.assert(isNonEmptyString(this.opId), "AccountDeviceMutationV2.opId must be a non-empty string", { opId: this.opId });
    requireCanonicalSpkiB64(this.accountIdentityPublicKeyB64, "AccountDeviceMutationV2.accountIdentityPublicKeyB64");
    this.assert(
      Number.isInteger(this.expectedRevision) && this.expectedRevision >= 0,
      "AccountDeviceMutationV2.expectedRevision must be a non-negative integer",
      { expectedRevision: this.expectedRevision },
    );
    this.assert(
      ACCOUNT_DEVICE_MUTATION_ACTIONS.includes(this.action),
      'AccountDeviceMutationV2.action must be "device.add" or "device.revoke"',
      { action: this.action },
    );
    requireCanonicalSpkiB64(this.signerPublicKeyB64, "AccountDeviceMutationV2.signerPublicKeyB64");
    this.assert(isFiniteNumber(this.issuedAtMs), "AccountDeviceMutationV2.issuedAtMs must be number", { issuedAtMs: this.issuedAtMs });
    this.assert(isFiniteNumber(this.expiresAtMs), "AccountDeviceMutationV2.expiresAtMs must be number", { expiresAtMs: this.expiresAtMs });
    this.assert(this.expiresAtMs > this.issuedAtMs, "AccountDeviceMutationV2.expiresAtMs must be after issuedAtMs", { issuedAtMs: this.issuedAtMs, expiresAtMs: this.expiresAtMs });
    this.#validateTarget();
    validateEd25519Sig(this.sig, "AccountDeviceMutationV2.sig");
  }

  #validateTarget() {
    const target = this.target;
    this.assert(target && typeof target === "object" && !Array.isArray(target), "AccountDeviceMutationV2.target must be an object", { target });
    if (this.action === "device.add") {
      // The sibling's device-signed inbox binding — structurally validated by
      // constructing it (self-cert deviceId + SPKI + sig envelope pinned there).
      let binding;
      try {
        binding = new DeviceInboxBindingV1(target.deviceInboxBinding && typeof target.deviceInboxBinding === "object" ? target.deviceInboxBinding : {});
      } catch (err) {
        this.assert(false, "AccountDeviceMutationV2 device.add target.deviceInboxBinding is invalid: " + (err && err.message ? err.message : "unknown"), { target });
      }
      // Keep the constructed record from being GC-flagged as unused.
      this.assert(isNonEmptyString(binding.deviceId), "AccountDeviceMutationV2 device.add binding must carry a deviceId", { deviceId: binding.deviceId });

      // device.add MUST carry the device's leaf capability cert (C←B) so the home can store its
      // certId and later auto-revoke it. Structurally validate it and bind it to THIS device +
      // account (the leaf must grant authority to the very device being added, anchored to the
      // mutation's account). The signature + chain are verified by the home
      // (verifyAccountAuthority) — this is the structural coherence gate.
      let capability;
      try {
        capability = new AccountDeviceCapabilityV1(target.deviceCapability && typeof target.deviceCapability === "object" ? target.deviceCapability : {});
      } catch (err) {
        this.assert(false, "AccountDeviceMutationV2 device.add target.deviceCapability is invalid: " + (err && err.message ? err.message : "unknown"), { target });
      }
      this.assert(
        capability.granteeDeviceId === binding.deviceId,
        "AccountDeviceMutationV2 device.add deviceCapability.granteeDeviceId must equal the binding deviceId (the leaf must grant the device being added)",
        { granteeDeviceId: capability.granteeDeviceId, bindingDeviceId: binding.deviceId },
      );
      this.assert(
        capability.accountIdentityPublicKeyB64 === this.accountIdentityPublicKeyB64,
        "AccountDeviceMutationV2 device.add deviceCapability must anchor to the mutation's account",
        { certAccount: capability.accountIdentityPublicKeyB64, mutationAccount: this.accountIdentityPublicKeyB64 },
      );

    } else {
      // device.revoke: a self-cert deviceId, and an optional revoked cert id. The
      // deviceId must have CANONICAL SYNTAX (`rez:dev:<64-lowercase-hex>`), not merely
      // a `rez:dev:` prefix. NOTE this proves SHAPE only, NOT `deviceId ===
      // deviceIdFor(pub)`: this record carries no pubkey for the revoke target, so it
      // cannot be key-proven here. The syntax guard still narrows the
      // forgeable-id space: the home writes a durable terminal tombstone for a revoke
      // target, and a loose prefix check would let a revoke-capable device mint
      // tombstones for arbitrary malformed strings. This is an upstream early-reject;
      // the registry independently enforces canonical shape as the invariant owner.
      // (audit R4 F1 — DoS-syntax guard.)
      this.assert(isNonEmptyString(target.revokedDeviceId), "AccountDeviceMutationV2 device.revoke target.revokedDeviceId must be a non-empty string", { target });
      this.assert(
        isCanonicalDeviceId(target.revokedDeviceId),
        "AccountDeviceMutationV2 device.revoke target.revokedDeviceId must be a canonical rez:dev:<64-hex> id",
        { revokedDeviceId: target.revokedDeviceId },
      );
      if (target.revokedCertId !== undefined && target.revokedCertId !== null) {
        // Audit R4 F3-remediation finding 2: EXACT canonical shape (rez:cap: + 64 lowercase
        // hex — what deriveAccountCapabilityCertId emits), not a bare prefix that would
        // accept `rez:cap:revoked-leaf` or any attacker-chosen string.
        this.assert(
          isCanonicalAccountCapabilityCertId(target.revokedCertId),
          "AccountDeviceMutationV2 device.revoke target.revokedCertId must be a canonical rez:cap:<64-hex> id or omitted",
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
