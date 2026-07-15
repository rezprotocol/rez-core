import { RRecord } from "../../base/index.js";
import { canonicalJSONStringify } from "../../util/canonicalize.js";
import {
  requireCanonicalSpkiB64,
  isFiniteNumber,
  normalizeSig,
  validateEd25519Sig,
} from "./deviceRecordShared.js";
import { isCanonicalAccountCapabilityCertId } from "./accountCapabilityShared.js";

export const ACCOUNT_DEVICE_CAPABILITY_REVOKE_VERSION = 1;
export const ACCOUNT_DEVICE_CAPABILITY_REVOKE_PURPOSE = "rez:account-device-capability-revoke:v1";

/**
 * AccountDeviceCapabilityRevokeV1 — revokes a single `AccountDeviceCapabilityV1`
 * by its `certId` (S2.5 Slice 6). The revoke is the STATEMENT; enforcement is
 * separate and pure: `verifyAccountAuthority` is handed the current revocation
 * state (the set of revoked certIds) and rejects any chain containing a revoked
 * cert — and because every ancestor sits in the chain, revoking a parent
 * invalidates all descendants (recursive revocation, audit call #1).
 *
 * Signer: the account signing root (B-sign) OR a delegated device holding
 * `capability.revoke`. This record does NOT itself carry the signer's authority
 * chain — the authority to revoke is checked at the home (Slice 11) via
 * verifyAccountAuthority(requiredCapability="capability.revoke"); keeping the
 * chain out of the record mirrors how a mutation carries its own proof.
 *
 * `authorityEpoch` is the monotonic account authority revision this revoke
 * belongs to (Slice 11 / finding F4): peers track the newest epoch they have seen
 * and apply a bounded-staleness policy. Carrying it here lets a verifier reason
 * about freshness without a second fetch.
 *
 * Signed body (everything except `sig`):
 *   { v, purpose, accountIdentityPublicKeyB64, revokedCertId, authorityEpoch,
 *     issuedAtMs, signerPublicKeyB64 }
 * Structural-only `validate()`; signature verification is in the enforcement path.
 */
export class AccountDeviceCapabilityRevokeV1 extends RRecord {
  static type = "AccountDeviceCapabilityRevokeV1";

  constructor({
    v = ACCOUNT_DEVICE_CAPABILITY_REVOKE_VERSION,
    purpose = ACCOUNT_DEVICE_CAPABILITY_REVOKE_PURPOSE,
    accountIdentityPublicKeyB64,
    revokedCertId,
    authorityEpoch,
    issuedAtMs,
    signerPublicKeyB64,
    sig,
  } = {}) {
    super();
    this.v = v;
    this.purpose = purpose;
    this.accountIdentityPublicKeyB64 = accountIdentityPublicKeyB64;
    this.revokedCertId = revokedCertId;
    this.authorityEpoch = authorityEpoch;
    this.issuedAtMs = issuedAtMs;
    this.signerPublicKeyB64 = signerPublicKeyB64;
    this.sig = normalizeSig(sig);
    this._seal();
  }

  validate() {
    this.assert(this.v === ACCOUNT_DEVICE_CAPABILITY_REVOKE_VERSION, "AccountDeviceCapabilityRevokeV1.v must be 1", { v: this.v });
    this.assert(this.purpose === ACCOUNT_DEVICE_CAPABILITY_REVOKE_PURPOSE, "AccountDeviceCapabilityRevokeV1.purpose must be " + ACCOUNT_DEVICE_CAPABILITY_REVOKE_PURPOSE, { purpose: this.purpose });
    requireCanonicalSpkiB64(this.accountIdentityPublicKeyB64, "AccountDeviceCapabilityRevokeV1.accountIdentityPublicKeyB64");
    // Audit R4 F3-remediation finding 2: EXACT canonical shape (rez:cap: + 64 lowercase
    // hex), the SSOT predicate — not a bare prefix that accepts arbitrary content.
    this.assert(
      isCanonicalAccountCapabilityCertId(this.revokedCertId),
      "AccountDeviceCapabilityRevokeV1.revokedCertId must be a canonical rez:cap:<64-hex> id",
      { revokedCertId: this.revokedCertId },
    );
    this.assert(Number.isInteger(this.authorityEpoch) && this.authorityEpoch >= 0, "AccountDeviceCapabilityRevokeV1.authorityEpoch must be a non-negative integer", { authorityEpoch: this.authorityEpoch });
    this.assert(isFiniteNumber(this.issuedAtMs), "AccountDeviceCapabilityRevokeV1.issuedAtMs must be number", { issuedAtMs: this.issuedAtMs });
    requireCanonicalSpkiB64(this.signerPublicKeyB64, "AccountDeviceCapabilityRevokeV1.signerPublicKeyB64");
    validateEd25519Sig(this.sig, "AccountDeviceCapabilityRevokeV1.sig");
  }

  /** Signed body minus `sig`, canonical JSON — the bytes signer + verifier share. */
  static signableBytes({ v, purpose, accountIdentityPublicKeyB64, revokedCertId, authorityEpoch, issuedAtMs, signerPublicKeyB64 } = {}) {
    const body = { v, purpose, accountIdentityPublicKeyB64, revokedCertId, authorityEpoch, issuedAtMs, signerPublicKeyB64 };
    return new TextEncoder().encode(canonicalJSONStringify(body));
  }
}
