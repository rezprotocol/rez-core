import { RRecord } from "../../base/index.js";
import { canonicalJSONStringify } from "../../util/canonicalize.js";
import {
  requireCanonicalSpkiB64,
  isFiniteNumber,
  normalizeSig,
  validateEd25519Sig,
} from "./deviceRecordShared.js";
import { isCanonicalAccountCapabilityCertId } from "./accountCapabilityShared.js";

export const ACCOUNT_AUTHORITY_STATE_VERSION = 1;
export const ACCOUNT_AUTHORITY_STATE_PURPOSE = "rez:account-authority-state:v1";
// The DurableRecordV2 recordKind an account publishes its authority state under.
export const ACCOUNT_AUTHORITY_STATE_RECORD_KIND = "account-authority-state";

/**
 * AccountAuthorityStateV1 (S2.5 S11, finding F4) — the account's monotonic
 * revocation/authority snapshot at a given epoch. An authorized device folds the
 * home's canonical state into this record and publishes it as a DurableRecordV2
 * (owner = the account B key) so OFF-home peers converge on revocations they
 * cannot otherwise learn (a durable-record slot cannot prove "this cert was
 * revoked" — only a positive authority statement can).
 *
 * Its `{ revokedCertIds, minValidIssuedAtMs }` projection IS the `revocationState`
 * param shape every verifier (`verifyAccountAuthority`, `verifyDurableRecordV2`)
 * already accepts — the record is the authenticated transport for that state, and
 * `epoch` lets a reader apply a bounded-staleness policy (newest epoch wins).
 *
 * Signed body (everything except `sig`):
 *   { v, purpose, accountIdentityPublicKeyB64, epoch, revokedCertIds,
 *     minValidIssuedAtMs, issuedAtMs, signerPublicKeyB64 }
 * `revokedCertIds` is sorted + deduped (canonical) so the same authority state
 * serializes identically regardless of insertion order. Signer = the account
 * root B, or a delegated device authorized for deviceSet.publish (checked at the
 * consuming verifier, not here — enforcement lives in the verifier).
 */
export class AccountAuthorityStateV1 extends RRecord {
  static type = "AccountAuthorityStateV1";

  constructor({
    v = ACCOUNT_AUTHORITY_STATE_VERSION,
    purpose = ACCOUNT_AUTHORITY_STATE_PURPOSE,
    accountIdentityPublicKeyB64,
    epoch,
    revokedCertIds,
    minValidIssuedAtMs,
    issuedAtMs,
    signerPublicKeyB64,
    sig,
  } = {}) {
    super();
    this.v = v;
    this.purpose = purpose;
    this.accountIdentityPublicKeyB64 = accountIdentityPublicKeyB64;
    this.epoch = epoch;
    this.revokedCertIds = AccountAuthorityStateV1.#normalizeCertIds(revokedCertIds);
    this.minValidIssuedAtMs = minValidIssuedAtMs;
    this.issuedAtMs = issuedAtMs;
    this.signerPublicKeyB64 = signerPublicKeyB64;
    this.sig = normalizeSig(sig);
    this._seal();
  }

  // Sorted + deduped so the canonical form is insertion-order-independent.
  static #normalizeCertIds(value) {
    if (!Array.isArray(value)) return value;
    return [...new Set(value)].sort();
  }

  validate() {
    this.assert(this.v === ACCOUNT_AUTHORITY_STATE_VERSION, "AccountAuthorityStateV1.v must be 1", { v: this.v });
    this.assert(this.purpose === ACCOUNT_AUTHORITY_STATE_PURPOSE, "AccountAuthorityStateV1.purpose must be " + ACCOUNT_AUTHORITY_STATE_PURPOSE, { purpose: this.purpose });
    requireCanonicalSpkiB64(this.accountIdentityPublicKeyB64, "AccountAuthorityStateV1.accountIdentityPublicKeyB64");
    this.assert(Number.isInteger(this.epoch) && this.epoch >= 0, "AccountAuthorityStateV1.epoch must be a non-negative integer", { epoch: this.epoch });
    this.assert(Array.isArray(this.revokedCertIds), "AccountAuthorityStateV1.revokedCertIds must be an array", { revokedCertIds: this.revokedCertIds });
    for (const certId of this.revokedCertIds) {
      this.assert(
        isCanonicalAccountCapabilityCertId(certId),
        "AccountAuthorityStateV1.revokedCertIds entries must be canonical rez:cap:<64-hex> ids",
        { certId },
      );
    }
    this.assert(isFiniteNumber(this.minValidIssuedAtMs) && this.minValidIssuedAtMs >= 0, "AccountAuthorityStateV1.minValidIssuedAtMs must be a non-negative number", { minValidIssuedAtMs: this.minValidIssuedAtMs });
    this.assert(isFiniteNumber(this.issuedAtMs), "AccountAuthorityStateV1.issuedAtMs must be number", { issuedAtMs: this.issuedAtMs });
    requireCanonicalSpkiB64(this.signerPublicKeyB64, "AccountAuthorityStateV1.signerPublicKeyB64");
    validateEd25519Sig(this.sig, "AccountAuthorityStateV1.sig");
  }

  /**
   * The `revocationState` projection this record authenticates — exactly the
   * shape verifyAccountAuthority / verifyDurableRecordV2 consume.
   */
  toRevocationState() {
    return { revokedCertIds: [...this.revokedCertIds], minValidIssuedAtMs: this.minValidIssuedAtMs };
  }

  /**
   * The two fields a durable-record slot must read out of this payload WITHOUT constructing (and
   * fully validating) the record: which account the state speaks for, and its monotonic `epoch`.
   *
   * This is the SSOT for that projection — `durableRecordMonotonicBinding` maps the
   * `account-authority-state` record kind here rather than reaching into payload field names itself,
   * so the payload shape stays owned by this class.
   *
   * THROWS on anything unreadable. A slot's rollback floor is an authorization-grade decision, so a
   * missing or malformed epoch must never be coerced into a plausible 0 (which would silently admit
   * every rollback). Callers convert the throw into an explicit rejection.
   *
   * @param {object} json - the parsed payload
   * @returns {{ accountIdentityPublicKeyB64: string, epoch: number }}
   */
  static monotonicBindingOf(json) {
    if (!json || typeof json !== "object" || Array.isArray(json)) {
      throw new Error("AccountAuthorityStateV1 payload must be an object");
    }
    const account = json.accountIdentityPublicKeyB64;
    if (typeof account !== "string" || account.trim().length === 0) {
      throw new Error("AccountAuthorityStateV1 payload is missing accountIdentityPublicKeyB64");
    }
    const epoch = json.epoch;
    if (!Number.isSafeInteger(epoch) || epoch < 0) {
      throw new Error("AccountAuthorityStateV1 payload epoch must be a non-negative safe integer");
    }
    return { accountIdentityPublicKeyB64: account.trim(), epoch };
  }

  /** Signed body minus `sig`, canonical JSON. certIds normalized before signing. */
  static signableBytes({ v, purpose, accountIdentityPublicKeyB64, epoch, revokedCertIds, minValidIssuedAtMs, issuedAtMs, signerPublicKeyB64 } = {}) {
    const body = {
      v,
      purpose,
      accountIdentityPublicKeyB64,
      epoch,
      revokedCertIds: AccountAuthorityStateV1.#normalizeCertIds(revokedCertIds),
      minValidIssuedAtMs,
      issuedAtMs,
      signerPublicKeyB64,
    };
    return new TextEncoder().encode(canonicalJSONStringify(body));
  }
}
