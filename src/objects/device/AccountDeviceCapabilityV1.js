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
import {
  requireCapabilityList,
  deriveAccountCapabilityCertId,
  ACCOUNT_CAPABILITY_CERT_ID_PREFIX,
} from "./accountCapabilityShared.js";

export const ACCOUNT_DEVICE_CAPABILITY_VERSION = 1;
export const ACCOUNT_DEVICE_CAPABILITY_PURPOSE = "rez:account-device-capability:v1";

/**
 * AccountDeviceCapabilityV1 — one link in the account→device capability chain
 * (S2.5 Slice 6). The account signing root (B-sign) signs a cert delegating named
 * admin actions to a device key (the grantee C); a bounded chain re-delegates
 * (B→C1→C2). This is the cert that makes a SEEDLESS delegated device able to act
 * for the account without holding B-sign: an operation signed by C is authorized
 * by presenting a chain C←…←B that grants the required capability.
 *
 * Anchoring: every cert in a chain carries the SAME `accountIdentityPublicKeyB64`
 * (the B-sign root). A verifier MUST pass the account it expects — a self-
 * consistent chain for the wrong account verifies on its own (cf.
 * verifyDeviceRegistrationV1). See verifyAccountAuthority.
 *
 * Signer linkage: `signerPublicKeyB64` is who signed THIS cert — the account key
 * at the root (parentCertId === null), else the parent cert's grantee key. The
 * grantee is ALWAYS named (`granteeDevicePublicKeyB64` / self-cert
 * `granteeDeviceId`) — there are NO bearer caps; an operation signer must equal
 * the leaf grantee.
 *
 * Depth: `maxDelegationDepth` is the number of FURTHER hops the grantee may
 * delegate. A child cert requires `parent.maxDelegationDepth >= 1` and consumes
 * EXACTLY one — `child.maxDelegationDepth <= parent.maxDelegationDepth - 1` — so
 * depth strictly decreases down the chain (fixes the audit's finding that the
 * existing RCapability validator lets children keep the parent's depth forever).
 * At launch the root is issued with depth 0 (no re-delegation; B→C leaf only).
 *
 * `certId` is deterministic: `rez:cap:<sha256(canonicalJSON(coreBody))>` over
 * every signed field EXCEPT `certId`/`sig`, then folded back into the signed body
 * so the signature binds it. `signableBytes` = canonicalJSON(coreBody + certId).
 *
 * Structural-only `validate()` (no crypto) — mirrors the device-record family;
 * signature + chain + revocation + time are checked in verifyAccountAuthority,
 * which is pure and takes the crypto provider + the (passed-in) revocation state.
 */
export class AccountDeviceCapabilityV1 extends RRecord {
  static type = "AccountDeviceCapabilityV1";

  constructor({
    v = ACCOUNT_DEVICE_CAPABILITY_VERSION,
    purpose = ACCOUNT_DEVICE_CAPABILITY_PURPOSE,
    accountIdentityPublicKeyB64,
    parentCertId = null,
    granteeDevicePublicKeyB64,
    granteeDeviceId,
    capabilities,
    maxDelegationDepth,
    issuedAtMs,
    expiresAtMs,
    certId,
    signerPublicKeyB64,
    sig,
  } = {}) {
    super();
    this.v = v;
    this.purpose = purpose;
    this.accountIdentityPublicKeyB64 = accountIdentityPublicKeyB64;
    this.parentCertId = parentCertId === undefined ? null : parentCertId;
    this.granteeDevicePublicKeyB64 = granteeDevicePublicKeyB64;
    this.granteeDeviceId = granteeDeviceId;
    this.capabilities = capabilities;
    this.maxDelegationDepth = maxDelegationDepth;
    this.issuedAtMs = issuedAtMs;
    this.expiresAtMs = expiresAtMs;
    this.certId = certId;
    this.signerPublicKeyB64 = signerPublicKeyB64;
    this.sig = normalizeSig(sig);
    this._seal();
  }

  validate() {
    this.assert(this.v === ACCOUNT_DEVICE_CAPABILITY_VERSION, "AccountDeviceCapabilityV1.v must be 1", { v: this.v });
    this.assert(this.purpose === ACCOUNT_DEVICE_CAPABILITY_PURPOSE, "AccountDeviceCapabilityV1.purpose must be " + ACCOUNT_DEVICE_CAPABILITY_PURPOSE, { purpose: this.purpose });
    requireCanonicalSpkiB64(this.accountIdentityPublicKeyB64, "AccountDeviceCapabilityV1.accountIdentityPublicKeyB64");
    this.assert(
      this.parentCertId === null || (isNonEmptyString(this.parentCertId) && this.parentCertId.startsWith(ACCOUNT_CAPABILITY_CERT_ID_PREFIX)),
      "AccountDeviceCapabilityV1.parentCertId must be null or a rez:cap: id",
      { parentCertId: this.parentCertId },
    );
    requireCanonicalSpkiB64(this.granteeDevicePublicKeyB64, "AccountDeviceCapabilityV1.granteeDevicePublicKeyB64");
    this.assert(isNonEmptyString(this.granteeDeviceId), "AccountDeviceCapabilityV1.granteeDeviceId must be non-empty string", { granteeDeviceId: this.granteeDeviceId });
    const expectedGranteeId = DeviceRegistrationV1.deviceIdFor(this.granteeDevicePublicKeyB64);
    this.assert(this.granteeDeviceId === expectedGranteeId, "AccountDeviceCapabilityV1.granteeDeviceId must equal rez:dev:sha256(granteeDevicePublicKeyB64)", { granteeDeviceId: this.granteeDeviceId, expectedGranteeId });
    requireCapabilityList(this.capabilities, "AccountDeviceCapabilityV1.capabilities");
    this.assert(Number.isInteger(this.maxDelegationDepth) && this.maxDelegationDepth >= 0, "AccountDeviceCapabilityV1.maxDelegationDepth must be a non-negative integer", { maxDelegationDepth: this.maxDelegationDepth });
    requireCanonicalSpkiB64(this.signerPublicKeyB64, "AccountDeviceCapabilityV1.signerPublicKeyB64");
    this.assert(isFiniteNumber(this.issuedAtMs), "AccountDeviceCapabilityV1.issuedAtMs must be number", { issuedAtMs: this.issuedAtMs });
    this.assert(isFiniteNumber(this.expiresAtMs), "AccountDeviceCapabilityV1.expiresAtMs must be number", { expiresAtMs: this.expiresAtMs });
    this.assert(this.expiresAtMs > this.issuedAtMs, "AccountDeviceCapabilityV1.expiresAtMs must be after issuedAtMs", { issuedAtMs: this.issuedAtMs, expiresAtMs: this.expiresAtMs });
    this.assert(isNonEmptyString(this.certId), "AccountDeviceCapabilityV1.certId must be non-empty string", { certId: this.certId });
    const expectedCertId = AccountDeviceCapabilityV1.deriveCertId(this);
    this.assert(this.certId === expectedCertId, "AccountDeviceCapabilityV1.certId must be the deterministic rez:cap:sha256(coreBody)", { certId: this.certId, expectedCertId });
    validateEd25519Sig(this.sig, "AccountDeviceCapabilityV1.sig");
  }

  /**
   * The signed fields that DEFINE the cert (everything except `certId` and `sig`).
   * `certId` hashes this; `sig` then signs `coreBody + certId`.
   */
  static _coreBody({ v, purpose, accountIdentityPublicKeyB64, parentCertId, granteeDevicePublicKeyB64, granteeDeviceId, capabilities, maxDelegationDepth, issuedAtMs, expiresAtMs, signerPublicKeyB64 } = {}) {
    return {
      v,
      purpose,
      accountIdentityPublicKeyB64,
      parentCertId: parentCertId === undefined ? null : parentCertId,
      granteeDevicePublicKeyB64,
      granteeDeviceId,
      capabilities,
      maxDelegationDepth,
      issuedAtMs,
      expiresAtMs,
      signerPublicKeyB64,
    };
  }

  /** Deterministic cert id over the core body. SSOT for signer + verifier. */
  static deriveCertId(fields) {
    return deriveAccountCapabilityCertId(AccountDeviceCapabilityV1._coreBody(fields));
  }

  /**
   * The exact bytes the signer signs and every verifier recomputes — the core
   * body plus the (already-derived) `certId`, canonical JSON. Binds `certId` into
   * the signature so it cannot be swapped.
   */
  static signableBytes(fields) {
    const body = { ...AccountDeviceCapabilityV1._coreBody(fields), certId: fields.certId };
    return new TextEncoder().encode(canonicalJSONStringify(body));
  }
}
