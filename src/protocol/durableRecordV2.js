import { canonicalJSONStringify } from "../util/canonicalize.js";
import { base64ToBytes } from "../util/bytes.js";
import { durableRecordLocalId } from "./durableRecordV1.js";
import { verifyAccountAuthority } from "../objects/device/verifyAccountAuthority.js";

/**
 * DurableRecordV2 — the OWNER/SIGNER-separated durable record (S2.5 S8 / F2).
 *
 * DurableRecordV1 folds one key into three roles: it determines the slot
 * coordinate (`sha256(publisherPub|kind:recordId)`), it is the verified
 * signature key, AND it is the record's identity. That is fine while only the
 * account root (B-sign) ever publishes — but a DELEGATED device holds its own
 * per-device key C and a capability chain C←…←B, NOT B-sign's private key. If
 * such a device published with C, (a) the signature would verify against C, not
 * the account, and (b) the slot would move to C's coordinate, so peers fetching
 * the account's record at B's coordinate would never find it.
 *
 * V2 splits the roles:
 *   - `ownerPublicKeyB64`  = the ACCOUNT identity (B-sign). Anchors the slot AND
 *     the record's identity. Peers fetch at the UNCHANGED owner-keyed coordinate
 *     regardless of which device actually signed.
 *   - `signerPublicKeyB64` = the key that actually signed (B-sign for a primary
 *     device, or C for a delegated device).
 *   - `certChain`          = the AccountDeviceCapabilityV1 chain C←…←B proving
 *     the owner delegated `requiredCapability` to the signer (empty in direct
 *     mode, where signer == owner).
 *   - `requiredCapability` = the capability the signer needed to publish this
 *     kind of record (e.g. "deviceSet.publish"); null when none is required.
 *
 * Canonical shape:
 *   { v:2, recordKind, recordId, ownerPublicKeyB64, signerPublicKeyB64,
 *     certChain, requiredCapability, issuedAtMs, expiresAtMs, payloadB64, sigB64 }
 *
 * Verification (single helper below): slot recomputed from the OWNER key; the
 * signature checked against the SIGNER key; and owner→signer authority decided
 * by `verifyAccountAuthority` (DIRECT when signer == owner and no chain — the
 * byte-for-byte V1 primary path — else DELEGATED via the cert chain). This
 * module is the SSOT for the slot + signed bytes so the SDK (which signs) and
 * rez-node (which verifies) agree byte-for-byte; crypto is injected, never
 * imported, exactly like `verifyAccountAuthority`.
 */

export const DURABLE_RECORD_V2_VERSION = 2;

/**
 * The OWNER-keyed slot coordinate. Identical math to V1's
 * `durableRecordLocalId`, but explicitly keyed on the account owner so the
 * coordinate is stable across whichever device signs. A delegated signer never
 * moves the slot.
 *
 * @param {{ ownerPublicKeyB64: string, recordKind: string, recordId: string }} args
 * @returns {string} 64-char sha256 hex
 */
export function durableRecordV2Slot({ ownerPublicKeyB64, recordKind, recordId } = {}) {
  return durableRecordLocalId({ publisherPublicKeyB64: ownerPublicKeyB64, recordKind, recordId });
}

/**
 * Map a cert (instance or its toJSON()) to its `certId`. Throws if absent so a
 * record can never sign over a chain whose membership is unstated.
 */
function certIdOf(cert, index) {
  const json = cert && typeof cert.toJSON === "function" ? cert.toJSON() : cert;
  const id = json && typeof json === "object" ? json.certId : null;
  if (typeof id !== "string" || id.trim().length === 0) {
    throw new Error("durableRecordV2: cert at index " + index + " is missing certId");
  }
  return id;
}

/**
 * The exact bytes the signer signs and every verifier recomputes. Covers every
 * field EXCEPT `sigB64`, and commits to the cert chain by its ORDERED list of
 * `certId`s — a compact, complete commitment (each certId already binds its
 * cert's full body), so a holder cannot swap in a different-but-valid chain
 * without invalidating the signature.
 *
 * @param {object} record
 * @returns {Uint8Array}
 */
export function durableRecordV2SignableBytes(record) {
  if (!record || typeof record !== "object") {
    throw new Error("durableRecordV2SignableBytes requires a record object");
  }
  const chain = Array.isArray(record.certChain) ? record.certChain : [];
  const certChainCertIds = chain.map((cert, i) => certIdOf(cert, i));
  const payload = {
    v: record.v,
    recordKind: record.recordKind,
    recordId: record.recordId,
    ownerPublicKeyB64: record.ownerPublicKeyB64,
    signerPublicKeyB64: record.signerPublicKeyB64,
    requiredCapability: record.requiredCapability === undefined ? null : record.requiredCapability,
    certChainCertIds,
    issuedAtMs: record.issuedAtMs,
    expiresAtMs: record.expiresAtMs,
    payloadB64: record.payloadB64,
  };
  return new TextEncoder().encode(canonicalJSONStringify(payload));
}

/**
 * Build the unsigned V2 skeleton. The caller signs
 * `durableRecordV2SignableBytes(record)` with the SIGNER key and assigns the
 * base64 signature to `sigB64`. Direct mode: omit `signerPublicKeyB64`/
 * `certChain` and the signer defaults to the owner (an empty chain).
 *
 * @param {object} args
 * @returns {object} record without sigB64
 */
export function buildDurableRecordV2({
  recordKind,
  recordId,
  ownerPublicKeyB64,
  signerPublicKeyB64,
  certChain = [],
  requiredCapability = null,
  payloadB64,
  issuedAtMs,
  expiresAtMs,
} = {}) {
  const owner = String(ownerPublicKeyB64 || "").trim();
  const signer = String(signerPublicKeyB64 || "").trim() || owner;
  const chain = Array.isArray(certChain)
    ? certChain.map((cert) => (cert && typeof cert.toJSON === "function" ? cert.toJSON() : cert))
    : [];
  return {
    v: DURABLE_RECORD_V2_VERSION,
    recordKind: String(recordKind || "").trim(),
    recordId: String(recordId || "").trim(),
    ownerPublicKeyB64: owner,
    signerPublicKeyB64: signer,
    certChain: chain,
    requiredCapability: requiredCapability === undefined ? null : requiredCapability,
    issuedAtMs,
    expiresAtMs,
    payloadB64: String(payloadB64 || ""),
  };
}

/**
 * Verify a V2 record fully: structure, time window, owner-keyed slot binding,
 * the signature against the SIGNER key, and owner→signer authority. PURE —
 * crypto + freshest revocation/authority state are PASSED IN (mirrors
 * `verifyAccountAuthority`; the bounded-staleness policy lives at the call
 * site). `nowMs` is REQUIRED (no fail-open on expiry for an authorization-grade
 * decision).
 *
 * @param {object} opts
 * @param {object} opts.record — a V2 record incl. `sigB64`
 * @param {{ verify(args:{publicKey:Uint8Array,msg:Uint8Array,sig:Uint8Array}):Promise<boolean> }} opts.crypto
 * @param {number} opts.nowMs — REQUIRED finite epoch ms
 * @param {string|null} [opts.expectedLocalId] — the slot the caller fetched from; checked against the owner-keyed coordinate
 * @param {{ revokedCertIds?:(string[]|Set<string>), minValidIssuedAtMs?:number }|null} [opts.revocationState]
 * @returns {Promise<{ok:boolean, mode?:"direct"|"delegated", localId?:string, ownerPublicKeyB64?:string, signerPublicKeyB64?:string, recordKind?:string, recordId?:string, grantedCapabilities?:string[], leafCertId?:string|null, payloadB64?:string, reason?:string, failedAt?:number}>}
 */
export async function verifyDurableRecordV2({
  record,
  crypto,
  nowMs,
  expectedLocalId = null,
  revocationState = null,
} = {}) {
  if (!record || typeof record !== "object") {
    return { ok: false, reason: "record required" };
  }
  if (record.v !== DURABLE_RECORD_V2_VERSION) {
    return { ok: false, reason: "record.v must be " + DURABLE_RECORD_V2_VERSION };
  }
  const owner = String(record.ownerPublicKeyB64 || "").trim();
  const signer = String(record.signerPublicKeyB64 || "").trim();
  const kind = String(record.recordKind || "").trim();
  const id = String(record.recordId || "").trim();
  if (!owner) return { ok: false, reason: "ownerPublicKeyB64 required" };
  if (!signer) return { ok: false, reason: "signerPublicKeyB64 required" };
  if (!kind) return { ok: false, reason: "recordKind required" };
  if (!id) return { ok: false, reason: "recordId required" };
  if (!crypto || typeof crypto.verify !== "function") {
    return { ok: false, reason: "crypto.verify required" };
  }
  if (typeof nowMs !== "number" || !Number.isFinite(nowMs)) {
    return { ok: false, reason: "nowMs required (finite) for expiry check" };
  }
  if (typeof record.sigB64 !== "string" || record.sigB64.trim().length === 0) {
    return { ok: false, reason: "sigB64 required" };
  }
  if (!Number.isFinite(record.issuedAtMs) || !Number.isFinite(record.expiresAtMs)) {
    return { ok: false, reason: "issuedAtMs/expiresAtMs must be finite" };
  }

  // Time window — required, never fail-open.
  if (nowMs < record.issuedAtMs) return { ok: false, reason: "record not yet valid" };
  if (nowMs >= record.expiresAtMs) return { ok: false, reason: "record expired" };

  // Slot binding: the coordinate is keyed on the OWNER. If the caller tells us
  // where it fetched the record, reject a record whose owner-keyed slot differs
  // (substitution / wrong coordinate).
  const localId = durableRecordV2Slot({ ownerPublicKeyB64: owner, recordKind: kind, recordId: id });
  if (expectedLocalId !== null && String(expectedLocalId).trim() !== localId) {
    return { ok: false, reason: "record slot does not match the owner-keyed coordinate (substitution)" };
  }

  // Signature against the SIGNER key (B for direct, C for delegated).
  let sigBytes;
  let signerPub;
  try {
    sigBytes = base64ToBytes(record.sigB64);
    signerPub = base64ToBytes(signer);
  } catch (err) {
    return { ok: false, reason: "malformed signature or signer key: " + (err && err.message ? err.message : "unknown") };
  }
  let msg;
  try {
    msg = durableRecordV2SignableBytes(record);
  } catch (err) {
    return { ok: false, reason: "signable bytes: " + (err && err.message ? err.message : "unknown") };
  }
  const sigOk = await crypto.verify({ publicKey: signerPub, msg, sig: sigBytes });
  if (!sigOk) {
    return { ok: false, reason: "record signature invalid" };
  }

  // Authority: owner→signer. DIRECT when signer == owner and no chain (the
  // unchanged V1 primary path); DELEGATED via the cert chain otherwise.
  const certChain = Array.isArray(record.certChain) && record.certChain.length > 0 ? record.certChain : null;
  const authority = await verifyAccountAuthority({
    expectedAccountIdentityPublicKeyB64: owner,
    requiredCapability: record.requiredCapability === undefined ? null : record.requiredCapability,
    opSignerPublicKeyB64: signer,
    certChain,
    crypto,
    nowMs,
    revocationState,
  });
  if (!authority.ok) {
    return { ok: false, reason: "authority: " + authority.reason, failedAt: authority.failedAt };
  }

  return {
    ok: true,
    mode: authority.mode,
    localId,
    ownerPublicKeyB64: owner,
    signerPublicKeyB64: signer,
    recordKind: kind,
    recordId: id,
    grantedCapabilities: authority.grantedCapabilities,
    leafCertId: authority.leafCertId === undefined ? null : authority.leafCertId,
    payloadB64: record.payloadB64,
  };
}
