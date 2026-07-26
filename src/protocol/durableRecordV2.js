import { canonicalJSONStringify } from "../util/canonicalize.js";
import { base64ToBytes } from "../util/bytes.js";
import { durableRecordLocalId } from "./durableRecordV1.js";
import { verifyAccountAuthority } from "../objects/device/verifyAccountAuthority.js";
import { AccountAuthorityStateV1, ACCOUNT_AUTHORITY_STATE_RECORD_KIND } from "../objects/device/AccountAuthorityStateV1.js";

/**
 * Record kinds that ONLY the account root may sign (audit P0, 2026-07-26).
 *
 * A record that decides who is authorized cannot be authored by a delegated signer, or the party a
 * revocation names can rewrite it. The rule is structural — signer must equal owner, no cert chain,
 * no delegated capability — precisely because the overlay is account-agnostic and cannot check
 * revocation for accounts it does not home.
 *
 * SSOT: enforced once in verifyDurableRecordV2, so every verification site (the home's record.put,
 * a stranger replica accepting dht.rec_store, and a peer reading the slot) inherits it.
 */
export const ROOT_SIGNED_ONLY_RECORD_KINDS = new Set([ACCOUNT_AUTHORITY_STATE_RECORD_KIND]);

/**
 * Record kinds whose payload carries a MONOTONIC epoch (audit P0 follow-on, 2026-07-26).
 *
 * `issuedAtMs` orders a slot, but it is a self-asserted wall clock: it says when a record was made,
 * not where it sits in the account's authority history. Root-only signing closed the FORGERY door;
 * it does not close ROLLBACK — a genuinely root-signed OLDER snapshot, replayed after the newer one
 * expires out of a slot, still un-revokes a device. Ordering therefore has to key on the account's
 * own monotonic counter, and the holder has to remember the highest one it ever saw.
 *
 * Each entry maps the kind to the reader that projects `{ accountIdentityPublicKeyB64, epoch }` out
 * of its payload. The reader lives with the payload's class (SSOT) — this map only says WHICH kinds
 * are epoch-ordered, never what their payloads look like.
 *
 * Deliberately a SEPARATE set from ROOT_SIGNED_ONLY_RECORD_KINDS even though today they hold the
 * same one kind: "who may sign this" and "is this payload epoch-ordered" are independent properties,
 * and a future delegated-but-epoch-ordered kind must still get the binding check below.
 */
const MONOTONIC_EPOCH_READERS = new Map([
  [ACCOUNT_AUTHORITY_STATE_RECORD_KIND, (json) => AccountAuthorityStateV1.monotonicBindingOf(json)],
]);

/** Whether a record kind's payload carries a monotonic epoch (see MONOTONIC_EPOCH_READERS). */
export function recordKindCarriesMonotonicEpoch(recordKind) {
  return MONOTONIC_EPOCH_READERS.has(String(recordKind || "").trim());
}

/**
 * The monotonic epoch a record's payload asserts, and the account it binds itself to.
 *
 * Returns `null` — explicitly, meaning "this kind is not epoch-ordered" — for every other kind.
 * THROWS when the kind IS epoch-ordered but its payload cannot be read: absence is not a zero, and a
 * slot that silently treated an unreadable payload as epoch 0 would admit every rollback it exists
 * to stop. Callers turn the throw into a rejection.
 *
 * @param {object} record - a durable record (V1 or V2; the projection is version-agnostic because
 *   both versions carry `recordKind` + `payloadB64` and land on the SAME slot coordinate)
 * @returns {{ accountIdentityPublicKeyB64: string, epoch: number }|null}
 */
export function durableRecordMonotonicBinding(record) {
  if (!record || typeof record !== "object") {
    throw new Error("durableRecordMonotonicBinding requires a record object");
  }
  const kind = String(record.recordKind || "").trim();
  const read = MONOTONIC_EPOCH_READERS.get(kind);
  if (read === undefined) return null;
  let json;
  try {
    json = JSON.parse(new TextDecoder().decode(base64ToBytes(String(record.payloadB64 || ""))));
  } catch (err) {
    throw new Error("record kind " + kind + " payload is not decodable JSON: "
      + (err && err.message ? err.message : "unknown"));
  }
  return read(json);
}

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

  // ROOT-ONLY KINDS (audit P0, 2026-07-26). A record that decides who is authorized may not be
  // authored by a delegated signer: a revoked device still holds its key and its (now-revoked)
  // cert, so it could sign a newer authority state omitting its own certId and un-revoke itself
  // for every off-home peer. That is not a hypothetical — it was reachable through the generic
  // record.put, which does not bind a record to a session.
  //
  // Checking revocation at the write path CANNOT fix this: the overlay is account-agnostic. A node
  // that does not home an account has no way to learn its revocation state, so an attacker simply
  // publishes to any other replica. The rule therefore has to be STRUCTURAL — verifiable by a
  // stranger holding nothing but the record — which is exactly what "signer is the owner" is.
  //
  // Delegated devices still PUBLISH these records (the client-owned drain is unchanged); they may
  // not AUTHOR them.
  if (ROOT_SIGNED_ONLY_RECORD_KINDS.has(kind)) {
    if (signer !== owner) {
      return { ok: false, reason: "record kind " + kind + " must be signed by the account root (signer must equal owner)" };
    }
    if (Array.isArray(record.certChain) && record.certChain.length > 0) {
      return { ok: false, reason: "record kind " + kind + " must carry no cert chain (root-signed, direct mode only)" };
    }
    if (record.requiredCapability !== undefined && record.requiredCapability !== null) {
      return { ok: false, reason: "record kind " + kind + " must not assert a delegated capability" };
    }
  }

  // EPOCH-ORDERED KINDS: the payload must name the SAME account the envelope is owned by, and must
  // carry a readable epoch. Without this the epoch a holder pins its rollback floor to would be
  // unauthenticated relative to the slot — the envelope signature covers the payload bytes, but
  // nothing would tie the account INSIDE the payload to the owner key the slot is derived from, so
  // one account's slot could hold a state speaking for another. Structural, so every verification
  // site (home record.put, stranger replica, peer read) inherits it.
  if (recordKindCarriesMonotonicEpoch(kind)) {
    let binding;
    try {
      binding = durableRecordMonotonicBinding(record);
    } catch (err) {
      return { ok: false, reason: "record kind " + kind + " payload is unreadable: " + (err && err.message ? err.message : "unknown") };
    }
    if (binding === null) {
      // Unreachable given the guard above; if the two ever disagree, fail CLOSED rather than skip.
      return { ok: false, reason: "record kind " + kind + " is epoch-ordered but yielded no binding" };
    }
    if (binding.accountIdentityPublicKeyB64 !== owner) {
      return { ok: false, reason: "record kind " + kind + " payload is not bound to the record owner" };
    }
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
