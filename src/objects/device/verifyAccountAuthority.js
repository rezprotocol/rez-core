import { base64ToBytes } from "../../util/bytes.js";
import {
  AccountDeviceCapabilityV1,
  ACCOUNT_DEVICE_CAPABILITY_PURPOSE,
} from "./AccountDeviceCapabilityV1.js";
import { ACCOUNT_CAPABILITY_ACTIONS, isKnownCapability } from "./accountCapabilityShared.js";

/**
 * verifyAccountAuthority — decide whether `opSignerPublicKeyB64` is authorized to
 * perform `requiredCapability` FOR a specific account (S2.5 Slice 6). This is the
 * single dual-mode helper every B-signed operation routes through; it does NOT
 * verify the operation's own payload signature (the caller does that against
 * `opSignerPublicKeyB64` over the operation bytes) — it answers only the
 * authority question.
 *
 *   - DIRECT mode: no cert chain, and the operation is signed by the account root
 *     itself (`opSignerPublicKeyB64 === expectedAccountIdentityPublicKeyB64`). The
 *     account holds every capability. This is the unchanged primary-device path.
 *   - DELEGATED mode: a cert chain C←…←B is presented. The chain must anchor to
 *     the EXPECTED account at every link, be signed correctly at every hop, narrow
 *     capabilities + depth + TTL at every re-delegation, contain no revoked cert,
 *     be within its time window, and its LEAF must be granted to the operation
 *     signer and include `requiredCapability`.
 *
 * PURITY (Slice 6 guardrail): revocation/authority state is PASSED IN, never
 * fetched. Callers at the home / on a peer supply the freshest state they hold;
 * the bounded-staleness policy lives at the call site, not here. `nowMs` is
 * REQUIRED (no fail-open on expiry for an authorization-grade decision).
 *
 * @param {object} opts
 * @param {string} opts.expectedAccountIdentityPublicKeyB64 — REQUIRED trust anchor (B-sign pubkey)
 * @param {string|null} [opts.requiredCapability] — capability the op needs; null = membership only (any valid leaf)
 * @param {string} opts.opSignerPublicKeyB64 — who signed the operation (B for direct, C for delegated)
 * @param {Array<object>|null} [opts.certChain] — AccountDeviceCapabilityV1 instances or their toJSON(); empty/absent ⇒ direct mode
 * @param {{ verify(args:{publicKey:Uint8Array,msg:Uint8Array,sig:Uint8Array}):Promise<boolean> }} opts.crypto
 * @param {number} opts.nowMs — REQUIRED finite epoch ms
 * @param {{ revokedCertIds?:(string[]|Set<string>), minValidIssuedAtMs?:number }|null} [opts.revocationState]
 * @returns {Promise<{ok:boolean, mode?:"direct"|"delegated", accountIdentityPublicKeyB64?:string, grantedCapabilities?:string[], leafCertId?:string, reason?:string, failedAt?:number}>}
 */
export async function verifyAccountAuthority({
  expectedAccountIdentityPublicKeyB64,
  requiredCapability = null,
  opSignerPublicKeyB64,
  certChain = null,
  crypto,
  nowMs,
  revocationState = null,
} = {}) {
  if (typeof expectedAccountIdentityPublicKeyB64 !== "string" || expectedAccountIdentityPublicKeyB64.trim().length === 0) {
    return { ok: false, reason: "expectedAccountIdentityPublicKeyB64 required (trust anchor)" };
  }
  if (typeof opSignerPublicKeyB64 !== "string" || opSignerPublicKeyB64.trim().length === 0) {
    return { ok: false, reason: "opSignerPublicKeyB64 required" };
  }
  if (!crypto || typeof crypto.verify !== "function") {
    return { ok: false, reason: "crypto.verify required" };
  }
  if (typeof nowMs !== "number" || !Number.isFinite(nowMs)) {
    return { ok: false, reason: "nowMs required (finite) for expiry check" };
  }
  if (requiredCapability !== null && !isKnownCapability(requiredCapability)) {
    return { ok: false, reason: 'unknown requiredCapability "' + requiredCapability + '"' };
  }

  const hasChain = Array.isArray(certChain) && certChain.length > 0;

  // ── DIRECT mode ─────────────────────────────────────────────────────────────
  if (!hasChain) {
    if (opSignerPublicKeyB64.trim() === expectedAccountIdentityPublicKeyB64.trim()) {
      return {
        ok: true,
        mode: "direct",
        accountIdentityPublicKeyB64: expectedAccountIdentityPublicKeyB64,
        grantedCapabilities: [...ACCOUNT_CAPABILITY_ACTIONS],
      };
    }
    return { ok: false, reason: "no cert chain and op signer is not the account root (direct mode requires B-sign)" };
  }

  // ── DELEGATED mode ──────────────────────────────────────────────────────────
  const revoked = new Set();
  let minValidIssuedAtMs = null;
  if (revocationState && typeof revocationState === "object") {
    const ids = revocationState.revokedCertIds;
    if (Array.isArray(ids)) {
      for (const id of ids) revoked.add(id);
    } else if (ids instanceof Set) {
      for (const id of ids) revoked.add(id);
    }
    if (typeof revocationState.minValidIssuedAtMs === "number" && Number.isFinite(revocationState.minValidIssuedAtMs)) {
      minValidIssuedAtMs = revocationState.minValidIssuedAtMs;
    }
  }

  // Reconstruct each cert (structural validate + deterministic certId via _seal).
  const recs = [];
  for (let i = 0; i < certChain.length; i++) {
    const raw = certChain[i];
    const json = raw && typeof raw.toJSON === "function" ? raw.toJSON() : raw;
    if (!json || typeof json !== "object") {
      return { ok: false, reason: "cert is not an object", failedAt: i };
    }
    if (json.purpose !== ACCOUNT_DEVICE_CAPABILITY_PURPOSE) {
      return { ok: false, reason: "cert purpose mismatch", failedAt: i };
    }
    let rec;
    try {
      rec = new AccountDeviceCapabilityV1(json);
    } catch (err) {
      return { ok: false, reason: "cert failed structural validation: " + (err && err.message ? err.message : "unknown"), failedAt: i };
    }
    recs.push(rec);
  }

  const seenCertIds = new Set();
  for (let i = 0; i < recs.length; i++) {
    const rec = recs[i];

    // Anchoring: every cert names the EXPECTED account (impersonation gap).
    if (rec.accountIdentityPublicKeyB64.trim() !== expectedAccountIdentityPublicKeyB64.trim()) {
      return { ok: false, reason: "cert account mismatch (not the expected account)", failedAt: i };
    }

    // No duplicate cert in the chain (replay / loop).
    if (seenCertIds.has(rec.certId)) {
      return { ok: false, reason: "duplicate cert in chain", failedAt: i };
    }
    seenCertIds.add(rec.certId);

    // Revocation: a revoked cert kills the chain. Because every ancestor is in the
    // chain, revoking a parent recursively invalidates all descendants.
    if (revoked.has(rec.certId)) {
      return { ok: false, reason: "cert revoked", failedAt: i };
    }
    if (minValidIssuedAtMs !== null && rec.issuedAtMs < minValidIssuedAtMs) {
      return { ok: false, reason: "cert predates the account authority cutoff", failedAt: i };
    }

    // Time window — required, never fail-open.
    if (nowMs < rec.issuedAtMs) {
      return { ok: false, reason: "cert not yet valid", failedAt: i };
    }
    if (nowMs >= rec.expiresAtMs) {
      return { ok: false, reason: "cert expired", failedAt: i };
    }

    // Signature over the canonical signed body, by the cert's own signer key.
    let sigBytes;
    let signerPub;
    try {
      sigBytes = base64ToBytes(rec.sig.sigB64);
      signerPub = base64ToBytes(rec.signerPublicKeyB64);
    } catch (err) {
      return { ok: false, reason: "malformed cert signature or signer key: " + (err && err.message ? err.message : "unknown"), failedAt: i };
    }
    const msg = AccountDeviceCapabilityV1.signableBytes(rec);
    const sigOk = await crypto.verify({ publicKey: signerPub, msg, sig: sigBytes });
    if (!sigOk) {
      return { ok: false, reason: "cert signature invalid", failedAt: i };
    }

    if (i === 0) {
      // Root: signed by the account root itself.
      if (rec.parentCertId !== null) {
        return { ok: false, reason: "root cert must have parentCertId === null", failedAt: i };
      }
      if (rec.signerPublicKeyB64.trim() !== expectedAccountIdentityPublicKeyB64.trim()) {
        return { ok: false, reason: "root cert must be signed by the account root", failedAt: i };
      }
    } else {
      // Non-root: linked to + signed by the parent's grantee, narrowing scope/depth/TTL.
      const parent = recs[i - 1];
      if (rec.parentCertId !== parent.certId) {
        return { ok: false, reason: "parentCertId does not link to the preceding cert", failedAt: i };
      }
      if (rec.signerPublicKeyB64 !== parent.granteeDevicePublicKeyB64) {
        return { ok: false, reason: "cert signer is not the parent's grantee (delegation linkage)", failedAt: i };
      }
      if (!parent.capabilities.includes("capability.delegate")) {
        return { ok: false, reason: "parent lacks capability.delegate", failedAt: i };
      }
      if (parent.maxDelegationDepth < 1) {
        return { ok: false, reason: "parent has no remaining delegation depth", failedAt: i };
      }
      // Exact depth consumption: each hop strictly decrements.
      if (rec.maxDelegationDepth > parent.maxDelegationDepth - 1) {
        return { ok: false, reason: "cert does not consume delegation depth", failedAt: i };
      }
      // Subset narrowing: a child can only grant what the parent holds.
      for (const action of rec.capabilities) {
        if (!parent.capabilities.includes(action)) {
          return { ok: false, reason: 'cert grants "' + action + '" not held by parent', failedAt: i };
        }
      }
      // TTL narrowing: a child cannot outlive its parent.
      if (rec.expiresAtMs > parent.expiresAtMs) {
        return { ok: false, reason: "cert outlives its parent", failedAt: i };
      }
    }
  }

  // Leaf: the operation signer must BE the leaf grantee (non-bearer), and the leaf
  // must grant the required capability.
  const leaf = recs[recs.length - 1];
  if (leaf.granteeDevicePublicKeyB64 !== opSignerPublicKeyB64) {
    return { ok: false, reason: "operation signer is not the leaf cert grantee", failedAt: recs.length - 1 };
  }
  if (requiredCapability !== null && !leaf.capabilities.includes(requiredCapability)) {
    return { ok: false, reason: 'leaf cert does not grant "' + requiredCapability + '"', failedAt: recs.length - 1 };
  }

  return {
    ok: true,
    mode: "delegated",
    accountIdentityPublicKeyB64: expectedAccountIdentityPublicKeyB64,
    grantedCapabilities: [...leaf.capabilities],
    leafCertId: leaf.certId,
  };
}
