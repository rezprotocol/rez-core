import { canonicalJSONStringify } from "../../util/canonicalize.js";
import { base64ToBytes, bytesToBase64 } from "../../util/bytes.js";
import { isNonEmptyString } from "../../util/strings.js";

/**
 * Handle ownership proof — Ed25519 signatures that prove the caller controls
 * the keyId being claimed/released/renewed.
 *
 * `keyId` IS the base64 Ed25519 public key. A handle.register/renew/release
 * is authorized iff the request carries a signature by the matching private
 * key over a canonical payload binding (kind, handle, keyId, tsMs,
 * relayKeyId). The `relayKeyId` field pins the proof to a specific relay so
 * a captured signature can't be forwarded to a different relay that gossips
 * with this one. `tsMs` lets the relay reject stale proofs.
 *
 * Closes docs/SECURITY_AUDIT.md CRITICAL-3.
 */

const PROOF_KINDS = new Set(["handle.register", "handle.renew", "handle.release"]);

function isBytes(value) {
  return value instanceof Uint8Array;
}

function assertProofShape({ kind, handle, keyId, tsMs, relayKeyId }) {
  if (!PROOF_KINDS.has(kind)) {
    throw new Error("handle proof kind must be one of " + Array.from(PROOF_KINDS).join(", "));
  }
  if (!isNonEmptyString(handle)) {
    throw new Error("handle proof requires handle string");
  }
  if (!isNonEmptyString(keyId)) {
    throw new Error("handle proof requires keyId string");
  }
  if (!Number.isFinite(tsMs) || tsMs <= 0) {
    throw new Error("handle proof requires positive tsMs");
  }
  if (!isNonEmptyString(relayKeyId)) {
    throw new Error("handle proof requires relayKeyId string");
  }
}

/**
 * Build the canonical bytes that will be signed.
 * @param {{ kind: string, handle: string, keyId: string, tsMs: number, relayKeyId: string }} payload
 * @returns {Uint8Array}
 */
export function canonicalHandleProofBytes(payload) {
  assertProofShape(payload);
  return new TextEncoder().encode(canonicalJSONStringify({
    kind: payload.kind,
    handle: payload.handle,
    keyId: payload.keyId,
    tsMs: payload.tsMs,
    relayKeyId: payload.relayKeyId,
  }));
}

/**
 * Produce an ownership-proof signature for a handle mutation request.
 *
 * @param {object} opts
 * @param {string} opts.kind — "handle.register" | "handle.renew" | "handle.release"
 * @param {string} opts.handle
 * @param {string} opts.keyId — base64 Ed25519 pubkey
 * @param {number} opts.tsMs — wallclock ms when the proof was issued
 * @param {string} opts.relayKeyId — the relay this proof targets
 * @param {import("../../crypto/RCryptoProvider.js").RCryptoProvider} opts.crypto
 * @param {Uint8Array} opts.signingPrivateKey — privkey matching keyId
 * @returns {Promise<string>} base64 signature
 */
export async function signHandleOwnershipProof({
  kind,
  handle,
  keyId,
  tsMs,
  relayKeyId,
  crypto,
  signingPrivateKey,
} = {}) {
  if (!crypto || typeof crypto.sign !== "function" || typeof crypto.verify !== "function") {
    throw new Error("signHandleOwnershipProof requires crypto with sign/verify");
  }
  if (!isBytes(signingPrivateKey)) {
    throw new Error("signHandleOwnershipProof requires signingPrivateKey Uint8Array");
  }
  const msg = canonicalHandleProofBytes({ kind, handle, keyId, tsMs, relayKeyId });
  const sig = await crypto.sign({ privateKey: signingPrivateKey, msg });
  if (!isBytes(sig)) {
    throw new Error("crypto.sign returned non-bytes signature");
  }
  // Sanity-check that the privkey matches the claimed keyId pubkey BEFORE
  // shipping the proof. Catches keystore-mismatch bugs early.
  let pubKey;
  try {
    pubKey = base64ToBytes(keyId);
  } catch {
    throw new Error("signHandleOwnershipProof: keyId is not valid base64");
  }
  const verified = await crypto.verify({ publicKey: pubKey, msg, sig });
  if (verified !== true) {
    throw new Error("signHandleOwnershipProof: signingPrivateKey does not match keyId");
  }
  return bytesToBase64(sig);
}

/**
 * Verify an ownership-proof signature for a handle mutation request.
 *
 * The caller MUST also enforce a freshness window on `tsMs` and check
 * `relayKeyId` matches the local relay — neither is done here, since both
 * depend on context the helper doesn't own.
 *
 * @param {object} opts
 * @param {string} opts.kind
 * @param {string} opts.handle
 * @param {string} opts.keyId — base64 Ed25519 pubkey; doubles as the verifier key
 * @param {number} opts.tsMs
 * @param {string} opts.relayKeyId
 * @param {string} opts.signatureB64
 * @param {import("../../crypto/RCryptoProvider.js").RCryptoProvider} opts.crypto
 * @returns {Promise<boolean>}
 */
export async function verifyHandleOwnershipProof({
  kind,
  handle,
  keyId,
  tsMs,
  relayKeyId,
  signatureB64,
  crypto,
} = {}) {
  if (!crypto || typeof crypto.verify !== "function") {
    throw new Error("verifyHandleOwnershipProof requires crypto with verify");
  }
  if (typeof signatureB64 !== "string" || signatureB64.length === 0) return false;
  let pubKey;
  let sig;
  try {
    pubKey = base64ToBytes(keyId);
    sig = base64ToBytes(signatureB64);
  } catch {
    return false;
  }
  let msg;
  try {
    msg = canonicalHandleProofBytes({ kind, handle, keyId, tsMs, relayKeyId });
  } catch {
    return false;
  }
  try {
    const ok = await crypto.verify({ publicKey: pubKey, msg, sig });
    return ok === true;
  } catch {
    return false;
  }
}

export { PROOF_KINDS };
