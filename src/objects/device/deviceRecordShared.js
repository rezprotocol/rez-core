import { base64ToBytes, bytesToBase64, bytesToHex } from "../../util/bytes.js";

/**
 * Shared validation primitives for the S2.5 device-record family
 * (DeviceRegistrationV1, DeviceInboxBindingV1, DeviceSetRecordV1,
 * DeviceLinkRequestV1, …). SSOT: every device record validates key/signature
 * encodings identically, so a hardening (e.g. the audit's SPKI pinning) lands in
 * ONE place instead of drifting across siblings.
 */

// Ed25519 public key encoded as SPKI DER is exactly 44 bytes: a fixed 12-byte
// AlgorithmIdentifier prefix + the 32-byte raw key. Pinning BOTH length and
// prefix rejects a raw-32 key, a PKCS8 private key, or any other key type
// masquerading as a device/account identity key.
export const ED25519_SPKI_PREFIX_HEX = "302a300506032b6570032100";
export const ED25519_SPKI_LEN = 44;
export const CANONICAL_B64 = /^[A-Za-z0-9+/]+={0,2}$/;

export function isFiniteNumber(value) {
  return typeof value === "number" && Number.isFinite(value);
}

/**
 * Require a canonical STANDARD base64 string (no whitespace, exact round-trip).
 * Rejects non-canonical strings that base64ToBytes tolerates (stray padding,
 * unused trailing bits) which would hash differently than the bytes they decode
 * to. Returns the validated string. `length` (bytes) is enforced when given.
 */
export function requireCanonicalB64(value, label, { length = null } = {}) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(label + " must be a non-empty canonical base64 string");
  }
  if (!CANONICAL_B64.test(value)) {
    throw new Error(label + " must be canonical standard base64 (no whitespace)");
  }
  let bytes;
  try {
    bytes = base64ToBytes(value);
  } catch (err) {
    throw new Error(label + " is not decodable base64: " + (err && err.message ? err.message : "unknown"));
  }
  if (bytesToBase64(bytes) !== value) {
    throw new Error(label + " must be canonical base64 (round-trip mismatch)");
  }
  if (length != null && bytes.length !== length) {
    throw new Error(label + " must decode to " + length + " bytes, got " + bytes.length);
  }
  return value;
}

/**
 * Require a canonical base64 of a 44-byte Ed25519 SPKI DER public key — the exact
 * encoding the SDK signer/verifier and the rez-node verifier share. Any other
 * encoding yields a different self-certifying id (which hashes the exact string)
 * and a failed verify.
 */
export function requireCanonicalSpkiB64(value, label) {
  const v = requireCanonicalB64(value, label);
  const bytes = base64ToBytes(v);
  if (bytes.length !== ED25519_SPKI_LEN) {
    throw new Error(label + " must be a 44-byte Ed25519 SPKI DER public key, got " + bytes.length + " bytes");
  }
  if (bytesToHex(bytes.subarray(0, 12)) !== ED25519_SPKI_PREFIX_HEX) {
    throw new Error(label + " must carry the Ed25519 SPKI DER prefix");
  }
  return v;
}

// X25519 public key as SPKI DER — same 12-byte prefix shape as Ed25519 but
// with the X25519 OID (…6e vs …70). Pinning it rejects an Ed25519 signing key
// (or anything else) masquerading as a DH point before it reaches dhDerive.
export const X25519_SPKI_PREFIX_HEX = "302a300506032b656e032100";
export const X25519_SPKI_LEN = 44;

export function requireCanonicalX25519SpkiB64(value, label) {
  const v = requireCanonicalB64(value, label);
  const bytes = base64ToBytes(v);
  if (bytes.length !== X25519_SPKI_LEN) {
    throw new Error(label + " must be a 44-byte X25519 SPKI DER public key, got " + bytes.length + " bytes");
  }
  if (bytesToHex(bytes.subarray(0, 12)) !== X25519_SPKI_PREFIX_HEX) {
    throw new Error(label + " must carry the X25519 SPKI DER prefix");
  }
  return v;
}

// Accept the canonical `{ alg, sigB64 }` shape. Tolerate a missing/!object sig
// here (the record's validate() asserts it) so the constructor can assign a
// stable shape.
export function normalizeSig(sig) {
  if (!sig || typeof sig !== "object") return sig;
  return { alg: sig.alg, sigB64: sig.sigB64 };
}

/**
 * Validate the canonical Ed25519 signature envelope `{ alg:"ed25519", sigB64 }`.
 * Throws (with `label`) on any deviation — every device record signs with this
 * shape so verifiers decode identically.
 */
export function validateEd25519Sig(sig, label) {
  if (!sig || typeof sig !== "object") {
    throw new Error(label + " must be an object");
  }
  if (sig.alg !== "ed25519") {
    throw new Error(label + '.alg must be "ed25519"');
  }
  if (typeof sig.sigB64 !== "string" || sig.sigB64.length === 0 || !CANONICAL_B64.test(sig.sigB64)) {
    throw new Error(label + ".sigB64 must be a non-empty canonical base64 string");
  }
}
