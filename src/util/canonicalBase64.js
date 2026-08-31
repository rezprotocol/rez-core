import { base64ToBytes, bytesToBase64 } from "./bytes.js";

export const CANONICAL_B64 = /^[A-Za-z0-9+/]+={0,2}$/;

/**
 * Require canonical standard base64: no whitespace, exact padding, and no
 * alternative text encoding for the same bytes.
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
