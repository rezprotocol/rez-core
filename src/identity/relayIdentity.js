/**
 * Relay identity derivation SSOT (ADR-RELAY-IDENTITY).
 *
 * A relay's identity is self-certifying: it is derived from the node's
 * persistent Ed25519 signing key (SPKI DER bytes, the exact bytes carried as
 * `nodePublicKeyB64` in peer auth and relay descriptors). Operators cannot
 * choose a relayKeyId; verifiers re-derive both IDs from the key and reject
 * mismatches.
 *
 *   relayKeyId = "rez:relay:" + sha256hex(spkiDerBytes)        (64 hex chars)
 *   nodeKeyId  = "nodekey:"   + sha256hex(spkiDerBytes)[0..32) (compat format)
 *
 * Dependency-free and runtime-neutral: uses only rez-core's pure-JS Hash and
 * base64 utilities so browser and Node callers produce identical results. Do
 * NOT import node:crypto here.
 */
import { RRecord } from "../base/RRecord.js";
import { Hash } from "../base/util/Hash.js";
import { base64ToBytes } from "../util/bytes.js";

export const RELAY_KEY_ID_PREFIX = "rez:relay:";
export const NODE_KEY_ID_PREFIX = "nodekey:";

/**
 * Ed25519 SubjectPublicKeyInfo DER prefix (RFC 8410): a 44-byte structure of
 * 12 header bytes followed by the 32 raw public-key bytes.
 */
const ED25519_SPKI_PREFIX = Object.freeze([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);
const ED25519_SPKI_LENGTH = 44;

const CANONICAL_RELAY_KEY_ID_RE = /^rez:relay:[0-9a-f]{64}$/;

/**
 * True when `value` is a structurally canonical self-certifying relay ID
 * (`rez:relay:` + 64 lowercase hex). Structural only — it does NOT prove the
 * holder controls the underlying key; use validateRelayIdentityBinding for
 * that when the key is available.
 */
export function isCanonicalRelayKeyId(value) {
  return typeof value === "string" && CANONICAL_RELAY_KEY_ID_RE.test(value);
}

export const RELAY_IDENTITY_REASONS = Object.freeze({
  OK: "ok",
  INVALID_PUBLIC_KEY: "invalid-public-key",
  RELAY_KEY_ID_MISMATCH: "relay-key-id-mismatch",
  NODE_KEY_ID_MISMATCH: "node-key-id-mismatch",
});

function decodeSpkiDer(nodePublicKeyB64) {
  if (typeof nodePublicKeyB64 !== "string" || nodePublicKeyB64.trim().length === 0) {
    return null;
  }
  let bytes;
  try {
    bytes = base64ToBytes(nodePublicKeyB64.trim());
  } catch (err) {
    // base64ToBytes throws on malformed input; for derivation from untrusted
    // input the bounded answer is "not a key" — the caller decides severity.
    if (!(err instanceof Error)) throw err;
    return null;
  }
  if (bytes.length !== ED25519_SPKI_LENGTH) return null;
  for (let i = 0; i < ED25519_SPKI_PREFIX.length; i += 1) {
    if (bytes[i] !== ED25519_SPKI_PREFIX[i]) return null;
  }
  return bytes;
}

function digestHex(nodePublicKeyB64) {
  const bytes = decodeSpkiDer(nodePublicKeyB64);
  if (bytes === null) return null;
  return Hash.sha256Hex(bytes);
}

/**
 * Canonical self-certifying relay identifier for a node public key.
 * @param {string} nodePublicKeyB64 - base64 Ed25519 SPKI DER public key
 * @returns {string} `rez:relay:<sha256-lowercase-hex>`
 * @throws {Error} when the input is not a valid Ed25519 SPKI DER key
 */
export function relayKeyIdForNodePublicKeyB64(nodePublicKeyB64) {
  const hex = digestHex(nodePublicKeyB64);
  if (hex === null) {
    throw new Error("relayKeyIdForNodePublicKeyB64 requires a base64 Ed25519 SPKI DER public key");
  }
  return RELAY_KEY_ID_PREFIX + hex;
}

/**
 * Canonical compatibility node-key identifier for a node public key.
 * @param {string} nodePublicKeyB64 - base64 Ed25519 SPKI DER public key
 * @returns {string} `nodekey:<first-32-hex>`
 * @throws {Error} when the input is not a valid Ed25519 SPKI DER key
 */
export function nodeKeyIdForNodePublicKeyB64(nodePublicKeyB64) {
  const hex = digestHex(nodePublicKeyB64);
  if (hex === null) {
    throw new Error("nodeKeyIdForNodePublicKeyB64 requires a base64 Ed25519 SPKI DER public key");
  }
  return NODE_KEY_ID_PREFIX + hex.slice(0, 32);
}

/**
 * Verdict for a relay-identity binding check. In-process structured value —
 * never a wire payload — but held to the RRecord contract like every other
 * structured value in rez-core.
 */
export class RelayIdentityBindingVerdictV1 extends RRecord {
  static type = "RelayIdentityBindingVerdictV1";

  constructor({ ok, reason } = {}) {
    super();
    this.ok = ok;
    this.reason = reason;
    this._seal();
  }

  validate() {
    this.assert(typeof this.ok === "boolean", "RelayIdentityBindingVerdictV1.ok must be boolean", { ok: this.ok });
    const reasons = Object.values(RELAY_IDENTITY_REASONS);
    this.assert(reasons.includes(this.reason),
      "RelayIdentityBindingVerdictV1.reason must be a bounded reason", { reason: this.reason });
    this.assert((this.reason === RELAY_IDENTITY_REASONS.OK) === (this.ok === true),
      "RelayIdentityBindingVerdictV1 ok/reason must agree", { ok: this.ok, reason: this.reason });
  }
}

/**
 * Validate that a presented (relayKeyId, nodeKeyId) pair is exactly the pair
 * derived from nodePublicKeyB64. Never throws for untrusted input — every
 * failure is a bounded verdict. Comparison is exact: canonical prefix and
 * lowercase hex only; no trimming of the presented IDs (a non-canonical form
 * IS a mismatch).
 *
 * @param {{ relayKeyId?: string, nodeKeyId?: string, nodePublicKeyB64?: string }} input
 * @returns {RelayIdentityBindingVerdictV1}
 */
export function validateRelayIdentityBinding({ relayKeyId, nodeKeyId, nodePublicKeyB64 } = {}) {
  const hex = digestHex(nodePublicKeyB64);
  if (hex === null) {
    return new RelayIdentityBindingVerdictV1({ ok: false, reason: RELAY_IDENTITY_REASONS.INVALID_PUBLIC_KEY });
  }
  if (relayKeyId !== RELAY_KEY_ID_PREFIX + hex) {
    return new RelayIdentityBindingVerdictV1({ ok: false, reason: RELAY_IDENTITY_REASONS.RELAY_KEY_ID_MISMATCH });
  }
  if (nodeKeyId !== NODE_KEY_ID_PREFIX + hex.slice(0, 32)) {
    return new RelayIdentityBindingVerdictV1({ ok: false, reason: RELAY_IDENTITY_REASONS.NODE_KEY_ID_MISMATCH });
  }
  return new RelayIdentityBindingVerdictV1({ ok: true, reason: RELAY_IDENTITY_REASONS.OK });
}
