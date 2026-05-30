import { RSerializable } from "../../base/index.js";
import { isNonEmptyString } from "../../util/strings.js";
import { isFiniteNumber, validateSig, cloneSig, sigToJSON, sigFromJSON } from "../../util/settlement.js";

const HANDLE_MIN_LENGTH = 3;
const HANDLE_MAX_LENGTH = 32;
const HANDLE_PATTERN = /^[a-z0-9][a-z0-9_-]*[a-z0-9]$/;
const DEFAULT_TTL_MS = 365 * 24 * 60 * 60 * 1000; // 1 year

/**
 * A global handle claim: maps a unique name (e.g., "alice") to a publication key ID.
 *
 * Gossiped across the relay mesh. First-come-first-served — earliest
 * createdAtMs wins conflicts. Handles expire and must be renewed.
 *
 * Fields:
 *   handle — lowercase alphanumeric + hyphens/underscores, 3-32 chars
 *   keyId — the publication key ID this handle points to
 *   relayKeyId — the registrar relay that accepted this claim
 *   createdAtMs — when the claim was created
 *   expiresAtMs — when the claim expires (default 1 year from creation)
 *   previousKeyId — previous key ID if handle was reassigned (null for first claim)
 *   sig — Ed25519 signature from the registrar relay
 */
export class HandleClaimV1 extends RSerializable {
  static type = "HandleClaimV1";

  constructor({
    v = 1,
    handle,
    keyId,
    relayKeyId,
    createdAtMs,
    expiresAtMs,
    previousKeyId = null,
    sig,
  } = {}) {
    super();

    this.assert(v === 1, "HandleClaimV1.v must be 1", { v });
    this.assert(isNonEmptyString(handle), "HandleClaimV1.handle must be non-empty string", { handle });
    this.assert(handle.length >= HANDLE_MIN_LENGTH && handle.length <= HANDLE_MAX_LENGTH,
      "HandleClaimV1.handle must be " + HANDLE_MIN_LENGTH + "-" + HANDLE_MAX_LENGTH + " chars", { handle });
    this.assert(HANDLE_PATTERN.test(handle), "HandleClaimV1.handle must be lowercase alphanumeric with hyphens/underscores", { handle });
    this.assert(isNonEmptyString(keyId), "HandleClaimV1.keyId must be non-empty string", { keyId });
    this.assert(isNonEmptyString(relayKeyId), "HandleClaimV1.relayKeyId must be non-empty string", { relayKeyId });
    this.assert(isFiniteNumber(createdAtMs), "HandleClaimV1.createdAtMs must be number", { createdAtMs });
    this.assert(isFiniteNumber(expiresAtMs), "HandleClaimV1.expiresAtMs must be number", { expiresAtMs });
    this.assert(expiresAtMs > createdAtMs, "HandleClaimV1.expiresAtMs must be after createdAtMs", { expiresAtMs, createdAtMs });
    this.assert(previousKeyId === null || isNonEmptyString(previousKeyId),
      "HandleClaimV1.previousKeyId must be null or non-empty string", { previousKeyId });
    validateSig(sig, "HandleClaimV1");

    this.v = 1;
    this.handle = handle;
    this.keyId = keyId;
    this.relayKeyId = relayKeyId;
    this.createdAtMs = createdAtMs;
    this.expiresAtMs = expiresAtMs;
    this.previousKeyId = previousKeyId;
    this.sig = cloneSig(sig);
  }

  /**
   * Check if this claim has expired.
   * @param {number} [nowMs]
   * @returns {boolean}
   */
  isExpired(nowMs) {
    return (nowMs || Date.now()) >= this.expiresAtMs;
  }

  toJSON() {
    return {
      v: this.v,
      handle: this.handle,
      keyId: this.keyId,
      relayKeyId: this.relayKeyId,
      createdAtMs: this.createdAtMs,
      expiresAtMs: this.expiresAtMs,
      previousKeyId: this.previousKeyId,
      sig: sigToJSON(this.sig),
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("HandleClaimV1.fromJSON(json) requires object");
    }
    return new HandleClaimV1({
      v: json.v,
      handle: json.handle,
      keyId: json.keyId,
      relayKeyId: json.relayKeyId,
      createdAtMs: json.createdAtMs,
      expiresAtMs: json.expiresAtMs,
      previousKeyId: json.previousKeyId,
      sig: sigFromJSON(json.sig, "HandleClaimV1"),
    });
  }
}

export { HANDLE_MIN_LENGTH, HANDLE_MAX_LENGTH, HANDLE_PATTERN, DEFAULT_TTL_MS };
