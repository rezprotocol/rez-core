/**
 * Shared validation helpers for settlement, attestation, and pricing records.
 * Internal module — not exported from rez-core public API.
 *
 * SSOT for receipt signature format and pricing unit definitions.
 */

/** Canonical set of pricing units for service pricing across the protocol. */
export const PRICING_UNITS = new Set(["operation", "mb_month", "gb_month", "byte", "request"]);

export function isFinitePositive(value) {
  return typeof value === "number" && Number.isFinite(value) && value > 0;
}

export function isFiniteNumber(value) {
  return typeof value === "number" && Number.isFinite(value);
}

export function toSigBytes(value, label) {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return new Uint8Array(value);
  throw new Error(`${label} must be Uint8Array`);
}

export function validateSig(sig, typeName) {
  if (!sig || typeof sig !== "object") {
    throw new Error(`${typeName}.sig must be an object`);
  }
  if (sig.alg !== "ed25519") {
    throw new Error(`${typeName}.sig.alg must be "ed25519"`);
  }
  if (typeof sig.relayKeyId !== "string" || sig.relayKeyId.length === 0) {
    throw new Error(`${typeName}.sig.relayKeyId must be non-empty string`);
  }
  if (!(sig.sig instanceof Uint8Array) || sig.sig.length === 0) {
    throw new Error(`${typeName}.sig.sig must be non-empty Uint8Array`);
  }
}

export function cloneSig(sig) {
  return { alg: sig.alg, relayKeyId: sig.relayKeyId, sig: sig.sig };
}

export function sigToJSON(sig) {
  return {
    alg: sig.alg,
    relayKeyId: sig.relayKeyId,
    sig: Array.from(sig.sig),
  };
}

export function sigFromJSON(sig, typeName) {
  if (!sig || typeof sig !== "object") {
    throw new Error(`${typeName}.sig must be an object`);
  }
  return {
    alg: sig.alg,
    relayKeyId: sig.relayKeyId,
    sig: toSigBytes(sig.sig, `${typeName}.sig.sig`),
  };
}
