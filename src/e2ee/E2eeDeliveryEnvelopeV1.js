import { RRecord } from "../base/index.js";
import { canonicalJSONStringify } from "../util/canonicalize.js";
import { base64ToBytes } from "../util/bytes.js";
import { requireCanonicalB64 } from "../util/canonicalBase64.js";
import { assertSafeJsonKeys, parseUntrustedJson } from "../util/safeJson.js";

export const E2EE_DELIVERY_ENVELOPE_VERSION = 1;
export const E2EE_DELIVERY_ENVELOPE_KIND = "rez.e2ee.delivery-envelope.v1";
export const E2EE_DELIVERY_ENVELOPE_PURPOSE = "rez:e2ee-delivery-envelope:v1";
export const SUPPORTED_E2EE_DELIVERY_ENVELOPE_VERSIONS = Object.freeze([
  E2EE_DELIVERY_ENVELOPE_VERSION,
]);

export const E2EE_DELIVERY_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const RECORD_KEYS = Object.freeze([
  "kind",
  "v",
  "purpose",
  "deliveryId",
  "createdAtMs",
  "expiresAtMs",
  "payloadB64",
]);

function assertExactKeys(raw) {
  assertSafeJsonKeys(raw, "E2eeDeliveryEnvelopeV1");
  const allowed = new Set(RECORD_KEYS);
  for (const key of Object.keys(raw)) {
    if (!allowed.has(key)) {
      throw new Error("E2eeDeliveryEnvelopeV1 contains unknown field: " + key);
    }
  }
}

export function requireE2eeDeliveryId(value, label = "deliveryId") {
  if (typeof value !== "string" || !E2EE_DELIVERY_ID_PATTERN.test(value)) {
    throw new Error(label + " must be 1..128 safe ASCII characters");
  }
  return value;
}

/**
 * Authenticated inner envelope for application/protocol bytes.
 *
 * The complete canonical envelope is ratchet-encrypted, so delivery identity,
 * creation time, expiry, and the opaque payload are authenticated together.
 * Carrier policy is deliberately absent: crypto never learns which carrier
 * transported these bytes.
 */
export class E2eeDeliveryEnvelopeV1 extends RRecord {
  static type = "E2eeDeliveryEnvelopeV1";

  constructor(raw = {}) {
    super();
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      throw new Error("E2eeDeliveryEnvelopeV1 requires an object");
    }
    assertExactKeys(raw);
    this.kind = raw.kind == null ? E2EE_DELIVERY_ENVELOPE_KIND : raw.kind;
    this.v = raw.v == null ? E2EE_DELIVERY_ENVELOPE_VERSION : raw.v;
    this.purpose = raw.purpose == null ? E2EE_DELIVERY_ENVELOPE_PURPOSE : raw.purpose;
    this.deliveryId = raw.deliveryId;
    this.createdAtMs = raw.createdAtMs;
    this.expiresAtMs = raw.expiresAtMs;
    this.payloadB64 = raw.payloadB64;
    this._seal();
  }

  validate() {
    this.assert(this.kind === E2EE_DELIVERY_ENVELOPE_KIND,
      "E2eeDeliveryEnvelopeV1.kind must be " + E2EE_DELIVERY_ENVELOPE_KIND);
    this.assert(this.v === E2EE_DELIVERY_ENVELOPE_VERSION,
      "E2eeDeliveryEnvelopeV1.v must be 1");
    this.assert(this.purpose === E2EE_DELIVERY_ENVELOPE_PURPOSE,
      "E2eeDeliveryEnvelopeV1.purpose must be " + E2EE_DELIVERY_ENVELOPE_PURPOSE);
    requireE2eeDeliveryId(this.deliveryId, "E2eeDeliveryEnvelopeV1.deliveryId");
    this.assert(Number.isSafeInteger(this.createdAtMs) && this.createdAtMs > 0,
      "E2eeDeliveryEnvelopeV1.createdAtMs must be a positive safe integer");
    this.assert(Number.isSafeInteger(this.expiresAtMs) && this.expiresAtMs > this.createdAtMs,
      "E2eeDeliveryEnvelopeV1.expiresAtMs must be a safe integer after createdAtMs");
    requireCanonicalB64(this.payloadB64, "E2eeDeliveryEnvelopeV1.payloadB64");
    this.assert(base64ToBytes(this.payloadB64).length > 0,
      "E2eeDeliveryEnvelopeV1.payloadB64 must decode to non-empty bytes");
  }

  toBytes() {
    return new TextEncoder().encode(canonicalJSONStringify(this.toJSON()));
  }

  payloadBytes() {
    return base64ToBytes(this.payloadB64);
  }

  static fromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
      throw new Error("E2eeDeliveryEnvelopeV1.fromBytes requires non-empty Uint8Array");
    }
    const raw = parseUntrustedJson(
      new TextDecoder().decode(bytes),
      "E2eeDeliveryEnvelopeV1",
    );
    return E2eeDeliveryEnvelopeV1.fromJSON(raw);
  }
}

export function e2eeDeliveryEnvelopeVersionOf(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  if (raw.kind !== E2EE_DELIVERY_ENVELOPE_KIND) return null;
  return Number.isInteger(raw.v) ? raw.v : null;
}

export function isSupportedE2eeDeliveryEnvelopeVersion(version) {
  return SUPPORTED_E2EE_DELIVERY_ENVELOPE_VERSIONS.includes(version);
}
