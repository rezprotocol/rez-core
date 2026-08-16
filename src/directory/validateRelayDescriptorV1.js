import { RelayDescriptorV1 } from "../objects/index.js";

/**
 * Compatibility adapter over the ONE canonical descriptor validator,
 * `RelayDescriptorV1` (ATLAS_PREREQUISITES P2.1). This function owns NO
 * schema: no field lists, no limits, no regexes — it only funnels input
 * through the class and converts throw → verdict.
 *
 * Already-constructed instances are deliberately re-validated through their
 * JSON form: the old `instanceof` short-circuit skipped the expiry check, so
 * an expired instance passed while identical JSON was rejected.
 */
export function validateRelayDescriptorV1(value, { nowMs } = {}) {
  try {
    const json = value instanceof RelayDescriptorV1 ? value.toJSON() : value;
    const descriptor = RelayDescriptorV1.fromJSON(json, { nowMs });
    return { ok: true, descriptor };
  } catch (err) {
    return { ok: false, reason: err && err.message || "invalid" };
  }
}
