import { Hash } from "../../base/util/Hash.js";
import { canonicalJSONStringify } from "../../util/canonicalize.js";

/**
 * Shared primitives for the S2.5 account→device capability hierarchy (Slice 6).
 *
 * An account's signing root (B-sign) delegates named ADMIN actions to a device
 * key (C) via an `AccountDeviceCapabilityV1` cert; a bounded chain re-delegates
 * (B→C1→C2). Every operation that is B-signed today becomes dual-mode: signed
 * directly by B-sign, OR signed by C and accompanied by a cert chain that proves
 * B granted C the required action. This module is the SSOT for (1) the capability
 * vocabulary, (2) the cert-id derivation, so the record, the validator, and the
 * `verifyAccountAuthority` helper agree byte-for-byte.
 *
 * NOTE: `device.register` is deliberately ABSENT (audit call #2) — a valid leaf
 * capability cert IS the device registration; there is no second, independent
 * registration authority.
 */

// The locked vocabulary (audit call #2). Order is irrelevant — capabilities are
// validated by membership, and a cert's `capabilities` array is hashed as-carried.
export const ACCOUNT_CAPABILITY_ACTIONS = Object.freeze([
  "peerLink.create",
  "deviceSet.publish",
  "device.revoke",
  "capability.delegate",
  "capability.revoke",
]);

const ACTION_SET = new Set(ACCOUNT_CAPABILITY_ACTIONS);

export function isKnownCapability(action) {
  return ACTION_SET.has(action);
}

/**
 * Validate a cert's `capabilities` array: a non-empty array of KNOWN actions
 * with no duplicates. Throws Error(label …) on any deviation (mirrors the
 * deviceRecordShared throw style so a record's validate() fails loud). Returns
 * the validated array.
 */
export function requireCapabilityList(capabilities, label) {
  if (!Array.isArray(capabilities) || capabilities.length === 0) {
    throw new Error(label + " must be a non-empty array of capabilities");
  }
  const seen = new Set();
  for (const action of capabilities) {
    if (typeof action !== "string" || !ACTION_SET.has(action)) {
      throw new Error(label + ' has unknown capability "' + action + '"');
    }
    if (seen.has(action)) {
      throw new Error(label + ' has duplicate capability "' + action + '"');
    }
    seen.add(action);
  }
  return capabilities;
}

export const ACCOUNT_CAPABILITY_CERT_ID_PREFIX = "rez:cap:";

/**
 * Deterministic cert id over the cert's CORE body (every signed field except
 * `certId` and `sig`). Hashing the canonical JSON of the core body makes the id a
 * stable content address: a verifier recomputes it from the carried body and a
 * single bit-flip in any signed field changes the id. The id is then folded into
 * the signed body (see AccountDeviceCapabilityV1.signableBytes), so the signature
 * binds it too.
 */
export function deriveAccountCapabilityCertId(coreBody) {
  return ACCOUNT_CAPABILITY_CERT_ID_PREFIX + Hash.sha256Hex(canonicalJSONStringify(coreBody));
}
