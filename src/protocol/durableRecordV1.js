import { Hash } from "../base/util/Hash.js";
import { canonicalJSONStringify } from "../util/canonicalize.js";

/**
 * DurableRecordV1 — a public, signed, self-expiring key→blob record stored
 * on the Kademlia overlay independently of routing. The publisher signs it
 * once (while online); any holder can serve it and any fetcher verifies it
 * with a single signature check — no registry, no live publisher.
 *
 * Canonical shape:
 *   { v, recordKind, recordId, publisherPublicKeyB64,
 *     issuedAtMs, expiresAtMs, payloadB64, sigB64 }
 *
 * This module is the SSOT for the record's slot key and signed bytes so the
 * SDK (which signs records) and rez-node (which verifies them) agree
 * byte-for-byte. The crypto-bearing verifier lives in rez-node
 * (DurableRecord.js) because the concrete Ed25519 provider lives there.
 */

export const DURABLE_RECORD_VERSION = 1;

/**
 * Publisher-bound content address for a record's slot. Folding the publisher
 * key into the slot means two different publishers can never collide on — or
 * squat — the same `(recordKind, recordId)` slot: an attacker cannot
 * pre-occupy a victim's slot because their distinct key yields a distinct
 * hash. The result is a 64-char sha256 hex string and doubles as the
 * Kademlia routing target (it is already a 256-bit position in the same
 * keyspace as node ids).
 *
 * @param {{ publisherPublicKeyB64: string, recordKind: string, recordId: string }} args
 * @returns {string} 64-char sha256 hex
 */
export function durableRecordLocalId({ publisherPublicKeyB64, recordKind, recordId } = {}) {
  const pub = String(publisherPublicKeyB64 || "").trim();
  const kind = String(recordKind || "").trim();
  const id = String(recordId || "").trim();
  if (!pub) throw new Error("durableRecordLocalId requires publisherPublicKeyB64");
  if (!kind) throw new Error("durableRecordLocalId requires recordKind");
  if (!id) throw new Error("durableRecordLocalId requires recordId");
  return Hash.sha256Hex(pub + "|" + kind + ":" + id);
}

/**
 * The exact bytes the publisher signs and every verifier recomputes. Covers
 * every field EXCEPT `sigB64`. Deterministic via canonical JSON.
 *
 * @param {object} record
 * @returns {Uint8Array}
 */
export function durableRecordSignableBytes(record) {
  if (!record || typeof record !== "object") {
    throw new Error("durableRecordSignableBytes requires a record object");
  }
  const payload = {
    v: record.v,
    recordKind: record.recordKind,
    recordId: record.recordId,
    publisherPublicKeyB64: record.publisherPublicKeyB64,
    issuedAtMs: record.issuedAtMs,
    expiresAtMs: record.expiresAtMs,
    payloadB64: record.payloadB64,
  };
  return new TextEncoder().encode(canonicalJSONStringify(payload));
}

/**
 * Build the unsigned record skeleton. The caller signs
 * `durableRecordSignableBytes(record)` and assigns the base64 signature to
 * `sigB64`.
 *
 * @param {{ recordKind: string, recordId: string, publisherPublicKeyB64: string, payloadB64: string, issuedAtMs: number, expiresAtMs: number }} args
 * @returns {object} record without sigB64
 */
export function buildDurableRecordV1({ recordKind, recordId, publisherPublicKeyB64, payloadB64, issuedAtMs, expiresAtMs } = {}) {
  return {
    v: DURABLE_RECORD_VERSION,
    recordKind: String(recordKind || "").trim(),
    recordId: String(recordId || "").trim(),
    publisherPublicKeyB64: String(publisherPublicKeyB64 || "").trim(),
    issuedAtMs,
    expiresAtMs,
    payloadB64: String(payloadB64 || ""),
  };
}
