/**
 * MeshAddressV1 — the destination a creator hands to mesh dispatch.
 *
 * This is a PROTOCOL-level contract: it knows nothing about any app built on
 * top (chat, twitter, reddit, blogs). The mesh routes exactly two general
 * things, and every app resolves its own domain reference (a chat peerLink, an
 * @handle, a board id) DOWN to one of these at dispatch time — app concepts
 * never travel up into the protocol:
 *
 *   - inbox:      push to a registered, claimant-owned, routable queue. The
 *                 creator's app has already resolved WHICH inbox (e.g. chat maps
 *                 a peerLink to its current peerInboxId, freshly, per send), so
 *                 the protocol carries only the inboxId. Routing resolves
 *                 inboxId → route and delivers (or buffers while offline).
 *   - rendezvous: pull/publish a self-authenticating value at a content
 *                 coordinate hash(publisherPub | kind | id). The publisher need
 *                 not be online; any holder serves it; any fetcher verifies it.
 *                 The coordinate vocabulary is the durable-record slot (SSOT in
 *                 durableRecordV1.js), reused verbatim. `recordKind` generalizes
 *                 across invites, posts, blogs, profiles, handle records, etc.
 *
 * Pure data contract: shape + validation only. Mapping a kind to a
 * resolver/substrate is the routing layer's job; mapping an app concept (a
 * peerLink, an @handle) to an address is the app layer's job. Neither belongs
 * here, and no chat concept is permitted in this file.
 */

export const MESH_ADDRESS_KINDS = Object.freeze({
  INBOX: "inbox",
  RENDEZVOUS: "rendezvous",
});

/**
 * Build an inbox address — push to a registered, routable queue. The caller's
 * app has already resolved its domain reference to a concrete, current inboxId.
 *
 * @param {{ inboxId: string }} args
 * @returns {{ kind: string, inboxId: string }}
 */
export function buildInboxAddress({ inboxId } = {}) {
  const id = String(inboxId || "").trim();
  if (!id) throw new Error("buildInboxAddress requires inboxId");
  return { kind: MESH_ADDRESS_KINDS.INBOX, inboxId: id };
}

/**
 * Build a rendezvous address — a content coordinate (the durable-record slot)
 * any holder can pull, publisher offline or not.
 *
 * @param {{ recordKind: string, recordId: string, publisherPublicKeyB64: string }} args
 * @returns {{ kind: string, recordKind: string, recordId: string, publisherPublicKeyB64: string }}
 */
export function buildRendezvousAddress({ recordKind, recordId, publisherPublicKeyB64 } = {}) {
  const kind = String(recordKind || "").trim();
  const id = String(recordId || "").trim();
  const pub = String(publisherPublicKeyB64 || "").trim();
  if (!kind) throw new Error("buildRendezvousAddress requires recordKind");
  if (!id) throw new Error("buildRendezvousAddress requires recordId");
  if (!pub) throw new Error("buildRendezvousAddress requires publisherPublicKeyB64");
  return {
    kind: MESH_ADDRESS_KINDS.RENDEZVOUS,
    recordKind: kind,
    recordId: id,
    publisherPublicKeyB64: pub,
  };
}

/**
 * Predicate: is `address` a well-formed mesh address of a known kind with all
 * required fields present and non-empty?
 *
 * @param {*} address
 * @returns {boolean}
 */
export function isMeshAddress(address) {
  if (!address || typeof address !== "object") return false;
  if (address.kind === MESH_ADDRESS_KINDS.INBOX) {
    return typeof address.inboxId === "string" && address.inboxId.trim().length > 0;
  }
  if (address.kind === MESH_ADDRESS_KINDS.RENDEZVOUS) {
    return typeof address.recordKind === "string" && address.recordKind.trim().length > 0
      && typeof address.recordId === "string" && address.recordId.trim().length > 0
      && typeof address.publisherPublicKeyB64 === "string" && address.publisherPublicKeyB64.trim().length > 0;
  }
  return false;
}

/**
 * Assert `address` is a valid mesh address; throw with a precise reason if not.
 * Returns the address on success so callers can guard-and-use in one step.
 *
 * @param {*} address
 * @returns {object} the validated address
 */
export function assertValidMeshAddress(address) {
  if (!address || typeof address !== "object") {
    throw new Error("mesh address must be an object");
  }
  if (address.kind !== MESH_ADDRESS_KINDS.INBOX && address.kind !== MESH_ADDRESS_KINDS.RENDEZVOUS) {
    throw new Error("mesh address kind must be 'inbox' or 'rendezvous' (got " + String(address.kind) + ")");
  }
  if (!isMeshAddress(address)) {
    throw new Error("mesh address of kind '" + address.kind + "' is missing required fields");
  }
  return address;
}
