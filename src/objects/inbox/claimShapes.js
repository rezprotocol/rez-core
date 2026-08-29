/**
 * Canonical inbox claim / lease payload shapes — the SSOT both sides sign and
 * verify against (portable inbox lease, plans/PORTABLE_INBOX_LEASE_SPEC.md).
 *
 * Before this module, the signed-payload literals lived in the SDK signer
 * (InboxClaimStore), the node verifier (InboxClaimHandler), AND the relay
 * verifier (InboxRouter), kept in lockstep by comments — the exact drift
 * class that broke field forwarding once already. Every producer and
 * verifier now builds the bytes-to-sign from HERE.
 *
 * On "versions": a claim either CARRIES THE LEASE EXTENSION (close key +
 * generation signed into the claim; generation + retentionClass signed into
 * the delegation) or it is a legacy claim. That is a CAPABILITY of the
 * record, not a version number — which is why the predicate is named
 * `leaseFieldsPresence`, not `isV2`. A future extension adds its own named
 * fields, its own presence predicate, and extends these builders in ONE
 * place; it does not grow a version ladder through every call site.
 */

/**
 * Presence verdict for a field GROUP that is all-or-none by contract.
 * "partial" is always malformed — the caller maps it to its local failure
 * (BAD_REQUEST on the wire, dropped row in storage), never infers around it.
 * @returns {"none"|"all"|"partial"}
 */
function presence(flags) {
  const present = flags.filter(Boolean).length;
  if (present === 0) return "none";
  if (present === flags.length) return "all";
  return "partial";
}

/** Lease-extension presence on a CLAIM (wire body or signed-record fields). */
export function claimLeasePresence({ closePublicKeyB64, generation } = {}) {
  return presence([
    typeof closePublicKeyB64 === "string" && closePublicKeyB64.trim().length > 0,
    generation !== undefined && generation !== null,
  ]);
}

/** Lease-extension presence on a DELEGATION/lease (wire or record fields). */
export function delegationLeasePresence({ generation, retentionClass } = {}) {
  return presence([
    generation !== undefined && generation !== null,
    typeof retentionClass === "string" && retentionClass.trim().length > 0,
  ]);
}

/**
 * The canonical inbox-claim payload — the object whose canonical-JSON bytes
 * the claimant key signs. Legacy shape when the lease fields are absent;
 * extended shape when present. THROWS on a partial group: a malformed shape
 * must never acquire a canonical serialization.
 */
export function canonicalInboxClaimPayload({ inboxId, claimantPublicKeyB64, claimedAtMs, closePublicKeyB64, generation } = {}) {
  const lease = claimLeasePresence({ closePublicKeyB64, generation });
  if (lease === "partial") {
    throw new Error("canonicalInboxClaimPayload: closePublicKeyB64 and generation are all-or-none");
  }
  if (lease === "none") {
    return { inboxId, claimantPublicKeyB64, claimedAtMs };
  }
  return { inboxId, claimantPublicKeyB64, closePublicKeyB64, generation, claimedAtMs };
}

/**
 * The canonical claimant→node delegation (lease) payload — the object whose
 * canonical-JSON bytes the claimant key signs, verified identically by the
 * home node and by every relay on the routing path.
 */
export function canonicalNodeDelegationPayload({
  inboxId,
  claimantPublicKeyB64,
  nodeKeyId,
  nodePublicKeyB64,
  relayKeyId,
  issuedAtMs,
  expiresAtMs,
  generation,
  retentionClass,
} = {}) {
  const lease = delegationLeasePresence({ generation, retentionClass });
  if (lease === "partial") {
    throw new Error("canonicalNodeDelegationPayload: generation and retentionClass are all-or-none");
  }
  const payload = {
    kind: "inbox-node-delegation",
    inboxId,
    claimantPublicKeyB64,
    nodeKeyId,
    nodePublicKeyB64,
    relayKeyId,
    issuedAtMs,
    expiresAtMs,
  };
  if (lease === "all") {
    payload.generation = generation;
    payload.retentionClass = retentionClass;
  }
  return payload;
}
