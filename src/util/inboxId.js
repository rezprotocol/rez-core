// SSOT for the canonical inbox-id format across the protocol. An inbox id is
// "inbox:" + INBOX_ID_RANDOM_BYTES of lowercase hex — minted by the SDK
// (InboxClaimStore, the device-link requester) and consumed everywhere an explicit
// inbox is accepted (device-link ceremony inbox, delegated keystore, InboxClaimant).
// Exactly ONE length is canonical so requester, claim store, and keystore agree.

export const INBOX_ID_RANDOM_BYTES = 12; // 12 bytes → 24 lowercase-hex chars.
export const INBOX_ID_HEX_LEN = INBOX_ID_RANDOM_BYTES * 2; // 24

const CANONICAL_INBOX_ID_RE = new RegExp(`^inbox:[0-9a-f]{${INBOX_ID_HEX_LEN}}$`);

/** True iff `inboxId` is exactly "inbox:" + 24 lowercase hex chars. */
export function isCanonicalInboxId(inboxId) {
  return typeof inboxId === "string" && CANONICAL_INBOX_ID_RE.test(inboxId);
}

/**
 * Return the canonical inbox id or throw. Accepts leading/trailing whitespace
 * (trimmed) — fail loud on any other shape (wrong length, uppercase, non-hex,
 * missing prefix). One validator, one exact shape, everywhere.
 */
export function requireCanonicalInboxId(inboxId, context = "inboxId") {
  const v = typeof inboxId === "string" ? inboxId.trim() : "";
  if (!CANONICAL_INBOX_ID_RE.test(v)) {
    throw new Error(context + ' must be canonical ("inbox:" + ' + INBOX_ID_HEX_LEN + " lowercase hex chars), got: " + String(inboxId));
  }
  return v;
}
