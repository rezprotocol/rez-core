const INVITE_CODE_V3_PREFIX = "rez:inv:v3:";

/**
 * Durable-record `recordKind` for published peer-link invite envelopes. The
 * inviter publishes the signed envelope under this kind (keyed by inviteId +
 * publisher key); the acceptor fetches it the same way. Single source of
 * truth so the publish (SDK) and fetch (chat-server) sides never drift.
 */
export const PEERLINK_INVITE_RECORD_KIND = "peerlink-invite";

/**
 * Invite code v3 — `rez:inv:v3:<inviteId>.<publisherPublicKeyB64>`.
 *
 * Unlike v2 (which carried the inviter's inbox so the acceptor could send a
 * live claim.req), v3 carries the inviter's signing public key. That key is
 * (a) the commitment used to fetch + verify the inviter's durable invite
 * record without the inviter online, and (b) the substitution-safety anchor:
 * the fetched record must be signed by exactly this key. The handshake
 * delivery target now comes from the signed envelope's binding, so the inbox
 * id is no longer needed in the code.
 */
export function encodeInviteCodeV3({ inviteId, publisherPublicKeyB64 } = {}) {
  const id = String(inviteId || "").trim();
  const pub = String(publisherPublicKeyB64 || "").trim();
  if (!id) throw new Error("encodeInviteCodeV3 requires inviteId");
  if (!pub) throw new Error("encodeInviteCodeV3 requires publisherPublicKeyB64");
  if (id.indexOf(".") !== -1) throw new Error("encodeInviteCodeV3: inviteId must not contain '.'");
  return INVITE_CODE_V3_PREFIX + id + "." + pub;
}

export function parseInviteCodeV3(code) {
  const text = String(code || "").trim();
  if (!text.startsWith(INVITE_CODE_V3_PREFIX)) {
    const err = new Error("invite code v3 prefix invalid");
    err.code = "INVITE_V3_INVALID_FORMAT";
    throw err;
  }
  const body = text.slice(INVITE_CODE_V3_PREFIX.length);
  const dotIndex = body.indexOf(".");
  if (dotIndex <= 0 || dotIndex === body.length - 1) {
    const err = new Error("invite code v3 format malformed");
    err.code = "INVITE_V3_INVALID_FORMAT";
    throw err;
  }
  const inviteId = body.slice(0, dotIndex);
  const publisherPublicKeyB64 = body.slice(dotIndex + 1);
  if (!inviteId || !publisherPublicKeyB64) {
    const err = new Error("invite code v3 fields empty");
    err.code = "INVITE_V3_INVALID_FORMAT";
    throw err;
  }
  return { inviteId, publisherPublicKeyB64 };
}

export function isInviteCodeV3(code) {
  return typeof code === "string" && code.startsWith(INVITE_CODE_V3_PREFIX);
}
