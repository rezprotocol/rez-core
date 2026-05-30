const INVITE_CODE_V2_PREFIX = "rez:inv:v2:";

export function encodeInviteCodeV2({ inviteId, creatorInboxId } = {}) {
  const id = String(inviteId || "").trim();
  const inbox = String(creatorInboxId || "").trim();
  if (!id) throw new Error("encodeInviteCodeV2 requires inviteId");
  if (!inbox) throw new Error("encodeInviteCodeV2 requires creatorInboxId");
  return INVITE_CODE_V2_PREFIX + id + "." + inbox;
}

export function parseInviteCodeV2(code) {
  const text = String(code || "").trim();
  if (!text.startsWith(INVITE_CODE_V2_PREFIX)) {
    const err = new Error("invite code v2 prefix invalid");
    err.code = "INVITE_V2_INVALID_FORMAT";
    throw err;
  }
  const body = text.slice(INVITE_CODE_V2_PREFIX.length);
  const dotIndex = body.indexOf(".");
  if (dotIndex <= 0 || dotIndex === body.length - 1) {
    const err = new Error("invite code v2 format malformed");
    err.code = "INVITE_V2_INVALID_FORMAT";
    throw err;
  }
  const inviteId = body.slice(0, dotIndex);
  const creatorInboxId = body.slice(dotIndex + 1);
  if (!inviteId || !creatorInboxId) {
    const err = new Error("invite code v2 fields empty");
    err.code = "INVITE_V2_INVALID_FORMAT";
    throw err;
  }
  return { inviteId, creatorInboxId };
}

export function isInviteCodeV2(code) {
  return typeof code === "string" && code.startsWith(INVITE_CODE_V2_PREFIX);
}
