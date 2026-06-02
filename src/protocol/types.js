/**
 * RCGP wire protocol type strings.
 *
 * Shared vocabulary — used by both client (SDK) and server (node).
 * 28 types replacing the previous 102 chat-specific types.
 */
export const REZ_CONTRACT_TYPES = Object.freeze({
  // --- session lifecycle (5) ---
  SESSION_HELLO: "session.hello",
  SESSION_CHALLENGE: "session.challenge",
  SESSION_AUTHENTICATE: "session.authenticate",
  SESSION_READY: "session.ready",
  ERROR: "error",

  // --- mailbox operations (9) ---
  MAILBOX_DEPOSIT: "mailbox.deposit",
  MAILBOX_DEPOSIT_RES: "mailbox.deposit.res",
  MAILBOX_LIST: "mailbox.list",
  MAILBOX_LIST_RES: "mailbox.list.res",
  MAILBOX_FETCH: "mailbox.fetch",
  MAILBOX_FETCH_RES: "mailbox.fetch.res",
  MAILBOX_ACK: "mailbox.ack",
  MAILBOX_ACK_RES: "mailbox.ack.res",
  EVT_MAILBOX_DEPOSITED: "evt.mailbox.deposited",
  EVT_OUTBOUND_STATUS: "evt.outbound.status",

  // --- inbox claim (open registration; see docs/CAPABILITY_MODEL.md §6) ---
  INBOX_CLAIM: "inbox.claim",
  INBOX_CLAIM_RES: "inbox.claim.res",

  // --- inbox deposit policy (claimant-signed; see docs/SECURITY_AUDIT.md HIGH-1) ---
  INBOX_SET_DEPOSIT_POLICY: "inbox.setDepositPolicy",
  INBOX_SET_DEPOSIT_POLICY_RES: "inbox.setDepositPolicy.res",

  // --- channel operations (5, stub) ---
  CHANNEL_OPEN: "channel.open",
  CHANNEL_OPEN_RES: "channel.open.res",
  CHANNEL_CLOSE: "channel.close",
  CHANNEL_CLOSE_RES: "channel.close.res",
  CHANNEL_SIGNAL: "channel.signal",

  // --- node operations ---
  NODE_STATUS: "node.status",
  NODE_STATUS_RES: "node.status.res",

  // --- durable signed-record store (publish/fetch over the DHT overlay) ---
  RECORD_PUT: "record.put",
  RECORD_PUT_RES: "record.put.res",
  RECORD_GET: "record.get",
  RECORD_GET_RES: "record.get.res",

  // --- handle operations (6) ---
  HANDLE_REGISTER: "handle.register",
  HANDLE_REGISTER_RES: "handle.register.res",
  HANDLE_RESOLVE: "handle.resolve",
  HANDLE_RESOLVE_RES: "handle.resolve.res",
  HANDLE_RELEASE: "handle.release",
  HANDLE_RELEASE_RES: "handle.release.res",
});
