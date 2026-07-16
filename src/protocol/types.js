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
  MAILBOX_CURSOR_ACK: "mailbox.cursorAck",
  MAILBOX_CURSOR_ACK_RES: "mailbox.cursorAck.res",
  EVT_MAILBOX_DEPOSITED: "evt.mailbox.deposited",
  EVT_OUTBOUND_STATUS: "evt.outbound.status",

  // --- inbox claim (open registration; see docs/CAPABILITY_MODEL.md §6) ---
  INBOX_CLAIM: "inbox.claim",
  INBOX_CLAIM_RES: "inbox.claim.res",

  // --- inbox deposit policy (claimant-signed; see docs/SECURITY_AUDIT.md HIGH-1) ---
  INBOX_SET_DEPOSIT_POLICY: "inbox.setDepositPolicy",
  INBOX_SET_DEPOSIT_POLICY_RES: "inbox.setDepositPolicy.res",

  // --- per-device home binding (S2.5 Slice 4) ---
  // device.bind: present a proven device key (DeviceRegistrationV1 +
  //   DeviceInboxBindingV1) so the durable home binds a device cursor to the
  //   SIGNED self-cert deviceId. Revocation is NOT a separate directive — it is the
  //   serialized account.deviceMutation (device.revoke) path below, which fail-closes
  //   the home for that device atomically with the registry + authority epoch.
  DEVICE_BIND: "device.bind",
  DEVICE_BIND_RES: "device.bind.res",

  // --- serialized account device mutations + authority state (S2.5 S11) ---
  // account.deviceMutation.submit: a device submits a signed AccountDeviceMutationV1
  //   (add/revoke a sibling); the home serializes it under a per-account lock and
  //   returns {revision, devices, authorityState}. account.authorityState.get:
  //   the home serves the canonical {epoch, revokedCertIds, minValidIssuedAtMs}
  //   feeding every verifier's revocationState with bounded staleness.
  ACCOUNT_DEVICE_MUTATION_SUBMIT: "account.deviceMutation.submit",
  ACCOUNT_DEVICE_MUTATION_SUBMIT_RES: "account.deviceMutation.submit.res",
  ACCOUNT_AUTHORITY_STATE_GET: "account.authorityState.get",
  ACCOUNT_AUTHORITY_STATE_GET_RES: "account.authorityState.get.res",

  // --- multi-device fan-out: home-aggregated device set (S2.5 S12) ---
  // account.deviceBundle.publish: a device self-publishes its DevicePrekeyBundleV1
  //   (self-contained: deviceId + pubkey + inbox + prekeys, device-signed) to its
  //   account HOME. account.deviceSet.get: the home returns ALL active devices'
  //   bundles for the authenticated account so a publishing device can assemble the
  //   MULTI-device DeviceSetRecordV1 (sibling pubkeys/inboxes/prekeys) sealed per peer.
  ACCOUNT_DEVICE_BUNDLE_PUBLISH: "account.deviceBundle.publish",
  ACCOUNT_DEVICE_BUNDLE_PUBLISH_RES: "account.deviceBundle.publish.res",
  ACCOUNT_DEVICE_SET_GET: "account.deviceSet.get",
  ACCOUNT_DEVICE_SET_GET_RES: "account.deviceSet.get.res",

  // --- authority-state propagation outbox: the head-advancing account lease (P1#3) ---
  // The home owns a durable queue of "publish the current AccountAuthorityStateV1"
  // obligations (enqueued atomically with each device add/revoke fold). Because the
  // home cannot SIGN that record, a device drains it: claim the account's publishable
  // head under a server lease, prepare (freeze) the epoch to publish, then either report
  // failure or (leaf 3c) submit the signed record for a VERIFIED ack. Authority is the
  // AUTHENTICATED session's own account (never the body); the lease owner is the session
  // DEVICE; a delegated device needs the deviceSet.publish capability. The lease token is
  // server-minted and must never appear in logs. These four ops are crypto-FREE (the
  // signature-verifying completion/ack is the separate leaf-3c op).
  ACCOUNT_OUTBOX_LEASE_CLAIM: "account.outbox.lease.claim",
  ACCOUNT_OUTBOX_LEASE_CLAIM_RES: "account.outbox.lease.claim.res",
  ACCOUNT_OUTBOX_LEASE_PREPARE: "account.outbox.lease.prepare",
  ACCOUNT_OUTBOX_LEASE_PREPARE_RES: "account.outbox.lease.prepare.res",
  ACCOUNT_OUTBOX_LEASE_RELEASE: "account.outbox.lease.release",
  ACCOUNT_OUTBOX_LEASE_RELEASE_RES: "account.outbox.lease.release.res",
  ACCOUNT_OUTBOX_LEASE_FAIL: "account.outbox.lease.fail",
  ACCOUNT_OUTBOX_LEASE_FAIL_RES: "account.outbox.lease.fail.res",

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
