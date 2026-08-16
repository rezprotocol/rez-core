# Receipts and Delivery States

**Rewritten 2026-08-15 under DT-005** (delivery-transports plan, Phase 0).
The previous version of this document specified relay-emitted
`rez.receipt.v1` attestations. That implementation was **dead code** — no
call site ever invoked the send path, the schema had drifted from the spec,
and unsigned receipts were emittable while the verifier required signatures.
It has been **retired**: the builder/sender methods, the bridge surface, and
`verifyReceiptV1` are deleted. Re-introducing relay attestations is a future
*route-attestation* project proposal, not a latent feature of this codebase.

This document now describes only what exists. Delivery evidence in Rez is a
**three-way split**; the three kinds are different facts with different
trust roots and must never be conflated:

## 1. Transport custody facts (node-reported, unauthenticated end-to-end)

What the local node knows about an outbound deposit's custody:

- `mailbox.deposit` success: the deposit was accepted (synchronously routed,
  or persisted into `PersistentOutboundQueue` with `queued: true`).
- `evt.outbound.status` frames (`queued` / `delivered` / `expired`):
  best-effort, **live-session-only** notifications from the node's outbound
  queue. Known limitations (pinned by DT-002 characterization tests, to be
  addressed in the delivery-transports Phase 1 queue repair):
  - `delivered` means the **entry relay accepted the packet on the socket**
    — it is NOT an inbox-deposit fact.
  - Cap evictions (per-inbox / global oldest-drop) emit **no** event.
  - Frames are not persisted or replayed; a disconnected client misses them.

Custody facts say a carrier holds bytes. They say nothing about the
recipient.

## 2. Authenticated end-to-end delivery acks (`E2eeDeliveryAckV1`)

The only recipient-proving evidence: after decrypting a chat message, the
recipient's chat layer seals an `E2eeDeliveryAckV1 { senderAccountId,
messageIds }` back to the sender over the peer link. Properties:

- Authenticated by the E2EE decrypt itself — the sender trusts the
  *decrypted* peer identity, never the plaintext-claimed one.
- Keyed by the sender's local `messageId` (not any relay event id).
- Sent for 1:1 messages AND (since DT-004) group fan-out copies. Group acks
  feed the sender-side recovery evidence
  (`ServerPeerLinkProtocolService.recordOutboundGroupMessage`) but do NOT
  flip a group row's status — "delivered" on a group message would be the
  first-of-N ambiguity the status model deliberately avoids.
- Delivery of the ack itself is best-effort today (fire-and-forget send;
  receive-side effect not yet durable across a crash — tracked as DT-008,
  resolved by the delivery-transports atomic-commit work).

## 3. Application state (chat-level)

`pending → sent → queued → delivered → failed` on the sender's message row
(`ChatThreadStore`), driven by (1) for `sent`/`queued`/`failed` and by (2)
for `delivered` (1:1 only). Application state is a *projection* of the two
evidence kinds above, never a source of truth about the network.

## What does NOT exist

- **No relay receipts.** Nothing emits or verifies `rez.receipt.v1`.
- **No read receipts.** Nothing in the protocol reports user read state.
- `receiptInboxId` still travels through the send-path plumbing
  (`RezClient` → gateway → `OutboundQueueEntryV1`) as a wire-compatible
  field, but **nothing consumes it**; the relay drop point is
  `MailboxHandler.handleDeposit`, which reads only `mailboxId` +
  `ciphertextB64`. Treat the field as reserved; do not build on it.

## Future work pointer

The delivery-transports plan (`plans/DELIVERY_TRANSPORTS_PLAN_V6.md`,
frozen) defines the receipt model going forward: per-carrier custody facts
reported by `RDeliveryTransport` adapters, authenticated end-to-end receipts
by sealed-payload digest, and application state — the same three-way split,
formalized. Route attestation (cryptographic relay receipts) would be a new
proposal on top, not a revival of the deleted code.
