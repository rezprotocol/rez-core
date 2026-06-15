# Protocol Reference

This document describes the active Rez client-node protocol surface. Generated WebSocket record coverage lives in [WS_CONTRACTS.md](./WS_CONTRACTS.md).

For cryptographic goals and limitations, see [security.md](./security.md) and the [white paper](./WHITEPAPER.html).

## Active Ownership

- `rez-core` owns shared protocol constants, encoding helpers, crypto primitives, and records that must be usable across packages (including the settlement/paid-service wire records: `PaidServiceSpecV1`, `SettlementEntryV1`, `ServiceAckV1`, and the signed receipt family).
- `rez-node/src/contracts` owns server-side WebSocket request/result/event records and the contract registry.
- `rez-sdk` owns the app-facing client facade and capability APIs (including `WalletCapability` and `HandlesCapability`).
- `rez-chat` owns chat bridge records and app semantics.
- `rez-contracts` owns the on-chain Solidity contract suite — the canonical REZ ERC-20 token and machinery (published as `@rezprotocol/contracts`). It is consumed by `rez-node`'s chain-mode settlement layer via the generated ABI export; it defines no WebSocket protocol surface.

## SDK Lexicon

- **Peer Link** is the app-facing term for an encrypted relationship between accounts/devices.
- **Inbox** is the app-facing term for store-and-forward delivery targets.
- **Envelope** is a protocol/internal wrapper hidden by normal SDK APIs.
- **Mailbox** is the wire/protocol family name for inbox operations.
- **Channel** is reserved for `channel.*` protocol contracts.

## Client to Node Transport

Clients connect to a node over WebSocket JSON frames. SDK clients should prefer `new RezClient({ identity, uplinks })` from `@rezprotocol/sdk/client`, then explicitly call `start()` and `connect()`. Application code should not hand-roll WebSocket protocol handling.

Frames use a typed envelope with a correlation id, message type, version, and record body:

```json
{
  "id": "req-123",
  "t": "node.status",
  "v": 1,
  "body": {}
}
```

Errors use the `error` frame type and carry a structured code/message/detail body.

## Core WebSocket Families

The current generated contract set includes:

| Family | Purpose |
|---|---|
| `session.*` | Session hello, challenge, authenticate, and ready handshake |
| `mailbox.*` | Store-and-forward mailbox deposit/read/list operations |
| `object.*` | Object put/get addressing for public or capability-bound payloads |
| `channel.*` | Channel subscribe/append/read operations |
| `capability.*` | Capability issue/revoke/list operations |
| `node.*` | Node status and identity metadata |
| `peer.link.*` | Peer link invite, accept, and status flow |
| `handle.*` | Handle claim/lookup/renew operations (`handle.renew` is a paid service) |
| `settlement.*` | Wallet balance and signed-receipt queries (`settlement.balance`, `settlement.receipts`) — own-account only |
| `pricing.list` / `catalog.list` | Paid-service price preview and `PaidServiceSpecV1` catalog discovery (free) |
| `storage.persist` | Paid persistent-storage commitment (later tier) |
| `delivery.ack` | Delivery acknowledgement |

Paid families (`handle.register`/`handle.renew`, `storage.persist`, and future
service ids) are gated through `ServiceGate` on the node, which runs
capability → pricing → atomic `settleService` and returns `PAYMENT_REQUIRED`
when the payer is underfunded. See the [token economy whitepaper](../../rez-token-whitepaper.html)
for the full economic model.

Run `npm run docs:contracts` to verify the generated registry doc is current.

## SDK Lifecycle

SDK constructors are synchronous and inert. `start()` initializes local async SDK resources, `connect()` begins node/uplink interaction, `disconnect()` stops network interaction, and `stop()` tears down started local resources. Lifecycle events are `start`, `ready`, `connect`, `disconnect`, `stop`, and `error`.

## App Bridge

`rez-chat` has its own browser-to-server bridge for product semantics such as threads, contacts, invites, groups, files, profile, and node status. Those bridge records live under `rez-chat/src/records` and are app-level contracts, not substrate protocol contracts.

## Relay Mesh

Node-to-node relay mesh behavior is owned by `rez-node`. It covers peer authentication, route announcements, packet forwarding, and store-and-forward delivery. App/UI code must treat this as node/runtime infrastructure behind SDK APIs.
