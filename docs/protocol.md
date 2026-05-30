# Protocol Reference

This document describes the active Rez client-node protocol surface. Generated WebSocket record coverage lives in [WS_CONTRACTS.md](./WS_CONTRACTS.md).

For cryptographic goals and limitations, see [security.md](./security.md) and the [white paper](./WHITEPAPER.html).

## Active Ownership

- `rez-core` owns shared protocol constants, encoding helpers, crypto primitives, and records that must be usable across packages.
- `rez-node/src/contracts` owns server-side WebSocket request/result/event records and the contract registry.
- `rez-sdk` owns the app-facing client facade and capability APIs.
- `rez-chat` owns chat bridge records and app semantics.

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
| `handle.*` | Handle claim/lookup operations |
| `delivery.ack` | Delivery acknowledgement |

Run `npm run docs:contracts` to verify the generated registry doc is current.

## SDK Lifecycle

SDK constructors are synchronous and inert. `start()` initializes local async SDK resources, `connect()` begins node/uplink interaction, `disconnect()` stops network interaction, and `stop()` tears down started local resources. Lifecycle events are `start`, `ready`, `connect`, `disconnect`, `stop`, and `error`.

## App Bridge

`rez-chat` has its own browser-to-server bridge for product semantics such as threads, contacts, invites, groups, files, profile, and node status. Those bridge records live under `rez-chat/src/records` and are app-level contracts, not substrate protocol contracts.

## Relay Mesh

Node-to-node relay mesh behavior is owned by `rez-node`. It covers peer authentication, route announcements, packet forwarding, and store-and-forward delivery. App/UI code must treat this as node/runtime infrastructure behind SDK APIs.
