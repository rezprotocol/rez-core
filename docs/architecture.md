# Architecture

Rez is a JavaScript monorepo with strict package boundaries. The active workspace packages are:

| Package | Owner |
|---|---|
| `rez-core` | Protocol primitives, records, crypto, codecs, storage abstractions |
| `rez-node` | Relay/node runtime, WebSocket gateway, TCP mesh, server-side protocol records |
| `rez-sdk` | Client facade, auth/session helpers, uplink pool, browser/server SDK adapters |
| `rez-chat` | Application runtime, chat workflows, account UI, embedded node host |
| `rez-ui` | UI framework primitives and assets only |

`rez-contracts` is not an active package. Shared wire vocabulary now lives in `rez-core`; server-side contract records and the registry live in `rez-node/src/contracts`.

## Boundaries

- `rez-ui` must not import SDK, node, core, chat, or protocol internals.
- `rez-chat` must use `rez-sdk`, not `rez-core`, directly.
- `rez-sdk` may use `rez-core` primitives and must not depend on `rez-chat`.
- `rez-node` owns relay/gateway/runtime behavior and may use `rez-core`.
- `rez-core` owns reusable records and primitives, with no application workflow ownership.

## SDK Lifecycle and Lexicon

SDK-facing constructors are synchronous and inert. App developers should be able to create SDK objects, attach listeners, prepare app state, then call `start()` for local async setup and `connect()` for node/uplink interaction.

Canonical SDK lifecycle events are `start`, `ready`, `connect`, `disconnect`, `stop`, and `error`.

Canonical app-facing terms are:

- Peer Link: encrypted relationship between accounts/devices.
- Inbox: app-facing store-and-forward delivery target.
- Envelope: internal protocol wrapper hidden by default SDK APIs.
- Mailbox: wire/protocol family name for inbox operations.
- Channel: reserved for `channel.*` protocol contracts.

## Runtime Shape

The default product path is `rez-chat` embedding `rez-node` in process. Browser/UI code talks to the chat bridge. The chat server uses `rez-sdk` and the embedded node runtime to connect, route, encrypt, persist, and receive events.

Relay mesh responsibilities remain in `rez-node`: peer auth, descriptor exchange, DHT/gossip route discovery, onion routing, hosted inbox registration, and gateway delivery.

Application state responsibilities remain in `rez-chat`: account flow, session UI, thread/message presentation, contacts, groups, files, profile exchange, and user-facing workflows.

## Authorization Model

Capabilities are signed by inbox claimants; the node is a verifier, never a signer. See [`CAPABILITY_MODEL.md`](./CAPABILITY_MODEL.md) for the canonical spec. Session-bound operations on inboxes the SDK claimed itself authorize implicitly via the session binding; delegated access carries an explicit cap chain.

The node maintains a single `inboxId → claimantPublicKeyB64` registry as the trust root for every authorization decision. The node never knows account IDs; account-level identity is an SDK-side concept.

## Current Expansion Areas

- Public object posting was scaffolded as the `object:` namespace, then removed in the 2026-05 capability rework (no consumers, wrong cap shape). Rebuild deferred until first product surface needs it; architecture captured in memory.
- Handle registration exists in relay/node scaffolding, but needs a verified SDK/UI flow and gossip signature validation before it is treated as production-ready.
- Reznet is already broader than chat at the substrate level: relay mesh, route discovery, hosted inboxes, profile/file payloads, groups, delivery acks, and storage verification are present.
