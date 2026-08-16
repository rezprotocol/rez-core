# REZ Glossary

Definitions of REZ-specific terms used in rez-core and related documentation. Shared base types and logging are owned by `@rezprotocol/base`; core and SDK are use-case neutral; app-level semantics (chat, social, etc.) live in apps.

---

## Protocol & project

**Rez** — The protocol and system for secure, object-oriented overlay routing and delivery. Use-case neutral; supports encrypted envelopes, onion routing, and pairwise sessions.

**REZ_UNDELIVERABLE** — Transport-level error code indicating a packet could not be delivered (e.g. destination unknown or unreachable).

**RezInvariantError** — Error thrown when an invariant assertion fails (e.g. in `RObject.assert`).

**RezAbstractError** — Error thrown when an abstract method is called without being implemented (e.g. in `RAbstract`).

---

## Base types (R-prefix)

**RObject** — Base class for all REZ objects. Provides `type`, `assert()`, and `dispose()`.

**RAbstract** — Abstract base extending `RObject`; subclasses must implement methods that call `abstract(methodName)`.

**RSerializable** — Abstract base for objects that can be serialized via `toJSON()`, `fromJSON(json)`, and optionally `toCanonical()`.

**RService** — Abstract base for runtime services (e.g. RezRuntime, dispatchers). Has `start()`, `stop()`, and an optional `RLogger`.

**RCodec** — Abstract base for encode/decode steps. Implementations participate in a `CodecChain` to transform envelopes to/from bytes.

---

## Object model

**Envelope** — The outer container for a REZ object. Holds a `Header`, a body payload, and optional `meta`. All on-wire and stored objects are envelopes.

**Header** — Protocol-level fields on every envelope: `id`, `type`, `createdAt`, and `links`. Identity, type, and timestamps are stable across layers.

**Body** — Base type for the payload inside an envelope. Application-defined structure; bodies are versioned and structured (convention enforced by the `Body` base class).

**Link** — A protocol-level graph edge between objects. Stored in the header as `{ rel, target, meta }`. Used for threading, replies, and references.

**Payload** — The bytes or structured body inside an envelope (generic term).

---

## Transport & network

**WirePacket** — The unit of data moved across a transport: `bytes` (encoded envelope), `to`, optional `from`, `meta`, and optional `id`. Transport is bytes-only; no protocol parsing in network layer.

**Packet** — Synonym for wire-level unit of data (often used with `WirePacket`).

**RTransport** — Abstract transport interface: `send(packet)`, `onPacket(handler)`, `start()`, `stop()`. Implementations: TCP, HTTP, Memory.

**EndpointId** — Transport-level identifier for a destination (e.g. peer or relay address).

**DestinationId** — Generic logical destination (e.g. mailbox or principal).

**x-rez-*** — HTTP headers used by the HTTP transport: `x-rez-to`, `x-rez-from`, `x-rez-meta`, `x-rez-id`.

---

## Storage

**StorageProvider** — Abstract provider that supplies `ObjectStore`, `MailboxStore`, and `KeyValueStore`. Implementations: memory, filesystem.

**ObjectStore** — Store for envelopes keyed by `envelope.header.id`. Operations: `put(envelope)`, `get(id)`, `has(id)`, `delete(id)`, `listIds()`.

**MailboxStore** — Store for delivery buckets: append and list envelope IDs by mailbox. Operations: `append(mailboxId, envelopeId)`, `list(mailboxId)`, `deleteMailbox(mailboxId)`.

**KeyValueStore** — Generic key-value store: `set`, `get`, `delete`, `keys(prefix)`.

**MailboxId** — Identifier for an addressable delivery bucket (inbox-like). Use-case neutral; not tied to “inbox” UX.

---

## Runtime & services

**RezRuntime** — Central runtime service. Owns a `CodecChain` and `StorageProvider`; provides `encodeEnvelope`, `decodeEnvelope`, `saveEnvelope`, `loadEnvelope`, `depositToMailbox`, `listMailbox`, and `receivePacket`.

**CodecChain** — Ordered sequence of `RCodec` instances. Encode: envelope → ctx → … → ctx.bytes. Decode: ctx.bytes → … → ctx.envelope. Order matters (e.g. canonicalize → JSON → encrypt → onion).

**Dispatcher** — Service that subscribes to a transport and reacts to incoming packets. **ForwardingDispatcher** uses a routing table and policy to LOCAL / FORWARD / DROP. **InboxDispatcher** passes packets to `RezRuntime.receivePacket`.

**Gateway** — Local ingress/egress node; connects the node to the network. **RGatewayRole** defines the contract: `getGatewayId()`, `getTransport()`, `getRuntime()`, `start()`, `stop()`.

**Relay** — Node that forwards packets for others. Learns only previous and next hop when used with onion routing. **RRelayRole** defines the contract: `getRelayId()`, `getTransport()`, `getRuntime()`, `start()`, `stop()`. Anyone may run a relay and carry traffic freely (core messaging is free, permissionless); *earning REZ* additionally requires trust-graph recognition (see **Token economy & settlement**).

**RoutingTable** — Resolves a destination to the next hop. **RRoutingTable** abstract: `resolveNextHop(to)`.

**RoutingPolicy** — Decides what to do with a packet given a routing resolution: **RRoutingPolicy** `decide(packet, resolution)` → disposition (e.g. LOCAL, FORWARD, DROP) and optional `nextHop` / `reason`.

**Forwarding** — Bytes-only forwarding of packets; no interpretation of envelope contents at relay.

---

## Codec & serialization

**Codec** — A single encode/decode step (extends `RCodec`). Examples: JsonCodec, CanonicalizeCodec, EncryptEnvelopeCodec, DecryptEnvelopeCodec, OnionEncodeCodec, OnionPeelCodec.

**Canonicalize** — Normalize a JSON-serializable value so that serialization is deterministic: object keys sorted, recursive. Used for signing, hashing, and consistent wire format. See `canonicalize.js` and `canonicalJSONStringify`.

**CanonicalizeCodec** — Codec that replaces `ctx.envelope` with a canonicalized copy (sorted keys, etc.) before further encoding.

**Canonical JSON** — JSON produced from a canonicalized structure (e.g. via `canonicalJSONStringify`). Required for envelope hashing and relay receipt signatures.

---

## Envelope types (core)

**rez.encrypted.v1** — Outer envelope type for encrypted payloads. Body is `EncryptedEnvelopeV1` (ratchet header, nonce, ciphertext). Inner content is any REZ envelope (opaque to relays).

**rez.onion.v1** — Outer envelope type for v1 onion routing. Body is `OnionPacketV1` (size + payload blob). Used for multi-hop relay paths.

**rez.onion.v2** — Outer envelope type for v2 onion routing. Body and layer format differ from v1; supports size classes and improved replay handling.

**rez.receipt.v1** — RETIRED (DT-005, 2026-08-15). Was the envelope type for relay attestations; the implementation was dead code and has been deleted. Delivery evidence is the three-way split in RECEIPTS_AND_DELIVERY_STATES.md (transport custody facts / E2eeDeliveryAckV1 end-to-end acks / application state). The type name is reserved and must not be reused.

---

## Crypto abstractions

**RKeyManager** — Abstract key management: export/import public and private keys (opaque bytes).

**RPublicKey** / **RPrivateKey** — Wrapper for public/private key material (e.g. algorithm id and raw bytes).

**RDh** — Abstract Diffie–Hellman interface: `generateKeyPair()`, `deriveSecret(privateKeyBytes, publicKeyBytes)`, `getAlgId()` (e.g. X25519).

**RSigner** — Abstract signing interface (e.g. Ed25519). Used for relay receipts and identity.

**RCryptoProvider** — Abstraction for crypto primitives (e.g. WebCrypto-based provider).

---

## Sessions & encryption

**X3DH** — Key agreement protocol used to establish a shared secret with a peer (e.g. using prekeys). **X3DHService** and **X3DHPreKeyBundle** / **X3DHInitiatorHandshake** are REZ-side types.

**PreKeyBundle** — X3DH bundle containing public keys and prekeys for handshake.

**Handshake** — Key agreement handshake (e.g. X3DH) to bootstrap a session.

**SecureChannel** / **Session** — Pairwise secure channel. Session state is managed by **RSessionManager** (create initiator/responder session, get send/recv context, rotate DH).

**RatchetState** — Double ratchet state: root key, sending chain, receiving chain, DH key pair, remote DH public key, and optional skipped-key store.

**RatchetHeader** / **SessionHeader** — Header sent with each encrypted message (e.g. **RatchetHeaderV1**): session id, DH public key, chain lengths (pn, n), etc. Use-case neutral.

**RatchetChainState** / **RatchetKeyPair** — Per-chain state and key pairs used by the double ratchet.

**SkippedKeyStore** — Store for message keys skipped when processing out-of-order messages (optional / deferred in v1).

**EncryptedEnvelopeV1** — Body of a `rez.encrypted.v1` envelope: version, suite, ratchet header, nonce, ciphertext.

**ObjectKey** / **MessageKey** — Key used to encrypt a single message/object in the ratchet (optional synonym).

**RootKey** / **ChainKey** — Double ratchet root and chain key concepts.

---

## Onion routing

**Onion routing** — Overlay routing where each relay sees only previous and next hop; payload is layered encryption. Implemented as codec + services above transport (not part of transport itself).

**Hop** — A relay that forwards a packet along the path.

**Path** — Ordered list of hops from gateway to destination relay.

**Layer** — Encrypted blob for one hop. “Peeling” a layer reveals next-hop instructions and the inner blob.

**Peel** — Decode one onion layer (reveal next hop and inner payload). **OnionPeelCodec** / **OnionPeelCodecV2** decode at a relay; encode codecs build the layered packet at sender.

**OnionPacketV1** / **OnionPacketV2** — Body of `rez.onion.v1` / `rez.onion.v2`: version, size, payload (and v2-specific fields).

**RelayDescriptor** — Metadata for a relay (e.g. **RelayDescriptorV1**): identity key, onion key, endpoint, nickname, capabilities. Used to build paths and verify receipts.

**OnionKeyRecordV1** — Record holding a relay’s onion key material for v1.

**Onion path** — Ordered list of relays used to build or peel an onion packet.

---

## Token economy & settlement

The economic layer that pays the relay mesh for paid services. Core messaging
stays free; handles, persistent storage, large media, and content hosting are
paid. Thesis: **"Postage, not equity."** Full treatment in the
[token economy whitepaper](../../rez-token-whitepaper.html).

**REZ** — The fixed-supply (1,000,000,000, minted once at genesis, never again) ERC-20 utility token on Base (Ethereum L2). Immutable: no mint, owner, pause, blacklist, fee-on-transfer, or upgrade path. No staking, no yield, no founder allocation. A consumable utility credit ("postage"), not equity.

**Service Credit** — Off-chain balance unit used during beta (settled by `LocalSettlementProvider`) in place of on-chain REZ. Carries a **credit class**.

**Credit class** — Either `convertible` (issued only by the canonical issuance authority for purchase/conversion events; counted against the 100M conversion reserve via the `CreditLiabilityLedger`; converts 1:1 to REZ at mainnet) or `promotional` (starter allowance + operator grants; spendable but never convertible). Class is conserved through every transfer/escrow/slash and affects conversion/liability only — never emissions.

**Paid service** — A metered service gated behind payment. Each is declared by one **`PaidServiceSpecV1`** (`serviceId`, unit, default price, commitment-backed?, capability scope, description).

**ServiceCatalog** — A relay's registry of the `PaidServiceSpecV1`s it offers. `descriptor.meta.services` is the gossiped, priced projection of it.

**ServiceGate** — The single enforcement point for paid services: runs capability check → pricing → atomic `settleService`, returning `PAYMENT_REQUIRED` when the payer is underfunded.

**settleService** — The atomic, multi-leg settlement primitive: one operation that debits the payer and credits the serving relay (plus an optional protocol-fee leg), all sharing one `settlementId`. Computes the credit-class split (promotional-first).

**SettlementProvider** — Abstract settlement backend. `LocalSettlementProvider` (KV-backed, off-chain credits) in beta; `ChainSettlementProvider` (deposit-anchored, testnet REZ) for chain mode.

**SettlementJournal** — Append-only journal of `SettlementEntryV1` records; the source of truth for balances, replay, audit, and conversion. **ReceiptLog** is a capped, user-facing projection of it.

**SettlementEntryV1** — The canonical settlement record everything verifies against (gross/relay/fee amounts, per-class splits, price snapshot, `networkId`, idempotency key). Signed receipts (`DebitReceiptV1`, `CreditReceiptV1`, `EscrowReceiptV1`, `ReleaseReceiptV1`, `SlashReceiptV1`) are projections of it.

**networkId** — Immutable pre-genesis constant bound into the signed body of every economic artifact (settlement receipts, peer attestations, escrow records, relay descriptors, storage proofs). Only official-`networkId` artifacts earn emissions or convert; a private fork's activity is inert ("Monopoly money").

**Recognized relay** — A relay whose activity counts toward real REZ, recorded in the `RezRelayRegistry` (config-backed in beta, on-chain later) and keyed by **`recognizedRelayKey`** (the same value as `providerRelayId` in settlement records).

**Trust graph** — The EigenTrust-style relay-reputation system (`TrustGraph`) seeded from a published, neutral, multi-operator seed-relay set; rank flows along recognized relay-consumer relationship edges, decays, and saturates. It **supersedes** the linear `ReputationScorer`, which becomes an input feature. Rank is the basis for recognition and emission weighting; it is not buyable with disk or uptime.

**Emissions** — The 500M relay-rewards pool, distributed over a 10-year halving. Earned only by being demanded/vouched-for by other recognized relays — via settlement-verified **`ServiceAckV1`**s and demand-bound storage proofs (trust-weighted, circularity-discounted), plus capped public-good storage. Never from raw message volume, raw paid receipts, self-stored bytes, or bare uptime.

**Proof-of-replication (PoRep)** — Storage proof where each replica is a unique per-relay-key encoding, so k claimed replicas require k× real bytes (defeats dedup/wormhole). Proves disk cost (eligibility), not demand.

**Escrow bond** — A per-commitment performance bond posted from a relay's *earned working balance* (transient, consumed-or-returned) — the accountability mechanism for expensive commitments. There is **no** standing stake.

**Custody vault** — A non-upgradeable contract that holds an undistributed pool and adjudicates its own release rules: `TreasuryVault` (drip + caps + timelock), `RewardsVault` and `ConversionDistributor` (finalized-root + dispute-window + proof + claimed-bitmap). Upgradeable machinery logic can decide distribution but cannot drain the pools.

**rez-contracts** — The Foundry/Solidity repo (published as `@rezprotocol/contracts`) holding the immutable `RezToken`, the upgradeable machinery, and the non-upgradeable custody vaults.

---

## Logging

**RLogger** — Logger from `@rezprotocol/base` that distributes log events to one or more **RLogTransport** instances. Levels: debug, info, warn, error.

**RLogTransport** — Abstract sink for log events (e.g. console, memory, null). Implements `handle(event)`.

---

## Naming conventions

- **R** prefix: Base types and abstractions in `@rezprotocol/base` and core contracts (e.g. RObject, RTransport, RCodec).
- **Envelope type** format: `rez.<feature>.<version>` (e.g. `rez.encrypted.v1`, `rez.onion.v1`).
- **Info/labels** in KDF: Often `rez-<feature>-v<n>` (e.g. `rez-aead-v1`, `rez-onion-v1`, `rez-ratchet-root-v1`, `rez-x3dh-v1`).
