# ADR: Cryptographic Relay Identity

**Status:** Accepted (spec default, per ATLAS_PREREQUISITES.md P0.2)  
**Date:** 2026-08-15  
**Deciders:** Protocol maintainer (default adopted; no alternative recorded)  
**Implements:** Gate R1 of `../ATLAS_PREREQUISITES.md`

## Context

`relayKeyId` is today a freely chosen operator string, defaulting to
`node-<deviceId>` (two default sites: `rez-node/src/app/startRezNode.js` and
`rez-node/src/relay/NodeRelayBootstrap.js`). `DhtNodeId` is SHA-256 over the
UTF-8 string, so DHT position is grindable at zero key-generation cost. Peer
authentication signs over the presented `relayKeyId` but never checks that the
ID is entitled to the key: rebinding a *known* ID is blocked (TOFU pin on
`nodeKeyId`; operator public-key pins are config-only), but first-sight capture
of an unknown ID is free.

## Decision

1. **`relayKeyId` is self-certifying**:

   ```
   relayKeyId = "rez:relay:" + sha256hex(spkiDerBytes)
   ```

   where `spkiDerBytes` are the decoded bytes of `nodePublicKeyB64` (the
   node's Ed25519 public key in SPKI DER, exactly the bytes peer auth and
   descriptors already carry). Lowercase hex, full 64 hex chars.

2. **`nodeKeyId` remains** `nodekey:<first-32-hex>` of the same SHA-256 digest
   (compatibility with the existing format, which already hashes SPKI DER).
   Every verifier re-derives it from the key; a configured key ID that does
   not match the key is invalid.

3. **`DhtNodeId` remains SHA-256 over the UTF-8 canonical `relayKeyId`.** The
   extra hash is deliberate domain separation between the identity fingerprint
   and a DHT position.

4. **Invariant — shared DHT keyspace:** `DhtNodeId.fromRelayKeyId()` is also
   the inbox-ID hasher (`DhtRouteAnnouncer`, `DhtRouteResolver`). Relay IDs and
   inbox IDs share one keyspace through one function. This change alters relay
   DHT positions (their input string changes) but MUST NOT alter inbox-ID
   hashing semantics: the function keeps hashing whatever string it is given,
   and the inbox path keeps passing raw inbox IDs. A test pins the inbox bytes.

5. **Human-readable relay names are metadata only.** They never affect
   identity, authentication, or DHT position.

6. **Migration: one-time development-network identity reset.** Rez is
   pre-launch; deployed dev relays (r1/r2/r3) are redeployed with derived
   identities. No permanent legacy-alias protocol is built. If deployed
   identity continuity ever becomes a hard requirement, STOP and write the
   separate dual-identity migration ADR (dual advertisement, signature
   binding, expiration, downgrade handling, sunset date) — do not improvise
   aliases in code.

7. **Enforcement points** (all fail closed with `RELAY_IDENTITY_MISMATCH`-class
   reasons, never echoing key material): peer hello/challenge/identify/accept,
   descriptor admission, DHT node-reference admission, route registration,
   hosted-inbox registration, and node-identity load (a configured
   `relay.relayKeyId` must equal the derived ID or be rejected — it is never an
   override).

## Inventory of persisted/signed `relayKeyId` uses

Verified by code audit 2026-08-15 (~470 references, ~70 source files):

| Category | Where |
|---|---|
| Config | `NodeConfigValidator` (`config.node.relay.relayKeyId`), `rez-chat/src/server/config/defaultRezConfig.js` (hardcoded `ws:relay1..3` + `nodekey:` pins — invalidated by this ADR; updated in P1.4) |
| Relay descriptors | `RelayDescriptorV1` (signed field) |
| Peer auth | `PeerAuthShared` payloads (auth/challenge/accept, signed) |
| Relay store pins | `RelayStore` rebind guard + config pins |
| DHT | `DhtNodeId`, `KBucketTable`, `DhtLookup` |
| Route registrations | `RouteTable`, DHT route records (`validateStoredRouteEntry` binds `deliveryRelayKeyId`) |
| Hosted inbox | `HostedInboxRegistry`, `PgHostedInboxRegistry` |
| Handle proofs | `handleOwnershipProof` (canonical-signed) |
| Receipts | `ReceiptSigner`, `verifySettlementReceipt`, settlement receipt records |
| Settlement/storage | `StorageVerificationExchange`, escrow/debit/credit/release/slash receipts |
| Rate limiting | `peerRateLimitKeys` (self-chosen ID = self-chosen bucket; fixed by derivation) |
| Reputation/attestation | `ReputationScorer`, `PeerAttestationService` |
| Session records | `SessionCapabilities` (`relay.id \|\| relay.relayKeyId` alias — collapsed in P1.3) |
| SDK | `AuthStateMachine` (challenge requires it), `InboxClaimStore.createNodeDelegation` (signs it) |
| Gateway/onion | `GatewayRelaySelector`, `GatewayPathPlanner`, `buildOnionPacketV2`, `buildReturnOnion`, `GatewayLoop` |
| Test fixtures | rez-node/rez-chat e2e fixtures with literal relay IDs (updated in P1.4) |

## Consequences

- Grinding a target-adjacent DHT position now costs Ed25519 keypair generation
  per attempt, and the position is bound to the authenticated key at every
  admission point.
- All existing configured relay IDs (including `ws:relay1..3`) become invalid;
  dev network resets once.
- `rez-core` owns derivation (`src/identity/relayIdentity.js`, dependency-free,
  usable from browser and Node); `rez-node` owns enforcement, persistence, and
  the migration.
