# ADR: Protocol Network Domain

**Status:** Accepted (spec default, per ATLAS_PREREQUISITES.md P0.3)  
**Date:** 2026-08-15  
**Deciders:** Protocol maintainer (default adopted; no alternative recorded)  
**Implements:** the "Protocol network domain" required decision of
`../ATLAS_PREREQUISITES.md`

## Context

Future signed public facts (Atlas observations, and any other cross-node
assertion) must not be replayable between unrelated Rez networks — a fork, a
private deployment, or a test mesh — and mistaken for statements about the
local network. Rez today has exactly one network-scoping identifier: the
settlement `networkId` carried by settlement receipts (e.g.
`DebitReceiptV1.networkId`, a free non-empty string that "binds the receipt to
ONE settlement network"). Nothing scopes the protocol itself: peer handshakes,
descriptors, and durable records carry no network domain.

## Decision

1. **Rez defines a protocol-level network domain identifier, distinct from the
   settlement `networkId`.**

   - Canonical field name: `protocolNetworkId`.
   - Canonical representation: a non-empty ASCII string of the form
     `rez:net:<label>`, where `<label>` is 1–64 chars of `[a-z0-9-]`.
     Canonical bytes are the UTF-8 encoding of the exact string; it is signed
     as a string field, never re-encoded.

2. **Well-known values:**

   | Network | Value |
   |---|---|
   | Mainnet (future) | `rez:net:main` |
   | Public testnet | `rez:net:test` |
   | Local development | `rez:net:dev` |
   | Private forks | `rez:net:<operator-chosen-label>` (self-assigned; collision between consenting forks is their own concern) |

   The implicit default for all current code is `rez:net:dev`. Nothing may
   infer a domain from the settlement `networkId`.

3. **Binding (deferred to first consumer, decided now):** when a record kind
   or handshake needs domain scoping, it binds `protocolNetworkId` inside its
   signed bytes. Peer authentication and relay descriptors do NOT bind it yet —
   adding it there is a wire-breaking change that lands with the first record
   family that needs cross-domain rejection (expected: the first Atlas public
   observation record). This ADR fixes the name, encoding, and values so that
   record design cannot fork the concept.

4. **Rejection behavior (when bound):** a signed record or handshake carrying
   a `protocolNetworkId` different from the local node's configured value is
   rejected with reason class `network-domain-mismatch`. Absence of the field
   in record kinds that require it is a validation failure, not a wildcard.

5. **Relationship to the settlement `networkId`:** explicitly separate
   concepts. When economics are enabled on a network, the settlement
   configuration must declare which `protocolNetworkId` it settles for, making
   the relationship explicit configuration rather than implication. Settlement
   records keep their existing field untouched.

6. **Configuration:** `protocolNetworkId` will be a node-level config value
   (`config.node.protocolNetworkId`, default `rez:net:dev`) added when the
   first consumer lands. Private forks choose their own label at deployment.

## Consequences

- No production code changes now — this is a recorded design decision only
  (P0.3 is a design prerequisite; adding records or config before a consumer
  exists would violate the scope-control test).
- Atlas record design can begin (post-readiness) with a fixed, non-forkable
  domain concept.
- The settlement identifier is never silently reused as a protocol domain.
