# ADR: Delivery Transport Layers and Carrier Naming

**Status:** Accepted (Phase 0 deliverable DT-001 of the frozen delivery-transports plan)
**Date:** 2026-08-15
**Deciders:** Protocol maintainer (plan v6 frozen and approved 2026-08-15)
**Implements:** DT-001 of `plans/DELIVERY_TRANSPORTS_PLAN_V6.md` (§1, layer
taxonomy); mechanism per the accepted
`plans/DT-006_ATOMIC_COMMIT_FEASIBILITY.md` (rev 4 + Freeze Addendum)

## Context

Rez is adding pluggable delivery carriers (first target: an SMTP/IMAP email
bridge in the ProtonMail-bridge style) as *supplemental delivery for
already-known, verified Rez identities*. RezNet/DHT remains the discovery,
device-authority, and revocation control plane.

The word "transport" already means three different things in this codebase,
and conflating them is how facade anti-patterns start (see the 2026-05-17
DesktopSupervisor event-array war story in `CLAUDE.md`). The outbound seam
for carriers is real and singular: local E2EE sealing, then
`mesh.dispatch()` handing opaque bytes onward —
`MeshCapability.js:71` is the sole non-test caller of
`MailboxCapability.deposit`. Delivery *planning* (targets, policy, frozen
requirements/fallback set) happens **before** sealing because the
authenticated inner delivery envelope must be built before ratchet
encryption; the transport boundary itself remains post-seal, and crypto
never learns the carrier.

## Decision

### 1. Three transport layers exist and stay distinct

| Layer | Home | What it abstracts | Disposition |
|---|---|---|---|
| SDK connection transport | `rez-sdk/src/transport/Transport.js` (WS/TCP) | client-to-node framed request/response | keep unchanged; a carrier is not a node session |
| Hop/network transport | `rez-core/src/network/RTransport.js` | hop-level `WirePacket` byte send/receive | keep low-level; no delivery policy or identity binding |
| **Delivery carrier** | `RDeliveryTransport` (new, `rez-sdk`) | asynchronous recipient delivery, custody, security profile, settlement | the delivery-transports project |

The delivery-carrier layer sits **after E2EE sealing and before
`MailboxCapability.deposit()`**, with a RezNet adapter delegating to the
existing mailbox/node path.

Kept in place, explicitly not generalized into carriers: `UplinkPool`
(inside the RezNet adapter only), `RouteResolver`/`GossipRouteResolver`
(a strategy inside RezNet), `GatewayLoop` (wrapped, never generalized into a
foreign-carrier switch), `MeshCapability` (public compatibility preserved),
and chat's bus bridge (app RPC, not a carrier interface).

### 2. Naming rule (corrected per Phase 0 audit — this section governs)

- **Abstract interface:** `RDeliveryTransport` (rez-sdk).
- **Implementations:** `<Carrier>DeliveryTransport` — per the frozen plan:
  `RezNetDeliveryTransport`, `FakeDeliveryTransport`, and future carriers
  (`SmtpDeliveryTransport`, …). The word **`Delivery` is mandatory** in
  every carrier implementation class and file name.
- **Prohibited in carrier code:** the bare name `Transport`, and any
  carrier class or file ending in `Transport` that omits `Delivery`
  (`SmtpTransport`, `EmailTransport`, …) — those names collide with the two
  pre-existing non-carrier layers and are review-blocking.
- **The rule keys on what a class EXTENDS, not on what it is called.** Every
  `class X extends RDeliveryTransport` must have `X` — and its containing
  file — end in `DeliveryTransport`. Dodging the suffix does not dodge the
  rule: `class SmtpCarrier extends RDeliveryTransport {}` is prohibited
  exactly like `SmtpTransport`.
- The two pre-existing layers keep their names unchanged
  (`rez-sdk/src/transport/Transport.js`, `rez-core/src/network/RTransport.js`);
  the prohibition applies to NEW carrier-layer code only.
- Record names follow the frozen plan's table verbatim
  (`TransportAssessmentRequestV1` / `TransportSubmissionV1` /
  `TransportCustodyQueryV1` / `TransportSettlementV1`); carrier adapters see
  only those transport-facing records — never the router's operation ID,
  other targets, or fallback policy.

### 3. Enforcement

Naming and boundary rules are enforced by the DT-003 architecture-test
suite (no separate linter). The boundary invariants those tests pin — no
carrier identifiers in crypto/session modules, no carrier adapters in
`rez-chat`, no foreign credentials in `rez-node`, no global
email-address/DHT index — are consequences of this ADR's layer split.

## Consequences

- "Add a carrier" never touches rez-core crypto, the node's protocol
  surface, or chat's app logic: it is a new `RDeliveryTransport`
  implementation plus policy/records in `rez-sdk`.
- The RezNet path becomes the first adapter behind the same interface,
  so foreign carriers can never have a privileged code path that RezNet
  lacks (or vice versa).
- Glossary impact: in prose and code review, say "bus transport",
  "hop transport", or "delivery carrier" — the unqualified word
  "transport" is ambiguous in this codebase and should be treated as a
  question, not an answer.
