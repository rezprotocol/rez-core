# Rez Atlas Prerequisites

## Base-network readiness plan only

**Status:** Development-team implementation specification  
**Last reviewed:** 2026-08-15 (revised after full code audit; claims below are verified against source)  
**Scope:** Generic RezNet work that must be completed or preserved so Atlas can be added later without replacing the network  
**Not in scope:** Building Atlas

## One-sentence boundary

Rez Atlas is an optional intelligence and participation layer that gives RezNet a privacy-preserving map of itself; RezNet must continue routing, delivering, and storing messages normally when Atlas is absent, disabled, outdated, or broken.

## Purpose

This document protects the minimum prerequisites Atlas will eventually need while RezNet continues to evolve. It deliberately separates:

1. generic Rez work that should be completed before Atlas begins;
2. architectural seams that current Rez work must preserve; and
3. Atlas features that must not be smuggled into Rez under the label of a prerequisite.

The objective is not to make Rez “Atlas-shaped.” It is to keep Rez extensible enough that Atlas can later attach as an optional subsystem without forking the protocol, duplicating routing authority, or becoming a dependency of core messaging.

## Atlas-ready means

RezNet is ready for Atlas when an optional subsystem can:

- publish and retrieve a small signed, expiring public fact through the existing durable-record plane;
- identify the public relay that fact concerns by a stable cryptographic identity;
- retrieve that fact across more than the currently connected peer set;
- distinguish attempted replication from acknowledged storage;
- expose privacy-safe routing outcomes to an explicitly local advisor without publishing private user intent;
- offer local route-ranking advice without owning route discovery or forwarding;
- start, stop, fail, or be absent without changing baseline Rez behavior; and
- use the same signed record bytes in browser and Node environments.

No Atlas worker, observation record, planner, scheduler, knowledge store, or reward mechanism is required to prove this readiness. Generic test doubles are sufficient.

## Non-negotiable ownership boundary

| Responsibility | Owner before and after Atlas |
|---|---|
| Shared signed objects, canonical bytes, identifiers, and protocol vocabulary | `rez-core` |
| Peer protocol, DHT, relay identity enforcement, route execution, persistence, and optional subsystem lifecycle | `rez-node` |
| App-facing facade, browser crypto/storage, local user policy, and future Atlas participant facade | `rez-sdk` |
| Product UI and application workflows | `rez-chat` |
| UI primitives | `rez-ui` |
| Token and custody contracts | `rez-contracts` |

Atlas does not acquire ownership of mesh connections, `MeshCoordinator`, `InboxRouter`, route tables, DHT storage, onion construction, inbox delivery, identity, or application semantics.

## What already exists and should be preserved

| Existing seam | Current status | Prerequisite treatment |
|---|---|---|
| `DurableRecordV1/V2` and record DHT | Real small, signed, public, self-expiring control plane | Preserve opaque payloads, delegated signing, quotas, expiry, persistence, and publisher-offline retrieval |
| `RouteResolver` | Injected route-discovery strategy returning a verified route entry | Preserve; do not give an Atlas planner direct forwarding authority |
| `GatewayRelaySelector` and `GatewayPathPlanner` | Separate relay selection and onion path construction | Generalize the policy seam only as needed; keep path validation and execution in the node |
| `GatewayLoop` route-failure callback | Local failure signal exists | Evolve into bounded local outcome events without exposing destination identity to public Atlas records |
| `MeshCoordinator.setOnSyncTick` | One optional sync callback exists | Do not turn it into an Atlas scheduler; prefer independent lifecycle composition |
| `InboxRouter` | Enforces direct claimant-backed routes and forwards opaque bytes | Preserve unchanged as Atlas's private delivery plane |
| Browser crypto and IndexedDB providers | Implemented in `rez-sdk` | Preserve cross-runtime record/signature compatibility; a browser still need not run `rez-node` |
| Generic SDK/node dispatch | Implemented architectural rule | Preserve so Atlas operations never require transport-specific facade methods |

## Required before Atlas implementation

### Gate R1 — Cryptographic relay identity

**Why Atlas needs it**

Public observations must name a relay unambiguously. DHT position, relay authentication, descriptors, route registrations, receipts, and later observations cannot safely refer to an arbitrary operator-chosen string as if it imposed key-generation cost.

**Current gap**

`relayKeyId` is configurable and otherwise defaults to `node-<deviceId>`. `DhtNodeId` hashes that string. Although peer authentication binds the presented relay ID to a signed node key and `RelayStore` pins rebinding, an operator can cheaply grind relay ID strings to choose DHT positions.

**Rez prerequisite work**

- Define one stable relay identity derived from, or cryptographically bound to, the persistent node signing key.
- Define the exact relationship among `relayKeyId`, `nodeKeyId`, `nodePublicKeyB64`, and `DhtNodeId`.
- Make the DHT position derive from the cryptographic identity rather than a freely chosen routing string.
- Define a bounded migration for existing configured relay IDs, descriptors, route registrations, handles, receipts, and persisted peer state.
- Reject identity mismatches at peer authentication, descriptor admission, DHT node-reference admission, and route-registration admission.
- Keep human-friendly relay labels as non-authoritative metadata.

**Exit tests**

- Changing a display/configuration label cannot change DHT position.
- A peer cannot advertise one relay ID while authenticating with another node key.
- A discovered DHT node reference is rejected unless its ID, node key, and signed descriptor agree.
- Legacy identities migrate without silently rebinding an existing relay to a new key.
- Cheap string grinding no longer selects a target-adjacent DHT position.

**Canonical owners**

- Shared identity/descriptor vocabulary: `rez-core`.
- Node identity persistence, peer enforcement, DHT mapping, and migration: `rez-node`.

### Gate R2 — Honest durable-record DHT

**Why Atlas needs it**

Atlas public knowledge must converge beyond a relay's current neighbors and remain retrievable after its publisher disappears. “We attempted to send the record” cannot be reported as “this many replicas stored it.”

**Current gaps**

- `DhtLookup` accepts closer discovered nodes with `socket: null`, but it marks a candidate queried *before* checking socket availability: a socket-less candidate permanently burns one of the `alpha` slots for its round and can never be retried. Because discovered nodes sort closest-first, the closest candidates are exactly the ones most likely to be socket-less. Lookup is therefore not merely limited to the connected peer set — socket-less discoveries actively degrade the round budget.
- `DhtNode.putRecord()` increments `replicas` after a fire-and-forget `dht.rec_store` send whose socket-write errors are swallowed, and local storage does not count toward `replicas`. `{ stored: true, replicas: 0 }` is a reachable result that looks successful while the record is held only locally. `DurableRecordProtocol` has no store acknowledgement. The current replication result is actively misleading, not merely incomplete.

**Rez prerequisite work**

- Add a bounded way to query a verified discovered relay: direct connection, an authenticated connection-pool resolution seam, or a mediated query with equivalent binding.
- Apply connection budgets, concurrency limits, deadlines, negative caching, and malicious-closer-node defenses.
- Add an explicit record-store acknowledgement correlated to the request and authenticated peer.
- Report attempted, acknowledged, timed-out, rejected, and local storage separately.
- Preserve record signature, slot, size, expiry, epoch, quota, and delegated-authority checks at every ingress path.
- Verify publisher-offline re-replication and read repair across topology changes.
- Keep the durable-record plane small; this work must not turn it into bulk storage.

**Exit tests**

- A lookup discovers and then queries a previously unconnected closer node under a configured connection budget.
- Socket-less candidates cannot monopolize or prematurely terminate lookup.
- Forged node references, mismatched identities, timeouts, disconnects, and send attempts do not count as replicas.
- A store acknowledgement is accepted only from the authenticated intended peer and only for the requested record slot/content.
- A record remains retrievable after the publisher disconnects and holders undergo bounded churn.
- Existing invitation, device-set, and authority-state durable records remain compatible.

**Canonical owner**

`rez-node` owns peer control records, DHT queries, acknowledgements, persistence, and server validation. `rez-core` owns only signed objects genuinely shared across runtimes.

### Gate R3 — Canonical relay descriptor admission

**Why Atlas needs it**

Atlas observations will refer to public relay identity and protocol capabilities. The base descriptor must have one validation truth before Atlas can safely build evidence about it.

**Current gap**

`RelayDescriptorV1` validates its own metadata while `rez-core/src/directory/validateRelayDescriptorV1.js` repeats much of the same schema. Duplication is the smaller problem: several ingress paths bypass both validators entirely — configured seeds, `peer.bind`, and persistence hydration admit raw descriptor JSON with no schema validation, `RelayStore.upsertDescriptor()` accepts anything with a finite expiry, hydration restores `bindingTrust` verbatim from persisted state, and unvalidated descriptors are re-gossiped to peers as if vetted. The top-level `capabilities` field is signed, unbounded (validated only as "plain object"), gossiped, and persisted while having zero readers — an attacker-controlled signed blob, not merely an under-specified object. `meta.node.transports` and `meta.capabilities.transports` also allow two different transport vocabularies. This creates drift and discourages a clean distinction between stable relay roles and transient Atlas participant capability.

**Rez prerequisite work**

- Establish one canonical descriptor validation implementation in `rez-core`.
- Make `RelayStore.upsertDescriptor()` the mandatory admission choke point in `rez-node`: no ingress, persistence-hydration, trust-restoration, or gossip path may store or re-emit a descriptor that has not passed canonical validation.
- Bind descriptor identity to Gate R1's cryptographic relay identity.
- Define stable protocol roles and coarse network capabilities without adding transient load, exact hardware, or browser fingerprint data.
- Decide whether compatibility requires a V2 descriptor or a signed identity-binding companion record; do not mutate V1 semantics ambiguously.
- Keep momentary Atlas willingness and resource availability out of the base descriptor.

**Exit tests**

- Every descriptor ingress path invokes the same canonical validator.
- Unknown, duplicate, malformed, or identity-conflicting fields fail consistently.
- A persisted descriptor cannot rehydrate with higher trust than a freshly validated one, and a descriptor that never passed canonical admission is never re-gossiped.
- Canonical signed bytes cover identity, endpoints, roles, expiry, and version.
- Descriptor evolution has an explicit mixed-version compatibility test.

**Canonical owner**

`rez-core` owns the shared signed descriptor and its validation. `rez-node` owns admission policy and peer-state storage.

### Gate R4 — Optional local route-intelligence seam

**Why Atlas needs it**

Atlas must eventually compare public knowledge against real outcomes and offer local route advice. It must do so without replacing route discovery, seeing mandatory global intent, or gaining forwarding authority.

**Current gaps**

- `RouteResolver` is injectable, but it returns one route for a private `inboxId`; it is discovery, not an advisory ranking boundary.
- `GatewayRelaySelector` selects eligible relays randomly and `GatewayPathPlanner` constructs the path. There is no explicit optional scorer/advisor contract.
- `GatewayLoop` exposes a route-failure callback, but there is no bounded success/failure outcome stream designed for a local learning module.

**Rez prerequisite work**

- Preserve `RouteResolver` as node-owned discovery and verification.
- Define an optional local advisor seam over already-admitted public relay/path candidates.
- Keep eligibility, onion-key validation, hop bounds, exclusions, destination delivery requirements, and final execution in `rez-node`.
- Define private outcome events, scoped to the requesting client/node execution context, with coarse reason/timing classes and public relay IDs.
- If an outcome crosses a client/node boundary, keep it authenticated and session-scoped; never publish it as an Atlas fact automatically.
- Do not include inbox ID, account ID, contact identity, search/query text, plaintext payload, or the user's complete considered-route set in an exportable event.
- Make advisor timeout, exception, invalid output, or absence fall back to the current selector behavior.
- Avoid a generic plugin framework; add only the smallest injected interface needed by a deterministic local advisor.

**Exit tests**

- A stub advisor can reorder eligible candidates but cannot introduce an ineligible relay or bypass node validation.
- With no advisor, route selection is behaviorally identical to the current baseline.
- Advisor failure cannot fail, delay beyond a strict bound, or reroute a message unexpectedly.
- Outcome events remain private to the requesting execution context and contain no private destination or account identifier.
- The node can compare baseline and advisory choices in shadow mode without granting the advisor authority.

**Canonical owners**

- Candidate validation, route execution, and outcome production: `rez-node`.
- Future user policy and local Atlas planner: `rez-sdk`.

### Gate R5 — Optional subsystem composition and failure isolation

**Why Atlas needs it**

Atlas will have its own lifecycle, persistence, and background work. It must attach beside the mesh rather than expand `MeshCoordinator` into a network-wide scheduler or make node readiness depend on Atlas.

**Current gap**

`MeshCoordinator` already owns connection discovery, descriptor refresh, route synchronization, and status. Its single `setOnSyncTick` hook currently drives related DHT maintenance. Adding Atlas scheduling, leases, validation, and settlement to that hook would create mixed ownership and failure coupling.

**Rez prerequisite work**

- Preserve a composition root where optional independently owned services can be constructed beside `MeshCoordinator`.
- Define start, ready, stop, and local status behavior for optional node subsystems.
- Keep failure policy explicit: Atlas-like service failure is reported locally and never makes core mesh readiness false.
- Do not enumerate future Atlas directives in generic transports or bridges.
- Keep optional subsystem status namespaced rather than merging it into mesh truth.
- Leave task scheduling, leases, validation, storage repair, and settlement for Atlas implementation.

**Exit tests**

- A generic optional-service test double can start and stop with the node.
- Its start failure, tick failure, timeout, or stop failure is surfaced but does not stop mesh routing.
- Removing the optional service restores the exact base composition without conditional transport methods.
- `MeshCoordinator` retains only mesh lifecycle responsibilities.

**Canonical owner**

`rez-node` owns runtime composition and node-local optional service lifecycle.

### Gate R6 — Cross-runtime and extension compatibility guardrails

**Why Atlas needs it**

Atlas participants will include browsers and Node processes. The base network must preserve shared signed bytes and allow new optional record kinds without requiring every old node or application to understand their meaning.

**Current state**

Browser `WebCrypto`, encrypted IndexedDB, durable records, and SDK dispatch already provide most of this foundation. This gate is primarily about preserving those properties while other Rez work continues.

**Rez prerequisite work**

- Maintain byte-identical canonical record signing and verification across browser and Node crypto providers.
- Preserve opaque durable-record payloads and bounded record-kind extensibility.
- Define mixed-version behavior: old nodes may replicate a valid opaque record without interpreting its Atlas payload, while old applications may ignore unknown optional capabilities.
- Keep browser operation behind SDK/WebSocket abstractions; do not make a browser run the Node relay runtime.
- Preserve generic bus/transport dispatch and package dependency direction.

**Exit tests**

- Browser and Node providers sign and verify the same golden record vectors.
- A generic unknown future record kind can be stored and retrieved without transport-specific code.
- Unknown optional subsystem status or capability data does not break existing SDK clients.
- Architecture tests reject per-operation transport facades and `rez-chat` imports from `rez-core`.

**Canonical owners**

- Canonical records and vectors: `rez-core`.
- Peer handling: `rez-node`.
- Browser/Node client adapters: `rez-sdk`.

## Required decisions, but not necessarily base implementation

These decisions must be made before Atlas record design begins. They should not trigger premature feature work.

### Protocol network domain

Atlas public facts must not be replayable between unrelated Rez forks or environments and mistaken for observations about the local network. Rez currently has a settlement `networkId`, but that is not automatically the correct protocol-wide network domain.

Before defining Atlas records, decide:

- whether Rez has a protocol-level network/domain identifier;
- where it is configured and canonically represented;
- whether peer handshakes and descriptors bind it;
- how local/private forks choose one; and
- how signed Atlas records bind it.

Do not reuse the settlement identifier by implication; either make the relationship explicit or keep the concepts separate.

### Public observation privacy budget

Before Atlas observations exist, define which facts are inherently public and which measurements become identifying in combination. Exact IP, geography, browser version, hardware, battery, timing traces, destination-specific failures, and stable participant identity are not acceptable merely because each field seems harmless alone.

### Atlas code placement

Do not create a `rez-atlas` package in advance. Atlas logic should initially follow current owners:

- records in `rez-core`;
- runtime coordination in `rez-node`;
- participant facade and local policy in `rez-sdk`;
- opt-in product controls in `rez-chat`.

A separate package is justified only if implemented code reveals an environment-neutral responsibility genuinely shared by more than one package and not already owned by core, node, or SDK.

## Feature-specific prerequisites that may wait

These are not blockers for the first Atlas public-observation and local-planner vertical.

| Future Atlas capability | Prerequisite before that capability, not before Atlas begins |
|---|---|
| Private work queues and one-shot authority | Stateful capability consumption or explicit rejection of unsupported `maxUses`; lease and replay state remain Atlas work |
| Durable bulk publication | Shard placement, repair, acknowledgements, and retrieval plane separate from the record DHT |
| Paid storage | Cryptographically complete storage challenge/response binding and real proof of independent retention |
| Compensated compute | Deterministic verification, accepted-work receipts, idempotent settlement, and abuse resistance |
| Trust-weighted observations | Adversarially evaluated trust graph in shadow mode; signed assertions alone remain evidence |
| Human-readable publication aliases | Decentralized handle convergence or an explicitly non-canonical handle pointer |
| Direct browser peer participation | A separately designed WebRTC/WebTransport peer plane; not required for browser Atlas participation through a node |

## Explicitly not a prerequisite

Do not start any of the following as “Atlas readiness” work:

- Atlas record families;
- `AtlasCoordinator`;
- participant state machine or browser workers;
- work definitions, leases, results, validation, or acceptance;
- public observation exchange;
- Atlas knowledge store, snapshots, or route planner;
- arbitrary WASM task execution;
- distributed bulk storage;
- storage commitments or proof of replication;
- trust graph or Atlas reputation;
- credits, token rewards, or economic policy;
- new handle semantics;
- browser relay runtime;
- WebRTC/WebTransport channels;
- external-network integrations; or
- Atlas UI.

Those are Atlas or later product work. They begin only after the relevant readiness gates pass and Atlas is explicitly authorized.

## Sequenced Rez work

### Stage A — Protect the boundaries now

This stage is documentation and focused architecture-test work. It may proceed alongside current Rez development.

1. Make this document a reviewed guardrail.
2. Preserve opaque durable records and generic transport dispatch.
3. Preserve node-owned route execution and SDK-owned local user policy.
4. Add or retain architecture tests proving Atlas-like optional code cannot become a core dependency.
5. Baseline current no-Atlas routing behavior for later compatibility comparison.

### Stage B — Complete generic Rez hardening

Implement in dependency order:

1. R1 cryptographic relay identity.
2. R3 canonical descriptor admission and compatible identity binding.
3. R2 bounded multi-hop DHT lookup and acknowledged replication.
4. R4 local advisory/outcome seam.
5. R5 optional subsystem composition and failure isolation.
6. R6 cross-runtime and mixed-version guardrails.

R1 precedes DHT work because DHT position and discovered-node verification depend on the identity decision. R4 and R5 should remain small seams, not speculative Atlas abstractions.

### Stage C — Declare Atlas-ready

**Status 2026-08-15 (post re-audit):** the initial P0–P7 build was audited a
second time (multi-agent adversarial review + independent maintainer audit).
The audit FAILED the original Stage C claim and its findings were remediated
the same day: descriptor admission now verifies signatures and stores only the
canonical serialization (a tampered persisted descriptor could previously
rehydrate as verified/gossip-eligible); DHT lookup and `putRecord` now run
under real raced wall-clock deadlines (one total budget, per-ack settled
snapshots at expiry); globally-deferred dials are refunded and retained as
references; extension failure isolation covers non-`Error` rejections and
`start()` is bounded like `stop()`; refreshed records persist their moved
retention window; DurableRecordV2 direct + delegated golden vectors exist and
are reproduced in all runtimes; the inbox DHT position is pinned by a frozen
literal; and the `e2e.local-mesh.*` suite is reachable again
(`npm run test:e2e:local-mesh` + a dedicated CI job). That CI job is KNOWN RED
on three pre-existing product blockers (delegated WS auth on fs-nodes,
device-link ceremony vs fs home, group-coremember contact materialization) —
visible by design, unrelated to this hardening.

Outstanding before the declaration: (1) maintainer review of the remediated
build; (2) the one-time dev-network identity reset — redeploy r1/r2/r3 WITHOUT
a configured `relay.relayKeyId` so they derive their self-certifying
identities (the rez-chat default config already pins the derived values
computed from their existing node keys); (3) the three pre-existing local-mesh
blockers above; (4) the explicit approval line items below.

Atlas may be scoped for implementation only after:

- R1 through R6 pass their exit tests;
- no active Rez feature depends on Atlas being installed;
- the protocol-domain decision is recorded;
- baseline routing remains available unchanged;
- the initial Atlas vertical and its privacy budget receive explicit approval; and
- the new Atlas work is planned as Atlas, not hidden inside Rez maintenance.

## Development-team build specification

This section is the implementation handoff. Treat every numbered item below as
a separate mergeable ticket unless a ticket explicitly says otherwise. Do not
combine gates into one large pull request. Each ticket must leave the repository
green and must include its own focused tests.

### Team operating contract

The following rules are part of the work, not suggestions:

1. Use JavaScript only, with ESM, classes, `async`/`await`, `#private` members,
   and no optional chaining.
2. Add no dependency. `rez-core` must remain dependency-free.
3. Every new structured value or wire payload must be an `RRecord` subclass.
   Do not add ad-hoc plain-object contracts.
4. New node-to-node control records belong in
   `rez-node/src/contracts/wireRecords/`. Shared signed records belong in
   `rez-core`. Do not move node RPC/control records into `rez-core` merely
   because two nodes exchange them.
5. Generic transports continue dispatching through the existing control/bus
   registries. Do not add DHT, advisor, or optional-service methods to generic
   transport facades.
6. Do not add any class, record, constant, status field, metric, or config key
   containing `Atlas`. The completed work is generic Rez hardening.
7. Do not change `InboxRouter` delivery semantics, onion hop validation, inbox
   claim authority, or the payload-opaque transport boundary.
8. Do not publish local routing outcomes. They remain in-process unless a later,
   separately approved client-session contract is designed.
9. A failed optional service must never change core mesh readiness, routing, or
   durable-record correctness.
10. Every pull request must update this document's readiness scorecard and cite
    the exact exit criterion it closes.

### Required merge order

Use this exact dependency order:

| Order | Ticket group | May start in parallel with |
|---:|---|---|
| 0 | P0 baseline and decisions | Nothing |
| 1 | P1 cryptographic relay identity | P6 test-vector fixture preparation after P0 |
| 2 | P2 canonical descriptor admission | Nothing that consumes the new identity until P1 lands |
| 3 | P3 honest DHT traversal | P4 advisor record/interface definitions |
| 4 | P4 acknowledged durable-record replication | P5 optional lifecycle host |
| 5 | P5 local route-advisor and outcome seams | Remaining P4 integration tests |
| 6 | P6 optional subsystem composition | P7 cross-runtime tests |
| 7 | P7 full compatibility and readiness gate | Nothing; this is the final integration gate |

Do not start P3 or P4 on the old freely selectable relay identity. That would
encode the wrong trust assumption into more DHT code.

### P0 — Baseline, two required decisions, and one defect fix

#### P0.1 Record a no-Atlas behavioral baseline

**Owner:** `rez-node`

**Files to add or update**

- `rez-node/test/architecture.atlas-readiness.test.js`
- `rez-node/test/gateway.relay-selector.test.js` if the current selector tests
  live elsewhere, keep the existing canonical test file instead of duplicating
  it
- `rez-node/test/routing.durable-record-mesh.integration.test.js`
- `rez-core/docs/ATLAS_PREREQUISITES.md`

**Required assertions**

- With no advisor configured, `GatewayRelaySelector` uses the current random
  selection policy over the current eligible set.
- The baseline pins current behavior as it actually is, not as idealized:
  - the selector's hop clamp is pinned as-is (`minHops` overrides `maxHops`
    when larger, hop count is hard-capped at 3, and the count degrades to the
    eligible-set size instead of failing);
  - descriptor expiry is enforced upstream (`RelayStore.listDescriptors` and
    `GatewayLoop`), not by the selector;
  - `GatewayLoop.onRouteFailureCallback` has zero production subscribers, so
    route failures are currently observable only through that unused seam; and
  - `NotEnoughRelaysError` thrown by the selector is not classified as a
    routing failure by the retry path and bypasses the outbound retry queue.
- With no optional service configured, node startup, readiness, routing, and
  shutdown are byte-for-byte or behaviorally unchanged.
- `InboxRouter` remains the only component that installs and executes inbox
  delivery routes.
- `MeshCoordinator` remains responsible only for mesh discovery, peer
  connection, descriptor refresh, route synchronization, and mesh status.
- A `DurableRecordV2` can be published, retrieved, reloaded from persistence,
  and retrieved after the original publisher disconnects in the existing test
  mesh.
- Unknown `recordKind` values remain valid when the generic durable-record
  signature, size, slot, time, and authority checks pass.

**Done when**

The tests describe current behavior and pass before production code changes.
Do not weaken these assertions in later tickets; intentionally changed behavior
must add a new explicit assertion while preserving the no-extension path.

#### P0.2 Approve the relay identity ADR

**Owner:** protocol maintainer; implementation split between `rez-core` and
`rez-node`

Create `rez-core/docs/adr/ADR-RELAY-IDENTITY.md`. The `docs/adr/` directory does
not exist yet; creating it is part of this ticket — there is no existing ADR
framework to slot into. Unless the maintainer records a different choice before
implementation, use this default:

- `relayKeyId` is self-certifying and equals
  `rez:relay:<sha256-lowercase-hex>`, where the digest is over the decoded
  Ed25519 SPKI DER public-key bytes carried by `nodePublicKeyB64`.
- `nodeKeyId` remains `nodekey:<first-32-hex>` for compatibility, but every
  verifier re-derives it from the same public key. A configured key ID that does
  not match the key is invalid.
- `DhtNodeId` remains SHA-256 over the UTF-8 canonical `relayKeyId`. The extra
  hash is intentional domain separation between an identity fingerprint and a
  DHT position.
- Invariant: `DhtNodeId.fromRelayKeyId()` is also the inbox-ID hasher
  (`DhtRouteAnnouncer`, `DhtRouteResolver`) — relay IDs and inbox IDs share one
  DHT keyspace through one function. Changing relay identity derivation MUST
  NOT change inbox-ID hashing semantics; if the function is split, the inbox
  path keeps its current bytes, and a test proves it.
- Human-readable node names are metadata only and never affect identity or DHT
  position.
- Because Rez is pre-launch, the default migration is a one-time development
  network identity reset. Do not build a permanent legacy-alias protocol unless
  the maintainer explicitly states that deployed identity continuity is a hard
  requirement.

The ADR must also inventory every persisted or signed use of `relayKeyId`, at
minimum: config, relay descriptors, peer auth, relay store pins, DHT buckets,
route registrations, hosted inbox registrations, handle proofs, receipts,
settlement/storage artifacts, test fixtures, DHT per-peer rate-limit keys
(`peerRateLimitKeys` — a self-chosen ID is currently a self-chosen rate-limit
bucket), reputation/attestation records (`ReputationScorer`,
`PeerAttestationService`), session-capability records (`SessionCapabilities`
accepts a `relay.id || relay.relayKeyId` alias), SDK auth challenges
(`rez-sdk` `AuthStateMachine` requires a non-empty `relayKeyId`), SDK node
delegations (`InboxClaimStore.createNodeDelegation` signs it), and the
`rez-chat` default relay config and e2e fixtures (hardcoded `ws:relay*` IDs
paired with literal `nodekey:` pins — exactly the strings a derivation rule
invalidates).

**Blocking question**

If existing public node identities must survive, stop P1 and write a separate
dual-identity migration ADR. It must specify dual advertisement, signature
binding, expiration, downgrade handling, and the date/version when legacy IDs
become invalid. Do not improvise aliases in code.

#### P0.3 Approve the protocol network-domain ADR

**Owner:** `rez-core`

Create `rez-core/docs/adr/ADR-PROTOCOL-NETWORK-DOMAIN.md` and decide the
following before any future public observation record is designed:

- canonical field name and byte/string encoding;
- how mainnet, testnet, development, and private forks obtain distinct values;
- whether peer authentication and relay descriptors bind the value;
- exact relationship to the economic `networkId`;
- rejection behavior for cross-domain peers and signed records.

Recommended default: define a protocol-domain identifier distinct from the
settlement `networkId`, then explicitly bind the settlement network to it when
economics are enabled. Do not silently reuse the settlement identifier.

P0.3 is a design prerequisite only. Do not add an Atlas record or economic
artifact while completing it.

#### P0.4 Fix the dead `RoutingEngine` descriptor shortcut

**Owner:** `rez-node`

`rez-node/src/routing/RoutingEngine.js` calls
`this.relayStore.getDescriptorByKeyId(...)` behind a `typeof === "function"`
guard, but `RelayStore` defines no such method (only `getDescriptor`). The
RouteTable-derived next-hop shortcut is therefore permanently dead and silently
falls back to HTTP peer queries — exactly the silent fail-open behavior this
document exists to prevent. Fix the call to the real method, add a regression
test proving the shortcut executes, and remove the defensive `typeof` guard so
a future rename fails loudly instead of silently degrading.

### P1 — Cryptographic relay identity

#### P1.1 Add the shared derivation SSOT

**Owner:** `rez-core`

**Add**

- `rez-core/src/identity/relayIdentity.js`
- exports from the existing `rez-core/src/identity/index.js` and public package
  entrypoint
- `rez-core/test/relay-identity.test.js`

**Required public functions**

- `relayKeyIdForNodePublicKeyB64(nodePublicKeyB64)` returns the canonical
  `rez:relay:` identifier.
- `nodeKeyIdForNodePublicKeyB64(nodePublicKeyB64)` returns the canonical
  compatibility `nodekey:` identifier.
- `validateRelayIdentityBinding({ relayKeyId, nodeKeyId,
  nodePublicKeyB64 })` returns a record verdict with a bounded reason enum; it
  must not throw for untrusted input.

Use the existing dependency-free `Hash` and base64 byte utilities. Do not import
Node crypto into this module. Reject invalid base64, empty keys, non-canonical
prefix/case, and mismatched IDs.

**Tests**

- fixed golden public key to expected relay and node IDs;
- one changed key byte changes both IDs;
- label/config text has no effect;
- malformed base64 and mismatched fields fail closed;
- Node and browser callers receive identical results.

#### P1.2 Make node identity generation use the shared derivation

**Owner:** `rez-node`

**Update**

- `rez-node/src/identity/NodeIdentity.js` (note: `relayKeyId` does not live
  here today — it is grafted onto the identity post-hoc by `startRezNode.js`)
- `rez-node/src/app/startRezNode.js` (first `node-<deviceId>` default site)
- `rez-node/src/relay/NodeRelayBootstrap.js` (second `node-<deviceId>` default
  site; also keys the onion-key rotator on `relayKeyId`)
- `rez-node/src/util/relayKeyId.js` (the existing normalization SSOT — its
  header documents a past three-divergent-copies bug; node-side validation glue
  belongs here, delegating derivation to `rez-core`)
- `rez-node/src/app/NodeConfigValidator.js`
- `rez-node/test/identity.node-identity.test.js`
- configuration fixtures that set `relayKeyId`

**Required behavior**

- Generate the Ed25519 keypair once as today.
- Derive both IDs from the persisted public key through `rez-core`.
- Never derive `relayKeyId` from `deviceId`. Remove both `node-<deviceId>`
  default sites (`startRezNode.js` and `NodeRelayBootstrap.js`).
- A configured identity with key material is accepted only when both IDs
  re-derive correctly.
- A configured `relay.relayKeyId` is either equal to the derived ID or rejected
  with `RELAY_IDENTITY_MISMATCH`; it is never an override.
- Return the derived `relayKeyId` from the node identity SSOT used by bootstrap,
  descriptors, SDK delegation data, and runtime status.

Do not add a second derivation helper in `rez-node`.

#### P1.3 Enforce the binding at every admission point

**Owner:** `rez-node`

**Update at minimum**

- `rez-node/src/relay/PeerAuthShared.js`
- `rez-node/src/relay/RelayPeerDirectory.js`
- `rez-node/src/relay/SocketFrameRouter.js`
- `rez-node/src/network/RelayStore.js`
- `rez-node/src/network/RelayConnectionPool.js`
- `rez-node/src/routing/dht/DhtNodeId.js`
- `rez-node/src/routing/dht/DhtLookup.js`
- `rez-node/src/app/HostedInboxRegistry.js`
- `rez-node/src/storage/pg/PgHostedInboxRegistry.js`
- `rez-node/src/app/bootstrapRelay.js` (wires identity into DHT, rate limiting,
  gateway, and inbox routing)
- `rez-node/src/routing/dht/peerRateLimitKeys.js` (rate-limit buckets keyed on
  `relayKeyId`)
- `rez-node/src/settlement/ReputationScorer.js` (scores by `relayKeyId`)
- `rez-node/src/contracts/wireRecords/SessionCapabilities.js` (collapse the
  `relay.id || relay.relayKeyId` alias to one canonical field name)
- direct identity-related tests for all of the above

**Required behavior**

- Peer hello/challenge/identify/accept validates the self-certifying binding
  before assigning `relay-provisional` or `relay-verified`.
- Descriptor admission validates the same binding before pinning or gossiping.
- A DHT node reference is valid only when `nodeIdHex` matches the canonical
  `relayKeyId`, and the relay identity is known from an authenticated socket or
  a valid signed descriptor.
- Route and hosted-inbox registrations that name a delivery relay are accepted
  only when the local runtime can bind that ID to the expected relay identity.
- Existing TOFU pinning may remember a first-seen valid key; it may not make an
  invalid self-certifying binding valid.
- Error logs name the failure class, not the public key or private routing
  target.

**Required adversarial tests**

- correct signature with wrong `relayKeyId`;
- correct signature with wrong `nodeKeyId`;
- descriptor key differs from peer-auth key;
- DHT hint uses a valid ID with an arbitrary `nodeIdHex`;
- same relay ID is presented by a second key;
- configured seed pin conflicts with derived identity;
- restart preserves identity and DHT position;
- changing nickname, endpoint, or device ID preserves identity and DHT
  position.

#### P1.4 Migrate cross-package identity consumers

**Owners:** `rez-sdk` and `rez-chat`

The development-network identity reset invalidates every hardcoded relay ID.
This ticket lands with, or immediately after, P1.2/P1.3 — it is part of the
identity migration, not optional cleanup:

- `rez-sdk/src/auth/AuthStateMachine.js` requires a non-empty `relayKeyId` in
  the auth challenge, and `rez-sdk/src/inbox/InboxClaimStore.js`
  (`createNodeDelegation`) signs `relayKeyId` into node delegations. Both must
  accept only the canonical derived form after the reset.
- `rez-chat/src/server/config/defaultRezConfig.js` hardcodes
  `ws:relay1`/`ws:relay2`/`ws:relay3` paired with literal `nodekey:` pins;
  replace with derived identities for the reset network.
- rez-chat e2e tests that hardcode relay IDs move to fixture-derived
  identities.

### P2 — Canonical relay descriptor admission

#### P2.1 Remove the duplicate validator

**Owner:** `rez-core`

**Current duplicate sources**

- `rez-core/src/objects/relay/RelayDescriptorV1.js`
- `rez-core/src/directory/validateRelayDescriptorV1.js`

`RelayDescriptorV1` must become the only schema/shape validator. The directory
function may remain as a compatibility adapter, but it may only call
`RelayDescriptorV1.fromJSON()` and the one shared cryptographic identity-binding
validator. It must contain no duplicated field lists, limits, regular
expressions, or capability rules.

**Required tests**

- a table-driven corpus is run through direct construction, `fromJSON()`, and
  the compatibility validator;
- every input produces the same accept/reject outcome and same canonical
  reason;
- mutation testing covers every allowed field, unknown field, duplicate array
  member, boundary length, expiry, signature field, and identity mismatch;
- the compatibility validator must not short-circuit on `instanceof` in a way
  that skips expiry validation (today an already-constructed, already-expired
  instance passes while the same JSON is rejected) — expired input fails
  identically in both forms.

#### P2.2 Close the top-level capabilities ambiguity

**Owner:** `rez-core`

Top-level `descriptor.capabilities` is not merely ambiguous: it is validated
only as "plain object" (no key allowlist, no size or depth bound), has zero
readers in the codebase, and is nonetheless signed, gossiped, and persisted.
Treat it as attacker-controlled surface to be removed or strictly bounded, not
as ambiguity to document. Do not leave both `descriptor.capabilities` and
`descriptor.meta.capabilities` as competing truths. Use the existing canonical
format if compatibility tests prove one is already authoritative. Otherwise
introduce `RelayDescriptorV2` and make the choice explicit; do not silently
reinterpret V1.

The same decision must also resolve:

- the transport-vocabulary split: `meta.node.transports` allows
  `{http,https,tcp,ws,wss}` while `meta.capabilities.transports` allows
  `{tcp,http}` — one canonical enum must own transport names; and
- signing-domain separation: peer-auth payloads signed by the same node key
  carry a `kind` discriminator, but the descriptor signing payload has none.
  The V2/companion-record decision must add an explicit signing-domain
  discriminator to descriptor bytes.

Stable base capabilities may describe only protocol roles, for example
supported transports and store-and-forward support. They must not contain:

- CPU, memory, battery, GPU, browser, or hardware detail;
- current load or available capacity;
- IP-derived geography;
- willingness to run optional work;
- pricing, trust rank, reward eligibility, or reputation; or
- destination-specific measurements.

**Mixed-version requirement**

If V2 is required, add explicit V1-read/V2-read tests and a documented emission
policy. Old nodes must fail closed on a descriptor they cannot validate, while
new nodes must not merge V1 and V2 fields into a synthetic unsigned descriptor.

#### P2.3 Prove every ingress uses the SSOT

**Owner:** `rez-node`

Enforce admission at the choke point, then audit every caller. Today only
`DescriptorExchange` uses the directory validator and only self-publication
uses the class; every other path stores raw JSON.

- `RelayStore.upsertDescriptor()` — the real choke point (`source` defaults to
  `"discovery"`, validates nothing today). Admission is enforced here, not
  per-caller; per-caller enumeration is what let each path drift.
- configured seeds (accepted today on a shape sniff only);
- `DescriptorExchange`;
- `peer.bind` (today an authenticated peer can bind a descriptor with empty
  `onionKeys`, garbage endpoints, or a past `expiresAt`);
- `RelayStore` hydration — persisted-trust replay: `hydratePersistentDescriptors`
  restores `source` and `bindingTrust` verbatim from storage, so a KV write can
  resurrect a forged descriptor as an operator pin. Restored trust must be
  re-derived, never replayed;
- re-gossip: `DescriptorExchange` re-broadcasts store contents; only
  canonically admitted descriptors may be re-emitted;
- self descriptor publication; and
- the HTTP/directory discovery path referenced by
  `rez-node/docs/REZNET_MESH_MODEL.md` — the audit found no such code path
  exists; confirm and fix the stale doc rather than hunting for it.

Add an architecture test that fails when a second descriptor field validator
or allowed-field list appears outside the canonical `rez-core` owner.

### P3 — Bounded DHT traversal beyond connected peers

#### P3.1 Add an authenticated candidate-resolution seam

**Owner:** `rez-node`

**Add**

- `rez-node/src/routing/dht/DhtCandidateResolver.js`
- `rez-node/test/routing.dht-candidate-resolver.test.js`

**Update**

- `rez-node/src/network/RelayConnectionPool.js`
- `rez-node/src/network/RelayStore.js`
- `rez-node/src/routing/dht/DhtLookup.js`
- `rez-node/src/routing/dht/DhtNode.js`
- `rez-node/src/app/bootstrapRelay.js`

`DhtCandidateResolver` has one responsibility: given a candidate relay ID,
return an already-authenticated or newly authenticated socket bound to that ID,
or return a typed failure. It must:

1. require a valid, unexpired, identity-bound descriptor already admitted to
   `RelayStore`;
2. use `RelayConnectionPool` to reuse or establish a connection;
3. verify the authenticated peer on the resulting socket matches the requested
   relay ID;
4. never dial an endpoint supplied only by an untrusted DHT reply; and
5. expose no general-purpose plugin or arbitrary URL dial interface.

Add the narrowest required pool method, such as
`getAuthenticatedRelaySocket(relayKeyId)`. This is not a trivial accessor:
`RelayConnectionPool` currently has no relay-ID-to-socket API of any kind —
`sendByRelayId` is send-only and throws when unconnected, the relay-ID lookup
is private, and `ensureConnection` is keyed by endpoint. The new method
therefore entails admitted-descriptor lookup, endpoint selection, connection
establishment through the endpoint-keyed pool, and post-auth verification that
the authenticated peer matches the requested relay ID. Size the ticket
accordingly. Add only that method; do not expose the pool's internal
connection maps.

#### P3.2 Make iterative lookup actually query discovered candidates

**Owner:** `rez-node`

Modify `DhtLookup` so socket-less candidates are resolved before they are marked
queried. Use these default limits unless configuration already has stricter
canonical values:

| Limit | Default |
|---|---:|
| parallel queries (`alpha`) | 3 |
| returned closest nodes (`k`) | 20 |
| maximum lookup rounds | 10 |
| maximum new candidate dials per lookup | 4 |
| per-candidate dial timeout | 3,000 ms |
| total lookup deadline | 10,000 ms |
| negative candidate cache | 30,000 ms |

The lookup result must be an `RRecord` containing at least:

- value, when one was found;
- closest verified candidates;
- queried count;
- dial-attempt count;
- timeout count;
- rejected-candidate count; and
- completion reason: `value-found`, `converged`, `deadline`, `budget`, or
  `no-candidates`.

**Algorithm requirements**

- Do not mark a socket-less candidate queried until resolution succeeds or a
  typed resolution failure is recorded.
- Deduplicate by canonical relay ID and DHT node ID.
- Never let unresolved candidates displace all queryable candidates from the
  active `k` set.
- Prefer closer verified candidates, but reserve progress for an already
  queryable candidate when all closer candidates are unresolved.
- Apply the total deadline across dial and query time, not once per operation.
- Query responses received after deadline or on a different socket are ignored.
- A malicious peer cannot reset budgets by returning the same IDs in a
  different order.
- Resolver failure degrades lookup; it does not crash mesh routing.

**Required tests**

- A connected peer reveals a closer, previously unconnected relay; the lookup
  authenticates it and queries it in the next round.
- The current slot-burn defect is pinned as fixed by a dedicated regression
  test: a socket-less candidate is never marked queried before resolution
  succeeds or a typed failure is recorded, and it no longer permanently
  consumes an `alpha` slot with zero sends.
- Four malicious unreachable closer candidates cannot prevent a reachable
  fifth candidate from being queried.
- Repeated, duplicate, malformed, identity-mismatched, and target-adjacent fake
  candidates consume bounded work and do not enter the verified result set.
- Deadline and dial budget are deterministic under a fake clock.
- No candidate resolver configured reproduces the P0 connected-peer behavior.

### P4 — Acknowledged, truthful durable-record replication

#### P4.1 Add node-owned store request and acknowledgement records

**Owner:** `rez-node`

**Add under** `rez-node/src/contracts/wireRecords/`:

- `DhtRecordStoreRequestV1`
- `DhtRecordStoreAckV1`
- bounded constants for acknowledgement status and rejection reason
- exports and registry coverage. Note: the WS wire-manifest architecture test
  does not cover DHT control types — they dispatch through
  `ControlMessageRegistry`, not `REZ_CONTRACT_TYPES` — so the new records get
  no automatic guardrail from it. Add an equivalent totality/coverage
  architecture test for DHT control records (or explicitly extend the manifest
  to control types); do not claim "manifest coverage" for a surface the
  manifest does not govern.

The request record contains exactly:

- control type `dht.rec_store`;
- protocol version;
- request ID;
- publisher-bound slot key; and
- the signed durable record.

The acknowledgement contains exactly:

- control type `dht.rec_store.ack`;
- protocol version;
- matching request ID;
- matching slot key;
- SHA-256 digest of the canonical stored record bytes;
- status: `stored`, `refreshed`, or `rejected`; and
- a bounded rejection reason or null.

Do not put endpoint, account, inbox, path, pricing, storage capacity, or Atlas
fields in either record. Timeout and disconnect are local outcomes, not remote
acknowledgement statuses.

#### P4.2 Make `queryRecStore` await an authenticated acknowledgement

**Owner:** `rez-node`

**Update**

- `rez-node/src/routing/dht/DurableRecordProtocol.js`
- `rez-node/src/routing/dht/DhtQueryWaiter.js` — its resolution shape is
  hardcoded to the lookup result `{ value, nodes }` (timeouts and `clear()`
  resolve to it too), so the ack path requires either a generalized waiter
  contract or a separate, narrowly owned ack waiter. Decide which up front;
  do not contort an acknowledgement into the lookup shape
- `rez-node/test/routing.durable-record-protocol.test.js`
- `rez-node/test/architecture.wire-manifest.test.js`

Required contract:

- `queryRecStore(socket, key, record)` returns a promise of a typed result.
- The pending query is registered before sending.
- The receiver verifies the request record, slot binding, durable-record
  signature, expiry, size, authority, epoch floor, and local quota before
  acknowledging.
- `stored` means a new record or newer valid version was committed to the local
  record store and its persistence hook was invoked.
- `refreshed` means the exact valid record was already present and its permitted
  refresh semantics completed.
- `rejected` names a bounded safe reason; do not echo attacker-controlled error
  text.
- The sender accepts an acknowledgement only on the same authenticated socket,
  for the same request ID, key, and record digest.
- Late, duplicate, mismatched-socket, wrong-digest, and unknown-request
  acknowledgements are ignored and tested.
- Revocation is an explicit recorded decision, not an accident. **DECIDED
  (2026-08-15): ack-path verification does NOT include revocation state.**
  `#handleRecStore` verifies with `verifyDurableRecordDual(record, nowMs,
  { maxBytes })` and no `revocationState`, byte-identical to the pre-P4
  ingress. Rationale: a stranger replica is account-agnostic and cannot hold
  authoritative revocation state for accounts it does not home — pretending
  otherwise would be a fail-open oracle. Revocation IS evaluated where the
  node is authoritative: the HOME gateway's local put path (which passes its
  own account's state to `putRecord`) and the read-repair gate. An ack
  therefore attests storage/refresh of a structurally valid record, never
  authorization freshness.

#### P4.3 Return honest replication results from `putRecord`

**Owner:** `rez-node`

Replace the current `{ replicas }` result with a node-owned `RRecord`, for
example `DhtRecordPutResultV1`, containing:

- `storedLocally`;
- `localId`;
- `attemptedRemote`;
- `acknowledgedStored`;
- `acknowledgedRefreshed`;
- `rejectedRemote`;
- `timedOutRemote`;
- `disconnectedRemote`;
- `skippedRemote`;
- `targetReplicaCount`;
- `completedAtMs`; and
- a bounded top-level reason or null.

Rules:

- Local storage is never counted as a remote replica.
- A successful socket write is only an attempt.
- Only authenticated `stored` or `refreshed` acknowledgements count as remote
  holders.
- One relay ID counts at most once.
- The method has a total deadline and returns partial truthful results rather
  than hanging.
- Existing SDK callers receive a backward-compatible response until the node
  RPC version explicitly changes. Adapt at the node handler boundary; do not
  leak internal record classes into `rez-sdk`.

#### P4.4 Apply acknowledgement truth to repair and re-replication

**Owner:** `rez-node`

Update `republishHeldRecords()` so its status/metrics distinguish attempted and
acknowledged copies. The periodic tick must remain bounded by
`maxRepublishPerTick`; it must not create an unbounded promise collection or
overlap indefinitely with the next tick.

Read repair already exists: `DhtNode`'s resolve-overlay path re-verifies,
read-repairs into the local store, and applies a revocation-aware cache/serve
gate. Preserve and extend that path to consume acknowledged-replication truth.
Do not introduce a second read-repair implementation.

`recordReplicateIntervalMs` and `recordMaxRepublishPerTick` are read from
config but set nowhere — the effective values are always the defaults
(600,000 ms / 64). Either wire both keys through `NodeConfigValidator`
intentionally or declare the defaults canonical and delete the dead config
reads. No dead plumbing.

Add deterministic integration tests covering:

- publisher disconnect after initial acknowledged replication;
- restart of one holder from persisted storage;
- loss of enough holders to trigger bounded re-replication;
- read repair after a local miss;
- rejection of an older epoch or immutable-slot conflict;
- mixed success, timeout, rejection, and disconnect in one put; and
- invitation, device-set, and authority-state record compatibility.

### P5 — Optional local route advice and private outcomes

#### P5.1 Add the smallest advisor contract

**Owner:** `rez-node`

**Add**

- `rez-node/src/gateway/RouteAdvisor.js`
- node-owned internal `RRecord` classes for candidate input and advice output
- `rez-node/test/gateway.route-advisor.test.js`

The interface has one asynchronous method that receives already-admitted,
already-eligible relay candidates and returns an ordered list of their relay
IDs. It has no network, descriptor-store, route-table, inbox, crypto, or sender
reference.

Input may contain only public or local coarse fields needed to rank already
eligible relays. It must not contain:

- inbox ID, account ID, contact ID, handle, or payload;
- plaintext endpoint query or search text;
- the user's message bytes or size class;
- the complete route discovery trace;
- private key material; or
- authority to add or remove candidates.

Use a default 50 ms advisor deadline. A timeout, exception, duplicate ID,
unknown ID, omitted eligible ID, or malformed response causes complete fallback
to the current selector. Do not partially trust malformed advice.

#### P5.2 Integrate advice after eligibility and before random choice

**Owner:** `rez-node`

**Update**

- `rez-node/src/gateway/GatewayRelaySelector.js`
- `rez-node/src/gateway/GatewayLoop.js`
- `rez-node/src/gateway/MeshBootstrap.js`
- focused gateway tests

Required order of operations:

1. node validates descriptor, expiry, endpoint, onion key, exclusions, and hop
   constraints;
2. optional advisor ranks only that eligible set;
3. node validates the returned permutation;
4. node chooses from the advised order or current random fallback;
5. `GatewayPathPlanner` selects onion keys and constructs the path; and
6. `GatewaySender` executes it.

The advisor never receives `RouteResolver.resolve(inboxId, ctx)` and never
becomes route discovery. It advises the public onion-relay portion only.

Support modes `off`, `shadow`, and `advisory` as bounded node-local policy:

- `off`: do not call the advisor;
- `shadow`: call and validate it, record local comparison, execute baseline;
- `advisory`: execute valid advice, otherwise baseline.

There is no `required` or `enforced` mode.

The existing `ReputationScorer` (constructed at bootstrap today, consulted by
nothing) is the natural first shadow-mode advisor double: consuming it proves
the seam can rank from an existing local scoring component without granting it
routing authority. This is a test-double choice, not a dependency — Atlas does
not depend on it and the seam must work with any deterministic advisor.

#### P5.3 Add a private, truthful route-outcome stream

**Owner:** `rez-node`

**Add**

- `RouteOutcomeV1` as a node-owned internal `RRecord`
- a bounded in-process publisher/subscriber with unsubscribe support
- `rez-node/test/gateway.route-outcome.test.js`

Outcomes cover onion-send execution only. `GatewayLoop`'s shared-home durable
deposit, direct-route-cache, and `inboxRouter.routeDelivery` fallback paths
bypass the selector entirely and are explicitly out of scope for outcome
events in this prerequisite work — do not emit events for them, and do not
present the stream as a general routing-outcome feed. This keeps the seam
small; widening coverage is a later, separately approved decision.

Allowed outcome classes:

- `entry-send-accepted`: the entry socket accepted the write; this is not
  delivery proof;
- `route-failed`: an authenticated route failure was correlated to the packet;
- `send-timeout`;
- `send-disconnected`; and
- `delivery-confirmed` only when an existing authenticated end-to-end receipt
  actually proves it.

The record may contain packet correlation local to the process, public relay
IDs involved in the executed path, advisor mode, coarse duration bucket, coarse
reason, and timestamp. It must not contain the destination inbox, sender
account, payload, contact, non-executed candidate set, or discovery trace.

Outcomes are memory-bounded and expire. Use a default maximum of 1,000 events
or 15 minutes, whichever removes an event first. They are not persisted,
gossiped, placed in durable records, included in general metrics labels, or
sent to an SDK client by this prerequisite work.

### P6 — Optional subsystem lifecycle and failure isolation

#### P6.1 Add a narrow lifecycle host

**Owner:** `rez-node`

**Add**

- `rez-node/src/app/OptionalNodeServiceHost.js`
- node-owned service status `RRecord` classes
- `rez-node/test/app.optional-node-service-host.test.js`

Each service is a class instance with:

- stable non-user-derived name;
- `start()`;
- `stop()`;
- `getStatus()`; and
- optional `isEnabled()`.

Host behavior:

- start enabled services independently after the core runtime has been
  constructed;
- catch and report each service's start failure without aborting mesh startup;
- stop successfully started services in reverse order;
- bound stop time per service;
- report namespaced `disabled`, `starting`, `ready`, `degraded`, `failed`, and
  `stopped` states;
- never retry on the mesh discovery tick; and
- never merge optional-service status into `MeshCoordinator.getStatus()` or
  core readiness.

This is a small composition helper, not a plugin loader. It must not discover
packages, load arbitrary modules, expose dependency injection by string name,
or own timers for services.

#### P6.2 Integrate the host at the node composition root

**Owner:** `rez-node`

**Update**

- `rez-node/src/app/startRezNode.js`
- `rez-node/src/app/bootstrapRelay.js` only if construction ownership requires
  it
- `rez-node/src/gateway/MeshCoordinator.js`
- startup, readiness, shutdown, and mesh-coordinator tests

Required lifecycle order:

1. construct core storage, relay runtime, gateway, DHT, and mesh;
2. start core runtime exactly as today;
3. start optional services independently;
4. report optional status separately;
5. on shutdown, stop optional services before tearing down dependencies they
   may read; and
6. continue the existing core shutdown sequence.

Replace `MeshCoordinator.setOnSyncTick` only if required to remove mixed
ownership. Durable-record maintenance is DHT work and may retain a DHT-owned
timer or a generic scheduler owned at the composition root. Do not replace one
single callback with an unbounded array of anonymous tick callbacks.

**Failure tests**

- service throws in `start()`;
- service reports degraded after start;
- service background task rejects;
- service hangs in `stop()`;
- two services fail independently;
- no services configured;
- mesh routing succeeds during every failure above; and
- `/ready` remains governed by mandatory storage/runtime dependencies only.

### P7 — Cross-runtime and extension compatibility

#### P7.1 Add shared golden vectors

**Owners:** vector source in `rez-core`; consumers in `rez-node` and `rez-sdk`

Add one canonical fixture containing:

- Ed25519 public/private test key material intended only for tests;
- canonical relay and node IDs;
- canonical relay descriptor signing bytes and signature;
- canonical `DurableRecordV1` bytes and signature;
- canonical direct-owner `DurableRecordV2` bytes and signature;
- canonical delegated `DurableRecordV2` bytes and signature; and
- canonical slot/DHT IDs.

The fixture must be represented through record classes or immutable encoded
bytes, not a second hand-written schema. Node crypto and browser `WebCrypto`
must independently produce or verify identical bytes.

Add tests in:

- `rez-core/test/` for canonical bytes and ID derivation;
- `rez-node/test/` for Node verification and DHT mapping; and
- `rez-sdk/test/` for browser/WebCrypto verification and IndexedDB round trip.

#### P7.2 Prove opaque unknown-kind transport

**Owners:** `rez-core`, `rez-node`, and `rez-sdk` within their current boundaries

Use a fake future kind such as `future-test-public-fact-v1`; do not use an
Atlas-named kind. Prove that:

- SDK can sign it as a generic durable record;
- node validates generic envelope invariants without interpreting payload
  meaning;
- DHT stores, acknowledges, persists, reloads, retrieves, and read-repairs it;
- an application that does not know the kind can ignore it cleanly; and
- no transport-specific method or switch case was added for the kind.

#### P7.3 Add the final no-extension compatibility suite

**Owner:** `rez-node`, with package-boundary tests in the package that owns each
rule

The final suite must run two configurations through the same scenarios:

- base Rez with every optional seam absent; and
- base Rez with deterministic test doubles installed.

Scenarios:

- node start/ready/stop;
- direct hosted-inbox delivery;
- DHT route discovery with gossip fallback;
- onion route selection and send;
- route failure and outbound queue behavior;
- durable-record put/get/restart/churn; and
- mixed descriptor versions if P2 introduced V2.

The base configuration is the compatibility authority. Installing, disabling,
timing out, or breaking the test doubles must not make a base scenario fail.

## Ticket completion template

Every ticket must include this exact report in its pull request:

```text
Prerequisite ticket:
Exit criterion closed:
Files changed:
Verification performed:
Pass/fail status:
Specs checked:
Canonical owners confirmed:
Duplicate/split-brain findings:
Boundary/SSOT findings:
God-class findings:
Dead code removed:
Tests added/updated:
Behavior with extension absent:
Privacy/security invariants checked:
Remaining risks or follow-ups:
```

Do not mark a ticket complete with an unreviewed TODO, skipped test, silent
fallback, or undocumented compatibility break.

## Verification commands

Run from the monorepo root. Use the repository's root-installed workspace
dependencies; do not install inside a package.

The root `package.json` currently defines no scripts — there is no `npm run
ci` and no `npm run guardrails`. Use the package-owned commands:

```sh
npm test --workspace rez-core
npm test --workspace rez-sdk
npm test --workspace rez-node
npm test --workspace rez-chat
```

If a later ticket adds a single root CI command, adopt it then; do not assume
one exists. During each ticket, run the smallest focused set first. Before
merging a ticket, run the owning package's full tests. Before declaring
Atlas-ready, run all four packages above and record every command and result.
At minimum the final gate must cover `rez-core`, `rez-node`, `rez-sdk`, and
the `rez-chat` architecture tests that protect package and generic-transport
boundaries.

Warning: the `rez-chat` and `rez-ui` test scripts enumerate test files by
hand (this has already hidden failing guardrails once). Any new test file
added to those packages must also be appended to the package's `npm test`
script or it silently never runs. Before counting a new test as coverage,
verify it actually executes in the package's test command. `rez-core`,
`rez-sdk`, and `rez-node` auto-discover tests.

The final review must also run a repository search proving:

- no `Atlas` production symbol was introduced;
- no optional chaining was added (there are currently zero real uses; this is
  convention-enforced only — if machine enforcement is wanted, add an
  architecture test that matches `?.` specifically and does not flag the
  allowed and widely used `??`);
- no new dependency was added;
- no new per-operation generic transport method was added;
- descriptor validation has one canonical implementation;
- relay ID derivation has one canonical implementation; and
- `MeshCoordinator` did not acquire advisor, work scheduling, settlement, trust,
  or storage-repair responsibilities.

## Scope-control test for every prerequisite ticket

Before accepting a ticket as base Rez work, ask:

1. Would this still improve correctness, extensibility, or truthfulness if Atlas were never built?
2. Can it be specified and tested without an Atlas record, worker, scheduler, planner, or reward?
3. Does Rez behave normally when the extension is absent?
4. Does the change preserve current canonical ownership?

If the answer to any question is no, the ticket is probably Atlas implementation and should remain deferred.

## Readiness scorecard

| Gate | Current assessment | Atlas blocker |
|---|---|---|
| R1 Cryptographic relay identity | **PASS** (2026-08-15): `relayKeyId` is self-certifying (`rez:relay:` + sha256 of the node SPKI key) per ADR-RELAY-IDENTITY; derivation SSOT in `rez-core/src/identity/relayIdentity.js`; binding enforced at peer auth (hello/identify/challenge), peer directory, descriptor admission, DHT discovered refs, hosted-inbox registrations, and SDK auth/delegation; exit tests in `identity.relay-binding-enforcement.test.js` + `identity.node-identity.test.js`. Deploy dependency: the dev relays (r1–r3) must be redeployed WITHOUT a configured relayKeyId (the one-time identity reset) | Cleared |
| R2 Honest durable-record DHT | **PASS** (2026-08-15, re-audit remediated): `dht.rec_store`/`dht.rec_store.ack` protocol (P4), `DhtRecordPutResultV1` honest counters (local never counts; only acked stored/refreshed are holders), `DhtCandidateResolver` + reworked `DhtLookup` traverses verified discovered relays under dial/deadline/negative-cache budgets with the slot-burn defect fixed. Re-audit fixes: lookup deadlines RACE in-flight dials/queries (a never-settling query cannot hang the lookup; invalid clock fails loud), `putRecord` runs verify+local+lookup+acks under ONE total deadline with per-ack settled snapshots at expiry, node-global `budget-exhausted` deferrals are refunded and retained as references, and refreshes persist the moved retention window (holder survives restart). Exit tests in `routing.dht-lookup.test.js` (R2/R4 block), `routing.dht-candidate-resolver.test.js`, `routing.durable-record-protocol.test.js` (R6 block), `routing.durable-record-mesh.integration.test.js` | Cleared |
| R3 Canonical descriptor admission | **PASS** (2026-08-15, re-audit remediated): `RelayDescriptorV1` is the one validator (directory fn is a pure adapter; instance-expiry hole closed); `RelayStore.upsertDescriptor` is the admission choke point for every ingress incl. peer.bind (verdict now honored) and hydration (persisted config/self trust capped); one transport enum; reserved top-level `capabilities` must be empty; descriptor signing bytes carry a domain discriminator. Re-audit fixes: admission now VERIFIES the descriptor signature against the binding-validated node key (previously a tampered persisted row rehydrated as verified/gossip-eligible — signature ownership was split across ingress paths) and stores only the CANONICAL re-serialization (unsigned extra top-level fields can no longer be persisted or re-gossiped). Exit tests in `relay-descriptor-canonical.test.js` + `network.relay-store.admission.test.js` (re-audit R1 block) | Cleared |
| R4 Optional route-intelligence seam | **PASS** (2026-08-15): `RouteAdvisor` contract (50 ms deadline, permutation-validated, full fallback), off/shadow/advisory modes in `GatewayRelaySelector.selectRanked` (baseline `select()` untouched and pinned), `RouteOutcomeV1` + bounded in-process stream scoped to onion sends; exit tests in `gateway.route-advisor.test.js` + `gateway.route-outcome.test.js` | Cleared |
| R5 Optional subsystem composition | **PASS** (2026-08-15, re-audit remediated): `OptionalNodeServiceHost` at the `startRezNode` composition root — independent start, reverse-order bounded stop, namespaced status, failures isolated from mesh readiness and `/ready`; `MeshCoordinator` surface pinned unchanged. Re-audit fixes: isolation is TOTAL (non-`Error` rejections — strings/objects/null — are contained at every lifecycle hook and in `applyRouteAdvice`; previously they escaped into routing selection and startup) and `start()` is bounded like `stop()` (a hung optional service can no longer stall `startRezNode()` resolution; it is marked failed and still gets bounded stop cleanup). Exit tests in `app.optional-node-service-host.test.js` (re-audit R5 block) + `startRezNode.mesh-bootstrap.test.js` | Cleared |
| R6 Cross-runtime compatibility | **PASS** (2026-08-15, re-audit remediated): shared golden vectors (`rez-core/test/support/goldenVectors.js`) reproduced byte-for-byte by Node crypto AND browser WebCrypto (deterministic Ed25519, signatures identical, not merely verified); unknown-kind (`future-test-public-fact-v1`) records ride the generic path with an architecture test proving no kind-specific src; final no-extension gate in `architecture.no-extension.compat.test.js`. Re-audit fixes: the P7.1-required `DurableRecordV2` vectors now EXIST — direct-owner AND delegated (real capability cert, chain-committed signable bytes, owner-keyed slot) — deep-frozen and reproduced in rez-core (node:crypto), rez-sdk (WebCrypto), and through rez-node's live `verifyDurableRecordDual` ingress; the shared-keyspace inbox invariant is pinned by a FROZEN `inboxId → DHT position` literal instead of the prior self-referential check | Cleared |

## Definition of done

The prerequisite effort is complete when all readiness gates pass without introducing any Atlas feature and this statement is true:

> A future optional subsystem can publish small signed public facts, consume them locally, advise route selection, and fail independently—while the existing Rez mesh remains the sole transport authority and behaves exactly as it does when the subsystem does not exist.

## Related documents

- [Architecture](./architecture.md)
- [Architecture Guarantees](./ARCHITECTURE_GUARANTEES.md)
- [Protocol](./protocol.md)
- [Security](./security.md)
- [Security Posture](./SECURITY_POSTURE.md)
- [Storage Model](./STORAGE_MODEL.md)
- [Capability Model](./CAPABILITY_MODEL.md)
- [Deferred Roadmap](./ROADMAP.md)
- [Future Integrations](./FUTURE_INTEGRATIONS.md)
