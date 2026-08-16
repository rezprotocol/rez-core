# Future Integrations

## RezNet Interoperability and Collaboration Opportunities

**Status:** Deferred strategic note  
**Last reviewed:** 2026-08-15  
**Roadmap authority:** None. This document does not place integration work in scope or commit Rez to a partner, dependency, protocol, or schedule.

## Purpose

Rez does not need external integrations to prove RezNet or Rez Atlas. The current priority is to harden Rez's own substrate and prove a narrow, useful Atlas vertical end to end.

This document preserves a later opportunity: Rez may be more valuable as a privacy-preserving participant in a broader decentralized ecosystem than as an isolated network attempting to own every layer itself.

The collaboration proposition is not:

> Replace your network with RezNet.

It is:

> Use one narrow Rez capability where private transport, offline delivery, disposable participant compute, or local route intelligence complements what your network already does.

This distinction keeps integrations optional, technically bounded, and compatible with Rez's goal of becoming infrastructure that does not depend on its founder or any central operator.

## Strategic Position

Rez's potential role among adjacent projects is a combination that remains unusual:

- payload-agnostic private transport;
- claimant-controlled inboxes and store-and-forward delivery;
- signed, self-expiring public network knowledge;
- browser and native participation under one capability model;
- disposable compute that does not require participants to become permanent infrastructure;
- public observations with private intent, policy, and ranking kept local;
- durable publication without durable publisher presence;
- compensation for accepted, useful, verifiable service rather than raw activity;
- no requirement that a token holder, foundation, or network operator govern users; and
- no centralized service whose database becomes a surveillance target.

No single integration partner needs to adopt all of this. The practical opportunity is to expose these properties through small adapters and opaque signed envelopes.

## Non-Goals

Future integration work must not become an excuse to:

- pause the Atlas substrate work before Rez proves its own vertical;
- turn RezNet into a generic bridge that leaks metadata between networks;
- introduce a privileged Rez-operated gateway;
- make an external network Rez's identity authority or route-policy authority;
- require another project to adopt REZ, Rez handles, or Rez governance;
- import another network's application semantics into `rez-core`;
- copy a partner's protocol implementation into Rez;
- claim privacy properties that end at an observable bridge;
- maintain a global account-linking table across networks; or
- broaden paid services before useful work, verification, receipts, and settlement are real.

## Existing Rez Foundations

The following implemented seams make later interoperability credible. They are foundations, not a claim that an integration framework already exists.

| Existing foundation | Canonical owner | Possible later use |
|---|---|---|
| Signed `DurableRecordV2` construction and verification | `rez-core` | Small self-expiring manifests, service advertisements, observations, and bridge descriptors |
| Relay DHT protocol, lookup, value store, resolver, and announcer | `rez-node` | Replicated discovery of signed integration records |
| `MeshCoordinator` | `rez-node` | Lifecycle of relay participation, without making it a cross-network scheduler |
| `InboxRouter` and hosted inbox delivery | `rez-node` | Private asynchronous ingress and egress for integration payloads |
| `RCapability` and shared capability vocabulary | `rez-core` | Explicit authorization for publish, retrieve, bridge, or compute actions |
| `FileChunker` | `rez-core` | Deterministic chunk boundaries and hashes for manifests; not yet a durable storage system |
| Browser `WebCrypto` provider and encrypted IndexedDB-backed state | `rez-sdk` | Disposable browser participants and local secret custody |
| App-facing SDK and generic node/client dispatch | `rez-sdk` and `rez-node` | Integration adapters without coupling applications to node internals |

Important gaps remain. External integration work must not conceal them:

- DHT traversal, node identity cost, and acknowledged replication need hardening.
- Onion-routing guarantees and direct-delivery privacy modes need to match documented claims.
- Storage challenges require cryptographically complete request/response verification.
- Capabilities need enforceable usage and replay semantics for one-shot work.
- Atlas participant execution, work verification, observations, and receipts do not yet exist as a complete vertical.
- Bulk storage placement, repair, erasure coding, and proof of replication are not supplied by `FileChunker`.
- Trust-graph recognition and production economics must remain deferred until their inputs are real and adversarially tested.
- Rez does not yet have a canonical cross-network envelope or bridge threat model.

These gaps are reasons to defer integrations, not reasons to forget them.

## Integration Shapes

### 1. Private ingress and egress

Rez privately transports an opaque payload between a user and an adapter for another network. The external network continues to own its native objects and validation rules.

```text
local application
      |
      | private Rez route
      v
user-selected adapter
      |
      | external protocol
      v
partner network
```

The adapter must reveal that traffic to the partner network at some boundary. Rez must document exactly what the adapter and partner can observe rather than implying end-to-end Rez privacy beyond that point.

### 2. Rez control plane with external bulk storage

Rez carries a small signed manifest, capabilities, expiry, and retrieval information while an external network stores the bulk encrypted bytes.

```text
publisher appears briefly
        |
        | private publication request
        v
encrypted bulk object -> external durable store
        |
        v
signed short-lived Rez manifest -> Rez DHT replicas
        |
publisher disappears
        |
        v
authorized reader resolves manifest and retrieves object
```

This is the strongest near-term integration pattern because it respects Rez's current DHT as a small public control plane rather than pretending it is already a bulk content network.

### 3. External public state with private Rez coordination

Another network owns shared or replicated public application state. Rez carries invitations, capabilities, notifications, recovery hints, or targeted coordination that should not become public shared state.

### 4. Atlas work adapter

An external application submits a bounded deterministic task through Rez. Opt-in Atlas participants execute it, and Rez returns signed results and verification receipts.

This shape is later-phase work. It requires a real participant runtime, resource limits, deterministic task definitions, replay protection, independent verification, and accepted-work receipts before compensation is considered.

### 5. Dual-network application transport

An application understands one application-level signed object but can transport it over Rez or another privacy network. This is valuable for interoperability research and resilience without pretending the networks share routing, identity, or trust models.

## Candidate Projects

The assessments below are hypotheses to validate with maintainers. They are not statements of interest from the named projects.

### Autonomi

**Potential relationship:** Complementary durable storage.

Autonomi provides content-addressed encrypted storage, public and private data APIs, mutable pointers and registers, vaults, and node participation. Rez could provide private publication and retrieval transport while Autonomi supplies durable bulk persistence.

**Best proof of concept:**

1. A briefly connected Rez client encrypts and publishes an object.
2. A user-selected adapter stores the bulk object through Autonomi.
3. Rez publishes only a signed, expiring manifest containing the minimum retrieval material.
4. The publisher goes offline.
5. A second Rez client later resolves the manifest and retrieves the object.

**What Rez contributes:** Private ingress, claimant capabilities, offline delivery, signed manifests, and local access policy.

**What Rez could learn or reuse through an adapter:** Operational experience with content-addressed chunks, durable placement, mutable references, payment, and repair.

**Primary risks:** Storage-payment correlation, adapter observability, DataMap or address leakage, availability claims Rez cannot independently verify, and accidental dependence on one storage network.

**Assessment:** Strongest complementary opportunity and highest-value demonstration after the first Rez-native Atlas vertical.

Official references:

- [Autonomi developer documentation](https://docs.autonomi.com/developers)
- [Autonomi data storage model](https://docs.autonomi.com/developers/core-concepts/data-storage)
- [Autonomi client API](https://docs.autonomi.com/developers/api-reference/autonomi-client)

### Waku

**Potential relationship:** Messaging interoperability and browser transport experiments.

Waku exposes modular relay, store, filter, and light-push protocols and supports browser JavaScript clients as well as native nodes. A Rez-to-Waku adapter could carry an opaque application payload between ecosystems without either network replacing the other.

**Best proof of concept:** A capability-gated, user-operated bridge that maps one explicitly public Rez application channel to one Waku content topic and publishes a leakage report alongside the demo.

**What Rez contributes:** Private claimant-targeted delivery, offline inbox behavior, route privacy, and a path that does not require public application topics for Rez-native traffic.

**What Rez could learn:** Browser peer management, large public messaging deployments, interoperability conventions, and store/filter behavior.

**Primary risks:** Public topic names revealing intent, IP/topic correlation at the bridge, treating a peer-receipt acknowledgement as end delivery, spam, and creation of a centralized bridge service.

**Assessment:** Probably the fastest credible interoperability demo, but less strategically complete than the Autonomi storage combination.

Official references:

- [Waku protocol roles](https://docs.waku.org/learn/concepts/protocols/)
- [Waku content topics](https://docs.waku.org/learn/concepts/content-topics)
- [Waku JavaScript and Node guidance](https://docs.waku.org/build/javascript/run-waku-nodejs)

### Freenet

**Potential relationship:** Private coordination around replicated public application state.

Current Freenet applications separate shared contract state, local private delegates, and browser user interfaces. Rez could carry invitations, capability delivery, targeted notifications, or other asynchronous coordination that should remain outside public contract state.

**Best proof of concept:** A Freenet delegate emits an opaque notification request to a local Rez adapter; the intended Rez claimant receives it without a public recipient mapping being added to the Freenet contract.

**What Rez contributes:** Private asynchronous transport and offline destination semantics.

**What Rez could learn:** Untrusted replicated computation, commutative state synchronization, local secret zones, and browser-delivered decentralized applications.

**Primary risks:** Correlating a Rez claimant with a Freenet contract identity, unclear responsibility for message validity, duplicate state between the contract and Rez, and overloading Rez with Freenet application semantics.

**Assessment:** Architecturally interesting and potentially high value, after Rez has a stable signed public-object vocabulary.

Official references:

- [Freenet application architecture](https://freenet.org/build/manual/tutorial/)
- [Freenet browser interface](https://freenet.org/build/manual/components/ui/)

### Golem

**Potential relationship:** Private work transport or disposable browser participation around an existing compute market.

Golem already owns a provider/requestor market, agreements, execution environments, and payment. Rez should not duplicate those semantics merely to claim compatibility. A later adapter could instead test whether Rez privately routes offers, task inputs, or results, or whether Atlas browser participants can satisfy a narrowly defined workload class.

**Best proof of concept:** A deterministic, public, non-sensitive task sent through Rez to a Golem requestor adapter with independently verified output and an explicit metadata trace.

**Primary risks:** Conflicting settlement systems, unverifiable computation, payment identity correlation, mismatched browser execution assumptions, and a large expansion of Atlas scope.

**Assessment:** Worth revisiting only after Atlas has verified work and receipts. Not an early integration.

Official reference:

- [Golem network overview](https://docs.golem.network/docs/golem/overview)

### Veilid

**Potential relationship:** Protocol research, dual-transport applications, and mutual security review.

Veilid is the closest current networking peer: applications participate as Veilid nodes and use private routing and signed DHT records through a multi-platform API. That overlap makes it a valuable technical peer and a poor target for a replacement pitch.

**Best proof of concept:** The same application-level signed object sent over either Rez or Veilid, followed by a comparative report on observable metadata, offline behavior, browser participation, and route construction.

**What collaboration could provide:** Cross-project threat modeling, adversarial test cases, protocol lessons, and practical evidence about different privacy and DHT choices.

**Primary risks:** Building an abstraction so generic that it weakens both protocols, making false equivalence between security guarantees, and spending time on competitive feature parity.

**Assessment:** Strong philosophical and research alignment; direct adoption of RezNet is less likely than mutual learning or application-level interoperability.

Official references:

- [Veilid applications](https://veilid.gitlab.io/developer-book/apps/index.html)
- [Veilid API lifecycle](https://veilid.gitlab.io/developer-book/apps/api/index.html)
- [Veilid DHT concepts](https://veilid.gitlab.io/developer-book/concepts/dht.html)

### Holochain

**Potential relationship:** Private communication or discovery across application-specific networks.

Holochain's agent-centric applications keep private entries on the agent's source chain while publishing validated public data to application-specific DHTs. Rez might eventually carry private cross-application invitations or discovery without putting the initiating intent in an application DHT.

**Primary risks:** Conflicting identity models, unclear validation ownership, and duplicating application state across two agent-centric systems.

**Assessment:** A plausible specialist adapter, not a priority.

Official references:

- [Holochain application architecture](https://developer.holochain.org/concepts/2_application_architecture/)
- [Holochain DHT model](https://developer.holochain.org/concepts/4_dht/)

### IPFS and libp2p

**Potential relationship:** Optional content and transport adapters.

IPFS could act as a content-addressed storage target for public or encrypted objects, while libp2p is a source of transport and NAT traversal interoperability. Neither should be confused with guaranteed durable availability: IPFS persistence still depends on pinning or another retention arrangement.

**Primary risks:** Address and retrieval correlation, accidental publication of private material, equating content addressing with persistence, and introducing a large dependency surface into Rez core packages.

**Assessment:** Useful as adapter targets or comparative infrastructure, but not as canonical Rez dependencies.

Official references:

- [libp2p documentation](https://docs.libp2p.io/)
- [IPFS persistence and pinning](https://docs.ipfs.tech/concepts/persistence/)

### Session

**Potential relationship:** Application-level messaging interoperability experiments.

Session already operates a purpose-built messaging network with onion requests, recipient swarms, and temporary offline storage. Any collaboration is more likely to concern application interoperability or shared research than adoption of Rez routing.

**Primary risks:** Identity correlation, incompatible delivery and spam controls, and offering little value beyond what Session already owns.

**Assessment:** Philosophically adjacent but a low-probability early integration target.

Official references:

- [Session network](https://docs.getsession.org/session-network)
- [Session onion requests and message routing](https://docs.getsession.org/session-network/session-protocol/onion-requests-and-message-routing)

### GNUnet

**Potential relationship:** Research collaboration and protocol lineage.

GNUnet combines private overlay routing, a small-block DHT, decentralized naming, and anonymous file sharing. It is best treated as a mature source of design lessons and research questions rather than an immediate product adapter.

**Assessment:** High learning value; lower probability of near-term production integration.

Official references:

- [GNUnet CADET](https://docs.gnunet.org/v0.20.x/developers/cadet/cadet.html)
- [GNUnet DHT](https://docs.gnunet.org/v0.20.x/developers/dht/dht.html)
- [GNU Name System](https://docs.gnunet.org/master/users/gns.html)

## Recommended Order When Integrations Become Appropriate

This ordering is intentionally outside the active roadmap.

1. **Autonomi storage adapter experiment** — highest complementary value and closest to the durable-publication mission.
2. **Waku bridge experiment** — smallest visible interoperability surface and a useful metadata-leakage exercise.
3. **Freenet private-notification experiment** — tests the public-state/local-intent separation across networks.
4. **Veilid dual-transport comparison** — research and threat-model value after Rez's guarantees are stable enough to compare honestly.
5. **Golem or another compute-market adapter** — only after Atlas work verification and receipts exist.
6. **Specialist Holochain, IPFS/libp2p, Session, or GNUnet work** — driven by a concrete user need or maintainer collaboration, not completeness.

## Activation Gates

No external integration should enter implementation scope until all of the following are true:

- Rez's first narrow Atlas vertical works across browser and Node participants.
- The DHT and routing hardening required by that vertical is complete and tested.
- A canonical signed integration envelope or manifest exists in `rez-core` because at least two Rez packages genuinely share it.
- The node owns server-side adapter RPC records and validation; the SDK sends plain wire objects and does not import node records.
- A written threat model identifies what the user, Rez relays, adapter, partner network, storage providers, observers, and payment systems can learn.
- Metadata leakage is tested, not merely described.
- The integration can be run by users or independent operators without a mandatory Rez-operated service.
- Failure of the partner network does not corrupt Rez identity, authorization, or local policy.
- The proof of concept answers one real product question with measurable success criteria.
- A partner maintainer or real application user has expressed a need; architectural admiration alone is insufficient.

## Required Integration Artifacts

Every future integration should produce:

1. **Adapter boundary specification** — inputs, outputs, canonical owner, and failure behavior.
2. **Metadata exposure matrix** — knowledge available to each actor before, during, and after the operation.
3. **Signed record specification** — only if a shared signed object is genuinely necessary.
4. **Capability and replay model** — who may invoke the adapter, how often, and under what expiry.
5. **Receipt model** — what was requested, accepted, attempted, verified, and delivered.
6. **Degraded-mode behavior** — what happens when either network is unavailable or inconsistent.
7. **Operator-independence proof** — how another person runs the adapter without Rez-controlled credentials or infrastructure.
8. **Removal plan** — how the optional integration can disappear without breaking RezNet.

## Privacy and Security Invariants

Integrations must preserve these invariants:

- Application payload meaning remains opaque to Rez routing infrastructure.
- A bridge receives no more plaintext or identity material than its explicit function requires.
- Private handles, contacts, destinations, search terms, and route rankings are never converted into public topic names or DHT keys.
- Cross-network identities are not globally linked by default.
- Route selection and application intent remain local unless a user explicitly publishes them.
- Public network knowledge is signed, bounded in size, scoped, and self-expiring.
- An acknowledgement from a bridge or first external peer is not represented as destination delivery.
- External durability claims are not represented as Rez-verified replication without a valid proof.
- Adapter discovery does not create a fixed set of privileged gateways.
- No integration creates a central analytics, abuse, indexing, or moderation database as a protocol dependency.
- Payment is not required for core person-to-person messaging.
- Economic rewards, if any, follow accepted and verifiably useful service rather than self-reported activity.

## The Collaboration Demonstration

The clearest future demonstration combines the principles above:

> A briefly connected browser publishes an opaque signed object through a private Rez route. Disposable participants perform bounded verifiable work. Bulk encrypted content is placed on an external durable network. Rez replicates only the minimum signed retrieval knowledge. The publisher disappears. A permitted recipient later retrieves and verifies the object without Rez, the storage network, or a mandatory central operator learning the complete relationship and intent graph.

That demonstration is more persuasive than a broad interoperability claim because it proves a human outcome: durable publication without durable publisher presence.

## Stop Conditions

An integration should be rejected or paused if it requires:

- a permanent centrally operated Rez gateway;
- a global identity-mapping service;
- publication of private intent for discovery;
- weakening Rez's capability or signature checks;
- moving partner-specific semantics into the core protocol;
- treating unverifiable storage or compute as completed work;
- mandatory adoption of another project's token, account system, or governance;
- dependence on an unauditable remote API;
- surveillance or behavioral indexing as an abuse-control prerequisite; or
- delaying the current Rez/Atlas proof in order to appear interoperable.

## Decision Record

The present decision is:

> Preserve future integration opportunities, but do not pursue them until Rez has proved its own narrow Atlas vertical and can state its privacy guarantees honestly at every boundary.

When that gate is reached, start with one complementary experiment—most likely private Rez publication backed by Autonomi storage—rather than a general partnership program.

## Related Rez Documents

- [Architecture](./architecture.md)
- [Protocol](./protocol.md)
- [Security](./security.md)
- [Security Posture](./SECURITY_POSTURE.md)
- [Storage Model](./STORAGE_MODEL.md)
- [Capability Model](./CAPABILITY_MODEL.md)
- [Architecture Guarantees](./ARCHITECTURE_GUARANTEES.md)
- [Deferred Roadmap](./ROADMAP.md)
- [Technical White Paper](./WHITEPAPER.html)
- [Token White Paper](../../rez-token-whitepaper.html)
