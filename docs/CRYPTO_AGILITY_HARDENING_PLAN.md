# Rez Crypto-Agility Hardening Plan

**Status:** Proposed implementation and audit plan  
**Audit snapshot:** 2026-08-15  
**Applies to:** `rez-core`, `rez-sdk`, `rez-node`, and compatibility coverage in `rez-chat`  
**Canonical owner:** `rez-core` owns shared protocol, cryptographic constructions, suite vocabulary, and signed/shared records. `rez-sdk` and `rez-node` own their existing runtime responsibilities and platform implementations.  
**Readiness:** **8/30 — foundation present; suite migration is not yet safe**

## 1. Executive decision

Rez has a useful platform seam, but it is not crypto-agile end to end.

`RCryptoProvider`, `NodeCryptoProvider`, and `BrowserCryptoProvider` already separate much of the Node/WebCrypto execution detail from core protocol code. The current encrypted-envelope suite label is also included in authenticated AAD. Those are valuable foundations.

The current protocol constructions nevertheless select algorithms directly:

- X3DH-v2 directly invokes X25519, Ed25519-shaped `sign`/`verify`, and HKDF-SHA256;
- the Double Ratchet directly invokes DH plus fixed HKDF-SHA256 derivations;
- envelope encryption directly invokes the v1 HKDF/AES-256-GCM construction;
- onion v2 directly invokes X25519, HKDF-SHA256, and AES-256-GCM;
- identity and relay identifiers are derived from Ed25519 public-key encodings;
- session persistence does not bind stored state to a suite;
- no authenticated suite negotiation, downgrade floor, suite registry, or suite retirement policy exists.

Therefore the design goal is:

> Adding an already-supported cryptographic suite should primarily mean adding classes, registering one immutable suite definition, and adding vectors—not editing X3DH, ratchet, envelope, onion, identity, transport, and application code in scattered places.

Adding a genuinely new primitive may still require one bounded implementation in each supported platform provider. That exception does not permit protocol selection logic to leak into platform providers.

This plan first wraps and proves the current construction byte-for-byte, then adds suite identity and persistence, then authenticated negotiation and downgrade resistance, and only then permits a hybrid post-quantum suite to be considered.

## 2. Normative constraints

Every ticket in this plan must preserve the following repository rules:

- JavaScript only; modern ESM, `async`/`await`, and classes. No TypeScript.
- One class per file.
- `#privateField` / `#privateMethod()` for private members and `_protectedMethod()` for protected behavior.
- No optional chaining.
- No new dependency, vendored implementation, or copied external code without explicit approval.
- `rez-core` remains dependency-free.
- Every new structured value or wire value is an `RRecord` subclass. Classes accept records rather than new ad hoc object shapes.
- Shared signed records and protocol vocabulary belong to `rez-core`.
- Node/client RPC request and response records, plus server validation, belong to `rez-node`.
- Browser-facing orchestration remains in `rez-sdk`; node/relay lifecycle and enforcement remain in `rez-node`.
- `rez-chat` consumes `rez-sdk` and does not import `rez-core` directly.
- Transports remain payload-agnostic and dispatch generically. No suite-specific transport methods or directive lists.
- No production symbol may be named for an optional higher-level product or application. This is generic Rez hardening.
- No silent fallback, silent failure, or skipped readiness gate.
- Cryptographic correctness coverage uses real cryptography, not mocked primitives.

The current package ownership is documented in [architecture.md](./architecture.md#boundaries) and [ARCHITECTURE_GUARANTEES.md](./ARCHITECTURE_GUARANTEES.md#41-protocolcrypto-primitive-ownership-stays-in-core). `rez-core` currently has no package dependencies ([package.json](../package.json#L14)).

## 3. Scope

### 3.1 In scope

1. Inventory every security-relevant algorithm choice, algorithm identifier, key encoding, KDF label, wire version, persisted version, and direct platform-crypto call in production Rez code.
2. Preserve and clarify the `RCryptoProvider` platform boundary.
3. Add a separate protocol suite, registry, and local policy boundary.
4. Represent suite offers, selections, transcripts, policies, persisted suite bindings, and future key transitions with `RRecord` classes.
5. Bind suite selection to session handshakes, encrypted envelopes, ratchet state, prekey material, onion keys/layers, and authenticated transcripts as appropriate.
6. Define downgrade-resistant peer-session and relay-onion suite selection.
7. Define mixed-version behavior, suite introduction, preference, requirement, retirement, and emergency disablement.
8. Preserve browser/Node interoperability through shared known-answer and end-to-end vectors.
9. Identify the account, device, relay, handle, descriptor, durable-record, capability, receipt, and keystore consequences of identity-signature migration.
10. Remove or quarantine duplicate crypto orchestration paths after proving the canonical owner.
11. Update canonical security documentation where it disagrees with current code.
12. Produce release gates suitable for an internal adversarial review and later external cryptographic audit.

### 3.2 Explicit non-goals

- Selecting or implementing ML-KEM, ML-DSA, SLH-DSA, or another post-quantum primitive in the abstraction phases.
- Adding a cryptographic dependency without a separate approval and dependency review.
- Claiming post-quantum security before a concrete hybrid construction, dependency, vectors, interop matrix, and external review exist.
- Rewriting the current protocol, replacing Double Ratchet wholesale, or changing current wire bytes during the compatibility phases.
- Negotiating arbitrary independent algorithms on the wire. Peers select an audited suite ID, not a user-assembled combination of KEM, signature, KDF, AEAD, and hash.
- Making transports inspect or understand cryptographic suite payloads.
- Changing chat semantics, delivery semantics, routing authority, onion hop validation, inbox behavior, or application payloads.
- Solving endpoint compromise, global traffic analysis, key transparency, recovery UX, or JavaScript memory zeroization in this plan.
- Treating TLS cipher-suite configuration, at-rest database encryption, password KDFs, economic-chain signing, and E2EE protocol suites as one interchangeable policy domain. They are inventoried together but migrate under separate policies.
- Preserving broken or undocumented downgrade behavior for compatibility.

## 4. Verified current state

This section records facts observed in the 2026-08-15 checkout. It is an audit baseline, not a target architecture.

### 4.1 Existing foundations to preserve

| Area | Verified implementation | Assessment |
|---|---|---|
| Platform provider base | `RCryptoProvider` declares random, SHA-256, HKDF-SHA256, AEAD, signing, seeded signing-key, and DH operations ([source](../src/crypto/RCryptoProvider.js#L3-L42)). | Useful execution seam, but algorithm-specific and incomplete: both concrete providers implement `generateSigningKeyPair()`, while the abstract class does not declare it. |
| Node provider | `NodeCryptoProvider` implements SHA-256, HKDF-SHA256, AES-256-GCM, Ed25519, and X25519 using `node:crypto` ([source](../../rez-node/src/crypto/NodeCryptoProvider.js#L11-L180)). | Real platform implementation; not a suite or policy object. |
| Browser provider | `BrowserCryptoProvider` implements the corresponding WebCrypto operations ([source](../../rez-sdk/src/e2ee/BrowserCryptoProvider.js#L9-L194)). | API shape broadly matches Node; no shared full-suite golden-vector gate was found. |
| X3DH identity binding | `X3DHService` verifies signed-prekey and identity-DH bindings before DH, rejects all-zero DH outputs, and uses X3DH-v2 derivation ([source](../src/services/X3DHService.js#L32-L58), [initiator](../src/services/X3DHService.js#L147-L232), [receiver](../src/services/X3DHService.js#L263-L319)). | Strong current construction; direct primitive selection prevents suite substitution. |
| Ratchet | `RatchetService` takes a `dhAlg` constructor option but directly uses the provider and fixed KDF helpers ([source](../src/services/RatchetService.js#L39-L105)); root and chain KDF labels are fixed ([root](../src/crypto/ratchet/KdfRoot.js#L4-L19), [chain](../src/crypto/ratchet/KdfChain.js#L4-L18)). | `dhAlg` is not suite negotiation. The construction is partly parameterized and otherwise fixed. |
| Encrypted envelope | `EncryptedEnvelopeV1` accepts only `HKDF-SHA256/AES-256-GCM` ([source](../src/objects/encryption/EncryptedEnvelopeV1.js#L11-L29)). The suite label and ratchet header are included in AEAD AAD ([source](../src/codec/encryption/buildAadBytesV1.js#L23-L40)). | The current fixed label is authenticated, which must be preserved. It is not an extensible suite registry. |
| Onion v2 | `OnionLayerAeadV2` directly performs X25519, the v2 KDF, and AES-256-GCM ([source](../src/crypto/onion/OnionLayerAeadV2.js#L21-L85)). | Versioned and bounded, but algorithm-fixed. |
| Onion key lifecycle | `OnionKeyRotator` creates X25519 keys, advertises active/draining records, and revokes expired keys ([source](../../rez-node/src/relay/OnionKeyRotator.js#L7-L12), [generation](../../rez-node/src/relay/OnionKeyRotator.js#L97-L123), [rotation](../../rez-node/src/relay/OnionKeyRotator.js#L142-L182)). | Rotation machinery exists; key records do not identify an algorithm or suite. |
| Session persistence | `SecureSessionRecord`, `RatchetState`, and node serialization persist keys and counters without a suite ID ([session](../src/objects/ratchet/SecureSessionRecord.js#L16-L51), [state](../src/objects/ratchet/RatchetState.js#L20-L93), [node persistence](../../rez-node/src/services/sessions/PersistentSessionManager.js#L256-L267)). | A restored session cannot resolve a suite explicitly. |
| Account identity | Account IDs are SHA-256 fingerprints of the current public-key bytes ([source](../src/identity/Identity.js#L25-L35)); key generation is explicitly Ed25519 ([source](../src/identity/Identity.js#L50-L67)). | Replacing the root key changes the account ID under current semantics. |
| Relay identity | Relay IDs and compatibility node IDs are derived from an Ed25519 SPKI encoding ([source](../src/identity/relayIdentity.js#L1-L15), [derivation](../src/identity/relayIdentity.js#L78-L103)). | Replacing the root key changes relay identity and DHT position under current semantics. |
| Relay signatures | `RelayDescriptorV1` accepts only `ed25519` signatures and V1 onion-key records ([source](../src/objects/relay/RelayDescriptorV1.js#L44-L68), [record](../src/objects/relay/RelayDescriptorV1.js#L207-L247)). | A signature-suite migration requires an additive descriptor version. |
| Wire and object model | Newer contract families use `RRecord`, but core crypto/session/onion wire-adjacent classes still include `RObject`, `RSerializable`, and plain nested objects, including X3DH records, ratchet headers, encrypted envelopes, and relay descriptors. | New suite work must not extend the legacy shape pattern. Touched wire values need an explicit RRecord migration decision. |
| Payload generality | `SecureChannelManager` describes arbitrary payload encryption and composes X3DH, ratchet, and codecs in core ([source](../src/e2ee/SecureChannelManager.js#L27-L53)). | The suite layer belongs below applications and above transports. |

### 4.2 Gaps confirmed by source inspection

The following are current gaps, not speculative future requirements:

1. **There is no protocol-suite abstraction.** No `RCryptoSuite`, immutable suite registry, or suite-policy class exists.
2. **There is no authenticated suite negotiation.** The peer handshake wire type is fixed at `x3dh.handshake.v2`; no offer or selection record exists ([source](../src/e2ee/E2eeHandshakePacketV1.js#L7-L37)).
3. **There is no downgrade policy or remembered peer floor.** Unknown suites are rejected by fixed constructors, but two suite-capable peers cannot prove that a stronger mutual option was not stripped.
4. **The envelope suite string is not a complete suite identity.** It names only KDF/AEAD while the handshake, ratchet DH, signature, key formats, and transcript rules live elsewhere.
5. **Provider capability discovery is absent.** A suite cannot be validated against a runtime before use.
6. **The provider base contract is incomplete.** `generateSigningKeyPair()` is used and implemented by both concrete providers but is absent from `RCryptoProvider`.
7. **Algorithm choices are scattered.** Production references to X25519, Ed25519, HKDF, AES-GCM, direct `node:crypto`, and direct WebCrypto exist outside the two main provider classes. Some are appropriate local-storage, identity-derivation, randomness, or runtime concerns; the audit must classify them instead of assuming that all crypto already crosses one seam.
8. **Suite identity is absent from persisted ratchet state.** Key length or wire version must not become an implicit suite discriminator.
9. **Identity replacement is coupled to identifier replacement.** Account and relay root-key rotation cannot be treated as a normal session-suite swap.
10. **No shared Node/browser full-suite vector gate was found.** Each runtime has real crypto coverage, but parity is inferred from API shape and compatible behavior rather than one canonical vector corpus consumed by both.
11. **Duplicate SDK source copies require resolution.** `rez-sdk/src/e2ee/index.js` re-exports the canonical core E2EE classes, while local `SecureChannelManager.js` and `X3DHKeyExchange.js` source copies remain. Import scanning found production use through the index/core exports, not the local copies. Delete only after an architecture test proves they are unreachable.
12. **Security documentation has drift.** `security.md` describes an older DH3/DH4-only `rez-x3dh-v1` derivation ([source](./security.md#x3dh-session-establishment)), while `X3DHService` implements DH1/DH2/DH3/[DH4] with `rez-x3dh-v2`. Documentation must not be used as proof until reconciled.

### 4.3 Current readiness scorecard

Scoring rubric: **0** absent; **1** partial/ad hoc; **2** implemented but not fully proven for migration; **3** implemented and release-gated.

| Capability | Score | Evidence and reason |
|---|---:|---|
| Platform execution seam | 2/3 | Abstract and two real providers exist, but the abstract contract is incomplete and bypasses need classification. |
| Suite composition and immutable registry | 0/3 | No suite classes or registry. |
| Authenticated offer/selection | 0/3 | Fixed handshake; no negotiation transcript. |
| Downgrade resistance | 1/3 | Current fixed suite label is authenticated in envelope AAD, but no multi-suite downgrade defense exists. |
| Wire versioning and suite binding | 2/3 | Versioned envelopes/handshakes/onions exist and the envelope label is authenticated; suite identity does not cover the whole construction. |
| Persisted session binding and migration | 0/3 | No suite ID in session or ratchet state. |
| Identity and root-key evolution | 1/3 | Signed prekeys, device authority epochs, and onion keys rotate; account and relay root identities remain key-derived and algorithm-fixed. |
| Browser/Node parity | 1/3 | Matching real provider operations exist; shared suite vectors and capability gates are missing. |
| Registration-first extension goal | 0/3 | A new construction currently requires scattered edits. |
| Adversarial/mixed-version release gates | 1/3 | Strong real-crypto tests exist, but no suite/downgrade/retirement matrix. |
| **Total** | **8/30** | **Ready to begin hardening; not ready to introduce or retire a suite.** |

## 5. Required architectural separation

### 5.1 Platform crypto provider: how an operation executes here

`RCryptoProvider` remains the runtime boundary.

Responsibilities:

- access trustworthy platform randomness;
- execute primitive operations supported by that runtime;
- import/export canonical key encodings;
- report supported primitive IDs without exaggeration;
- fail closed for unsupported algorithms, invalid keys, invalid sizes, and authentication failures;
- contain Node/WebCrypto differences.

It must not:

- select a Rez protocol suite;
- apply local suite preference or retirement policy;
- parse peer suite offers;
- decide downgrade behavior;
- define X3DH, ratchet, envelope, onion, identity-transition, or transport semantics;
- silently emulate an unsupported primitive with a weaker one.

The existing algorithm-specific provider methods may remain during compatibility work. The minimum provider hardening is to make the abstract contract truthful and add bounded capability reporting. A generic “algorithm bag” API is not required and must not replace typed scheme classes with string switches throughout core.

### 5.2 Protocol crypto suite: what construction Rez uses

Suite classes are owned by `rez-core`. They compose audited scheme and construction classes into immutable, versioned meanings.

Responsibilities:

- identify one exact protocol construction with one immutable suite ID;
- declare the primitive capabilities it requires;
- compose handshake, ratchet, KDF, AEAD, signature, hash, key encoding, transcript, and onion behavior for its domain;
- produce and consume the correct `RRecord` wire/state types;
- bind domain-separation labels and canonical transcript rules;
- reject use when the platform provider lacks required capabilities.

It must not:

- import `node:crypto`, browser globals, or platform packages;
- perform runtime discovery outside provider capability checks;
- consult mutable global policy while processing an established session;
- expose arbitrary primitive combinations to peers.

### 5.3 Suite policy: what this node/client is allowed to use now

Policy is separate from both provider and suite implementation.

Responsibilities:

- define ordered allowed suites per domain (`peer-session`, `relay-onion`, `identity-signature`, and separately scoped local-storage domains);
- define disabled and retired suite IDs;
- define compatibility windows and minimum accepted policy generation;
- choose from an authenticated intersection deterministically;
- remember a peer/session downgrade floor where required;
- require explicit operator/user action for exceptional downgrade.

Policy must never create a suite, reinterpret a suite ID, or claim support that the provider cannot execute.

### 5.4 Composition model

```text
peer or relay wire records
        |
        v
RCryptoSuitePolicy -----> RCryptoSuiteRegistry
        |                         |
        | chooses one             | resolves immutable ID
        v                         v
RSessionCryptoSuite / ROnionCryptoSuite / RIdentityCryptoSuite
        |
        | composes protocol constructions and typed schemes
        v
RHandshakeConstruction, RRatchetConstruction, RKeyAgreementScheme,
RSignatureScheme, RKdfScheme, RAeadScheme, RHashScheme
        |
        | executes primitives
        v
RCryptoProvider
      /   \
     v     v
NodeCryptoProvider    BrowserCryptoProvider
```

An established session stores its selected immutable suite ID. It does not repeatedly consult current preference policy, so a live policy update cannot silently change keys or wire behavior mid-session.

## 6. Candidate abstractions and classes

Names are candidates; responsibilities and boundaries are requirements. Every class gets its own file.

### 6.1 Minimal provider-contract additions (`rez-core` interface; runtime implementations in current owners)

| Candidate | Owner | Required responsibility |
|---|---|---|
| `RCryptoProvider` extension | `rez-core` | Declare every operation relied upon by core, including `generateSigningKeyPair()`, and declare a capability query. Keep existing methods for compatibility. |
| `CryptoProviderCapabilitiesV1 extends RRecord` | `rez-core` | Immutable, bounded primitive-ID set returned by providers; never sent as a peer claim without separate authentication. |
| `NodeCryptoProvider` | `rez-node` | Execute approved primitives through Node APIs and truthfully report capability IDs. |
| `BrowserCryptoProvider` | `rez-sdk` | Execute the same approved primitives through WebCrypto or an explicitly approved browser implementation and report the same canonical IDs. |

If a future KEM or signature primitive is unavailable in native Node or WebCrypto, dependency approval and a separate supply-chain/security review are prerequisites. Provider capability reporting must return unsupported until real implementation and vectors pass.

### 6.2 Typed scheme classes (`rez-core`)

| Abstract class | Current concrete adapter | Purpose |
|---|---|---|
| `RHashScheme` | `RSha256HashScheme` | Hash operation plus canonical ID and output rules. |
| `RKdfScheme` | `RHkdfSha256Scheme` | HKDF execution and label/input/output contracts. |
| `RAeadScheme` | `RAes256GcmScheme` | AEAD key/nonce/tag rules. |
| `RSignatureScheme` | `REd25519SignatureScheme` | Key generation/import, sign, verify, and encoding rules. |
| `RKeyAgreementScheme` | `RX25519KeyAgreementScheme` | DH key generation/derivation, encoding, and contributory checks. |

Scheme classes delegate primitive execution to `RCryptoProvider`. They do not own wire negotiation or suite policy.

### 6.3 Protocol-construction classes (`rez-core`)

| Abstract class | Current concrete construction | Purpose |
|---|---|---|
| `RHandshakeConstruction` | `RX3dhV2Construction` | Prekey creation, offer-bound initiation/response, transcript inputs, shared-secret derivation. |
| `RRatchetConstruction` | `RDoubleRatchetV1Construction` | Root/chain steps, header semantics, skipped-key identity, and message-key derivation. |
| `REnvelopeProtection` | `REncryptedEnvelopeV1Protection` | Envelope record, AAD, nonce derivation, seal/open behavior. |
| `ROnionLayerConstruction` | `ROnionLayerV2Construction` | Onion key compatibility, per-layer shared secret, KDF/AAD, seal/open behavior. |
| `RIdentitySignatureConstruction` | `REd25519IdentitySignatureV1` | Existing signed-object verification rules; intentionally separate from session confidentiality. |

The first pass may adapt existing services behind these interfaces rather than rewrite them. The compatibility requirement is current bytes and outcomes, not new names at any cost.

### 6.4 Suite, registry, and policy classes (`rez-core`)

| Candidate | Responsibility |
|---|---|
| `RCryptoSuite` | Abstract immutable suite identity, domain, required provider capabilities, record versions, and construction composition. |
| `RSessionCryptoSuite` | Typed session-suite contract. |
| `ROnionCryptoSuite` | Typed onion-suite contract. |
| `RIdentityCryptoSuite` | Typed signed-identity/artifact suite contract. |
| `RClassicSessionSuiteV1` | Exact current X3DH-v2 + Double Ratchet v1 + HKDF-SHA256 + AES-256-GCM + Ed25519-authenticated handshake behavior. |
| `RClassicOnionSuiteV2` | Exact current onion v2 X25519 + HKDF-SHA256 + AES-256-GCM behavior. |
| `REd25519IdentitySuiteV1` | Exact current identity/signature behavior. |
| `RCryptoSuiteRegistry` | Constructor-injected, immutable mapping of suite ID to suite instance; rejects duplicates and unknown domains. No global mutable singleton. |
| `RCryptoSuitePolicy` | Resolves allowed/preferred/retired suites from a validated policy record plus provider capabilities. |
| `CryptoSuitePolicyV1 extends RRecord` | Local ordered allowlists, disabled IDs, minimum policy generation, compatibility mode, and explicit downgrade authorization. |

### 6.5 Shared records (`rez-core`)

| Candidate record | Use |
|---|---|
| `CryptoSuiteOfferV1` | Bounded ordered suite IDs, protocol domain, policy generation, offer nonce, issuer identity/key epoch, issue/expiry times. |
| `CryptoSuiteSelectionV1` | Selected suite, hashes of both authenticated offers, selection nonce, identities, and policy generation. |
| `CryptoNegotiationTranscriptV1` | Canonical transcript inputs covered by signatures and key confirmation. |
| `CryptoPeerSuiteFloorV1` | Local remembered peer identity, domain, strongest accepted policy rank/generation, evidence hash, time, and explicit-reset state. |
| `CryptoKeyDescriptorV1` | Scheme ID, key ID, canonical encoding ID, public bytes, validity, and purpose. Never contains private material. |
| `IdentityKeySetV1` | Candidate future identity epoch containing bounded signing/agreement keys and validity. Must not be introduced before the identity ADR. |
| `IdentityKeyTransitionV1` | Candidate future cross-certification from old epoch to new epoch, with old/new signatures according to policy. Must not be introduced before the identity ADR. |

Node/client RPC wrappers remain node-owned if a later management endpoint is needed. The shared signed offer/selection/transcript vocabulary stays in core.

## 7. Suite identity and protocol versioning

### 7.1 Immutable, domain-scoped suite IDs

Use opaque, lowercase, bounded IDs whose meaning never changes, for example:

```text
rez.session.classic.v1
rez.onion.classic.v2
rez.identity.ed25519.v1
```

These are illustrative IDs, not authorization to ship them before the registry ticket fixes the canonical spelling.

Rules:

1. A suite ID maps to exactly one construction forever.
2. Suite IDs are scoped by domain. A session suite cannot be accepted as an onion or identity suite.
3. Registry entries are immutable after construction.
4. No aliases are accepted on wire.
5. Unknown IDs fail closed and are rate/size bounded before expensive crypto.
6. Algorithm names inside existing records are not treated as independent negotiation.
7. A changed transcript, label, key encoding, hybrid combiner, record schema, or confirmation rule requires a new suite ID and usually a new wire record version.
8. Security strength ordering lives in local signed/configured policy metadata, not lexicographic suite names or key length.

### 7.2 Preserve legacy bytes

The current `EncryptedEnvelopeV1.suite = "HKDF-SHA256/AES-256-GCM"` remains exactly that on v1 wire. Internally the classic adapter may map this closed legacy label to the classic session suite, but the old string must not be reinterpreted as permission to vary handshake, ratchet, or signatures.

`x3dh.handshake.v2`, `rez.encrypted.v1`, `RatchetHeaderV1`, `OnionPacketV2`, `OnionKeyRecordV1`, and `RelayDescriptorV1` remain immutable compatibility formats.

New fields are not appended to a signed or canonical legacy record unless its compatibility contract explicitly allows them and byte goldens prove safety. Prefer additive V2/V3 record classes.

### 7.3 Session v3 outline

A new multi-suite handshake must be a new wire type, tentatively `rez.session.handshake.v3`, with this state machine:

1. Responder publishes a signed, bounded `CryptoSuiteOfferV1` with its prekey bundle.
2. Initiator verifies the responder identity binding, expiry, offer signature, suite domain, registry membership, and local policy before any expensive KEM/DH work.
3. Initiator returns its own authenticated offer plus `CryptoSuiteSelectionV1` choosing the deterministic highest local-policy suite in the authenticated intersection.
4. Responder recomputes the intersection and selection. It rejects a mismatch; it does not retry weaker.
5. Both sides bind hashes of both offers, the selection, identities/key epochs, prekey identifiers, nonces, protocol context, and selected suite ID into the KDF transcript.
6. Both sides prove key confirmation under the derived secret before the session becomes usable.
7. The selected suite ID is stored in `SecureSessionRecordV2`/`RatchetStateV2` and authenticated in every new envelope header/AAD.

An attacker changing either offer or the selection must cause signature, transcript, or key-confirmation failure.

### 7.4 Envelope and ratchet versioning

- Existing sessions continue to emit `rez.encrypted.v1` with current bytes.
- Negotiated sessions use an additive encrypted-envelope record whose `suiteId` is authenticated in AAD.
- A session suite is immutable for that session. Upgrade requires a new authenticated handshake and new session ID.
- Ratchet headers do not independently choose algorithms. They carry suite-required key material and counters only.
- Persisted sessions store suite ID, suite-state version, key encoding IDs, and negotiation transcript hash.
- Legacy persisted records with no suite ID map only to the exact legacy classic adapter. No key-size or `dhAlg` inference.
- If the classic adapter is retired by policy, legacy state is readable only for an explicitly bounded migration/export path; it is not silently resumed.

### 7.5 Onion versioning

- `OnionKeyRecordV1` and onion v2 retain their exact current X25519 meaning.
- A new onion-key record version carries `suiteId`, key-encoding ID, key bytes, validity, and status.
- A new signed relay descriptor version advertises a bounded set of onion suites and keys. The descriptor signature covers them.
- The path builder chooses one suite supported by every hop or fails. It does not mix unreviewed per-hop primitives under one packet version.
- The packet/layer version authenticates suite identity and key ID. A relay never infers a suite from key length.
- Active/draining/revoked lifecycle remains the node-owned mechanism; new suite keys can overlap old keys during rollout.

## 8. Downgrade resistance

Downgrade resistance is a protocol invariant, not a UI warning.

### 8.1 Required invariants

1. Both peers' complete bounded offers are authenticated.
2. The selection is deterministic from the authenticated intersection and local policy.
3. Offer hashes and selected suite are bound into shared-secret derivation and key confirmation.
4. Unknown, malformed, expired, duplicate, overlong, wrong-domain, or unregistered suite IDs fail before expensive work.
5. Negotiation failure never automatically retries with a weaker suite in the same flow.
6. An established session cannot change suite in place.
7. A previously stronger peer relationship cannot silently fall below its remembered local floor.
8. Policy emergency-disable overrides preference but is explicit, auditable, and fail-closed.
9. Legacy fallback is permitted only during a declared compatibility phase and only when the peer has no authenticated evidence of stronger support.
10. Relays cannot alter endpoint offers or selections because they carry opaque authenticated bytes.

### 8.2 Remembered floor

`CryptoPeerSuiteFloorV1` records the strongest successful suite rank under the local policy generation for a stable peer identity. It is local security state, not a global reputation fact.

The floor must support:

- expiry/re-evaluation when policy generations change;
- account/device distinctions so one old device does not silently lower all devices;
- explicit operator/user reset with a receipt in local logs;
- signed peer capability withdrawal only if policy permits it;
- recovery UX that says why communication is blocked rather than silently falling back.

No universal numeric “security level” is encoded in suite IDs. Policy owns the ordering.

### 8.3 Downgrade test matrix

At minimum test:

- strip stronger suite from initiator offer;
- strip stronger suite from responder offer;
- replace selected suite;
- reorder offers;
- replay an expired offer;
- replay a selection under a new nonce/session/peer;
- use a valid offer in the wrong domain;
- advertise support the local provider lacks;
- fail strong-suite execution after selection and attempt weaker retry;
- reconnect after a stronger suite was previously pinned;
- explicit authorized downgrade during emergency disable;
- legacy peer with no stronger authenticated offer;
- two modern peers with a stripping intermediary;
- descriptor advertises modern onion key but path reply substitutes legacy key.

## 9. Identity and key-rotation implications

Session confidentiality agility and identity-signature agility are related but not interchangeable.

### 9.1 Current coupling

- `rez:acct:*` derives from the current account signing public-key bytes.
- `rez:relay:*` and `nodekey:*` derive from the current relay Ed25519 public-key bytes.
- Handle ownership, device authority, capabilities, durable records, inbox claims/delegations, relay descriptors, peer auth, receipts, and settlement attestations contain Ed25519-specific assumptions or key-shaped IDs.
- Signed prekeys and onion keys rotate today, but those rotations remain anchored to stable Ed25519 root keys.

Consequences:

1. Replacing an Ed25519 root with a PQ key changes current self-certifying identifiers unless a new identity model is adopted.
2. Merely adding a PQ KEM to X3DH can improve recorded-session confidentiality while authentication still depends on Ed25519.
3. A transition certificate signed only by Ed25519 is safe only while Ed25519 remains trustworthy or the transition was already witnessed/pinned before compromise.
4. Relay root rotation affects descriptor identity, DHT position, trust recognition, settlement identity, stored peer pins, and operational continuity.
5. Account root rotation affects account IDs, contact bindings, device certificates, handles, durable-record ownership, revocation state, and recovery.

### 9.2 Required identity ADR before signature-suite migration

A standalone ADR must choose and threat-model one of these strategies before production identity-suite records are added:

- **Genesis-key anchored identity:** stable ID remains derived from the original key; later key epochs are an authenticated chain. Simple continuity, but compromise/retirement of the genesis trust anchor needs witnessed transitions and explicit recovery rules.
- **Versioned logical identity:** introduce a new stable identity object whose ID derives from a canonical genesis record containing multiple scheme keys. Cleaner future agility, but it is a protocol identity migration rather than a key swap.
- **Intentional identity replacement:** new key means new identity, with explicit contact/handle/relay migration proofs. Strong self-certification semantics, high user and network migration cost.

The ADR must cover:

- account, device, relay, and application-facing identity separately;
- old-key/new-key cross-signature requirements;
- hybrid signature verification semantics (both required versus either accepted);
- epoch monotonicity, rollback floors, expiry, revocation, loss, compromise, and recovery;
- handle and durable-record ownership migration;
- relay DHT/trust/settlement continuity;
- multi-device propagation and offline devices;
- key transparency or witness assumptions;
- mixed-version behavior and terminal retirement of Ed25519-only verification.

Until that ADR lands, this plan permits hybrid session key establishment bound by the current identity, but it does not claim post-quantum authentication or identity replacement.

## 10. Browser and Node parity

Browser and Node must execute the same logical suite and produce the same canonical bytes. There is no “browser suite” and “Node suite.”

### 10.1 Shared vector corpus

Store dependency-free JSON fixtures under `rez-core/test/vectors/crypto-suites/`. Every fixture includes:

- fixture schema version and suite ID;
- primitive and construction inputs/outputs in canonical base64 or hex;
- public and private test keys clearly marked non-production;
- KDF labels and transcript bytes;
- offer, selection, and transcript canonical bytes/hashes;
- handshake shared secret and confirmation values;
- ratchet root/chain/message keys across multiple steps;
- envelope AAD, nonce, ciphertext, and tamper cases;
- onion per-hop secrets, layer bytes, packet bytes, and peel results;
- serialization/restart state where deterministic.

Both provider suites consume the same fixtures. Random generation tests remain separate.

### 10.2 Runtime gates

- Provider startup capability probes use real generate/import/sign/verify/derive/seal/open operations where safe, not user-agent strings.
- A suite is registerable but not selectable when the current provider lacks any required capability.
- Browser support gates are tested in the minimum supported browser matrix, not only Node's WebCrypto implementation.
- Unsupported environments receive a bounded readiness error before initiating a handshake.
- Cross-runtime tests cover Node→browser and browser→Node for handshake, message ratchet, persistence restore, and onion operations where the browser is an endpoint.
- Async/sync differences are normalized by awaiting provider results at suite boundaries.

## 11. Migration phases and exit criteria

No later phase starts until the prior exit criteria pass.

### Phase 0 — Freeze truth and compatibility

Work:

- complete the algorithm/key/label/wire/state/direct-import inventory;
- identify canonical crypto orchestration owners and duplicate/stale paths;
- capture current Node and browser outputs as legacy golden vectors;
- reconcile `security.md`, `SECURITY_POSTURE.md`, glossary, and implementation facts;
- add architecture guards for package boundaries and current wire versions.

Exit criteria:

- every production crypto call site is classified as protocol, identity, local storage, transport security, randomness/hash utility, or economic signing;
- no unexplained duplicate orchestration path remains;
- current X3DH-v2, ratchet, envelope v1, and onion v2 vectors are frozen;
- canonical docs match current construction names and KDF inputs;
- all current package tests pass unchanged.

### Phase 1 — Add seams around the classic construction

Work:

- make `RCryptoProvider` truthful and add capability reporting;
- add typed scheme/construction base classes;
- implement classic session, onion, and identity suite classes by adapting current code;
- add immutable registry and local policy classes;
- keep public APIs and wire bytes unchanged.

Exit criteria:

- classic vectors remain byte-identical in Node and browser;
- protocol orchestration no longer directly selects primitive strings outside classic scheme/construction classes;
- registry rejects duplicate/unknown/wrong-domain suites;
- provider/suite/policy responsibilities pass architecture tests;
- adding a test-only alternate registered suite using real existing primitives requires new classes/registration and no edits to protocol orchestrators.

### Phase 2 — Bind suite identity to state

Work:

- add `SecureSessionRecordV2`/`RatchetStateV2` or equivalent RRecord-based state with suite ID and transcript hash;
- add explicit legacy-state adapter;
- bind suites to codecs and session manager instances;
- version persistence without changing existing on-wire sessions.

Exit criteria:

- restart restores the exact suite without inference;
- legacy v1 state maps only to the classic suite;
- unknown/retired suite state fails with a bounded error and does not delete recoverable data;
- optimistic-lock and encrypted-store behavior remain intact;
- rollback from V2 software has a documented safe boundary.

### Phase 3 — Add authenticated peer-session negotiation

Work:

- add offer, selection, transcript, policy, and floor records;
- add the additive session handshake/envelope versions;
- bind offers and selection into KDF/key confirmation;
- implement mixed legacy/modern behavior behind an explicit compatibility policy.

Exit criteria:

- every downgrade matrix case fails as designed;
- modern↔modern selects the deterministic preferred mutual suite;
- modern↔legacy behavior matches the declared phase policy;
- no cryptographic failure triggers automatic weaker retry;
- selected suite survives persistence/reconnect;
- relay/node transports remain generic and payload-agnostic.

### Phase 4 — Add onion-suite agility

Work:

- add additive onion-key, descriptor, packet, and layer versions;
- advertise authenticated supported onion suites and keys;
- update path selection and relay key lifecycle through suite classes;
- allow overlapping classic/new keys during rollout.

Exit criteria:

- every selected path has one authenticated compatible suite across all hops;
- mixed descriptor/key versions have explicit outcomes;
- substitution, stripping, wrong-key, wrong-suite, expired, draining, revoked, and replay tests pass;
- current onion v2 behavior remains byte-identical when classic policy is selected;
- no forwarding or delivery semantics change.

### Phase 5 — Decide identity evolution

Work:

- land the identity ADR;
- inventory every signed artifact and identifier consumer against that decision;
- add records and migration code only after the ADR is approved;
- add account/device/relay/handle/durable-record transition vectors.

Exit criteria:

- stable identity, transition authority, rollback, compromise, loss, recovery, and retirement rules are unambiguous;
- account and relay consequences are independently tested;
- old software behavior is explicit and safe;
- no signed artifact silently accepts either-signature hybrid semantics unless the suite specifies it.

### Phase 6 — Evaluate and introduce a hybrid suite

Work:

- select a standardized construction based on current standards and Rez requirements;
- obtain dependency approval if native providers cannot implement it;
- implement provider support, scheme classes, construction classes, suite registration, and vectors;
- run disabled → observe → offer → prefer → require → retire rollout stages.

Exit criteria:

- dependency, side-channel, serialization-size, CPU/memory, browser-support, and denial-of-service reviews pass;
- Node/browser vectors and mixed-version tests pass;
- hybrid combiner and transcript receive independent cryptographic review;
- security claims precisely distinguish post-quantum confidentiality from authentication and ongoing ratchet protection;
- emergency disable and rollback are rehearsed without silent downgrade.

### Phase 7 — Release and retirement

Exit criteria:

- internal adversarial audit is closed;
- external cryptographic/protocol review is complete for any new construction;
- minimum supported versions and rollout dates are documented;
- metrics expose aggregate suite readiness/failure without collecting peer graphs, content, or private activity;
- old suite retirement is enforced by explicit policy and tested on persisted sessions, offline devices, and stale descriptors;
- rollback artifacts and incident runbooks exist.

## 12. Test and verification plan

### 12.1 Unit and contract tests

- Provider contract conformance for Node and browser.
- Capability truthfulness and unsupported-operation failures.
- Registry immutability, duplicate ID, wrong domain, unknown ID, and missing provider capability.
- Policy ordering, disable/retire, compatibility window, generation change, and explicit downgrade authorization.
- RRecord construction, sealing, bounded arrays/strings/bytes, unknown fields, canonical JSON, and round trips.
- Scheme known-answer tests.
- Construction known-answer tests for X3DH, root/chain KDFs, envelopes, and onion layers.
- Suite ID/domain immutability.

### 12.2 Compatibility tests

- Current classic outputs before/after Phase 1 are byte-identical.
- Existing `x3dh.handshake.v2`, `rez.encrypted.v1`, ratchet header, onion v2, descriptor v1, and persisted v1 fixtures remain readable under declared policy.
- New code does not emit new versions unless negotiation selected them.
- Legacy state never becomes a new suite by inference.
- SDK public exports resolve to one canonical E2EE implementation.

### 12.3 Real-crypto integration tests

- Node initiator ↔ Node responder.
- Browser initiator ↔ Node responder.
- Node initiator ↔ browser responder.
- Browser initiator ↔ browser responder where supported.
- Multiple ratchet turns, out-of-order delivery, skipped keys, DH rotation, reconnect, persistence restart, and multi-device fanout.
- Multi-hop onion build/peel with active/draining key overlap.
- No fake crypto provider in correctness gates.

### 12.4 Adversarial tests

- Full downgrade matrix in §8.3.
- Transcript confusion across peers, devices, sessions, domains, networks/contexts, and suite IDs.
- Low-order/invalid key, malformed encoding, wrong key type, all-zero secret, invalid signature, and AEAD tamper.
- Offer/record size and count exhaustion before expensive crypto.
- Replay of offers, selections, confirmations, descriptors, onion layers, key transitions, and retired persisted state.
- Algorithm-confusion attempts using valid bytes of another scheme.
- Hybrid combiner partial-failure behavior: failure of either required component fails the suite.
- Policy update during an active session does not mutate that session silently.
- Crashes between selection, key confirmation, state persistence, and first message recover safely.

### 12.5 Architecture tests

- Protocol suites and schemes import no Node/browser platform APIs.
- Providers contain no suite selection or downgrade policy.
- Application/UI packages contain no primitive or suite implementation.
- `rez-chat` has no direct `rez-core` import.
- Transport code has no per-suite method or directive enumeration.
- Production protocol orchestration contains no raw `"X25519"`, `"Ed25519"`, `"AES-GCM"`, or suite-selection string outside approved scheme/legacy adapter files.
- Every new structured/wire class extends `RRecord` and is one class/file.
- `rez-core/package.json` remains dependency-free.
- No production symbol uses an optional-product-specific name.

### 12.6 Performance and operability tests

- Handshake CPU, memory, bytes, and latency budgets on minimum browser and supported Node versions.
- Relay onion build/peel throughput and packet-size impact.
- Prekey, descriptor, DHT, mailbox, and storage quotas under larger future keys/signatures.
- Startup capability probe behavior.
- Emergency suite disable, preference reversal, rollback, and resumed rollout rehearsal.
- Privacy review of any aggregate rollout metric.

## 13. Ticketized implementation sequence

Ticket IDs are dependency order, not calendar commitments.

| Ticket | Scope | Depends on | Acceptance |
|---|---|---|---|
| `CA-000` | Create exhaustive crypto call-site/label/key/wire/state inventory and classify ownership. | — | Reviewed inventory covers all four JS packages and direct platform crypto calls. |
| `CA-001` | Reconcile security/glossary docs with live X3DH-v2, ratchet, envelope, onion, keystore, and identity code. | CA-000 | No known construction/label drift remains. |
| `CA-002` | Freeze current classic Node and browser vectors plus wire/persistence fixtures. | CA-000 | Fixtures reproduce current outputs; all existing suites pass. |
| `CA-003` | Prove canonical E2EE exports; remove unreachable duplicate SDK crypto orchestration sources if confirmed. | CA-000 | Architecture test proves one owner; no consumer/import regression. |
| `CA-010` | Complete `RCryptoProvider` contract and add `CryptoProviderCapabilitiesV1`. | CA-002 | Both providers pass one conformance contract; unsupported capabilities fail closed. |
| `CA-011` | Add typed classic hash/KDF/AEAD/signature/key-agreement scheme classes. | CA-010 | Shared known-answer vectors pass in Node/browser. |
| `CA-012` | Add typed current handshake/ratchet/envelope/onion construction adapters. | CA-011 | Current outputs remain byte-identical. |
| `CA-020` | Add suite base classes and immutable domain-scoped registry. | CA-012 | Duplicate/unknown/wrong-domain/capability failures tested. |
| `CA-021` | Add `RClassicSessionSuiteV1`, `RClassicOnionSuiteV2`, and `REd25519IdentitySuiteV1` registration. | CA-020 | All current protocol paths resolve through registered classic suites. |
| `CA-022` | Add `CryptoSuitePolicyV1` and `RCryptoSuitePolicy`. | CA-020 | Ordered allowlist, disable, retire, generation, and compatibility tests pass. |
| `CA-030` | Refactor `SecureChannelManager`, X3DH, ratchet, and envelope codecs to consume selected classic suite. | CA-021 | No scattered primitive choice in orchestration; v1/v2 bytes unchanged. |
| `CA-031` | Refactor onion builder/peeler/path/key rotation to consume selected classic onion suite. | CA-021 | Onion v2 bytes and lifecycle unchanged. |
| `CA-032` | Add architecture guards for provider/suite/policy separation and registration-first extension. | CA-030, CA-031 | Test-only real-crypto suite extension needs classes + registration only. |
| `CA-040` | Add suite-bound RRecord session/ratchet state and legacy-state adapter. | CA-030 | Restart and encrypted/plain persistence pass; no inference. |
| `CA-041` | Add non-destructive persistence migration and rollback boundary. | CA-040 | Snapshot, migrate, independently verify, and rollback rehearsal pass. |
| `CA-050` | Add offer, selection, transcript, and peer-floor RRecords. | CA-022 | Bounds, canonical bytes, replay fields, and wrong-domain rejection pass. |
| `CA-051` | Add deterministic negotiation and transcript/key-confirmation service. | CA-050 | Downgrade unit matrix passes with real signing/KDF. |
| `CA-052` | Add additive peer-session handshake/envelope versions. | CA-040, CA-051 | Modern/modern and modern/legacy matrices pass; no silent retry. |
| `CA-053` | Persist and enforce peer suite floors with explicit reset receipts. | CA-052 | Reconnect downgrade tests and recovery UX contract pass. |
| `CA-060` | Add additive onion-key and relay-descriptor records with authenticated suite advertisement. | CA-031, CA-050 | Signature, bounds, mixed-version, and substitution tests pass. |
| `CA-061` | Add negotiated onion packet/layer version and mixed-key rotation. | CA-060 | Multi-hop/mixed-version/downgrade/replay matrices pass. |
| `CA-070` | Write and approve identity/key-evolution ADR. | CA-000 | All §9 ADR questions resolved; no implementation bundled. |
| `CA-071` | Inventory and test every identity-bound artifact against the approved ADR. | CA-070 | Account/device/relay/handle/durable-record/receipt matrix reviewed. |
| `CA-072` | Implement approved identity key-set/transition records and migration, if authorized. | CA-071 | Cross-sign, epoch, rollback, revocation, loss, and mixed-version tests pass. |
| `CA-080` | Evaluate candidate hybrid primitives/construction and request dependency approval if required. | CA-052, CA-070 | Written standards, dependency, side-channel, browser, size, and DoS review approved. |
| `CA-081` | Implement Node/browser primitive support and vectors. | CA-080 | Provider conformance and shared KATs pass; capability is truthful. |
| `CA-082` | Add hybrid suite classes and registration, initially disabled. | CA-081 | No unrelated orchestrator edits; vectors and adversarial tests pass. |
| `CA-083` | Run disabled→observe→offer→prefer→require staged rollout. | CA-082 | Each stage has measured exit evidence and emergency rollback rehearsal. |
| `CA-090` | Internal adversarial audit and external cryptographic review. | CA-083 | Findings closed or explicitly accepted; claims updated. |
| `CA-091` | Retire classic suites under explicit policy when authorized. | CA-090 | Offline/persisted/legacy paths and operator runbook verified. |

## 14. Audit checklist

Use this checklist during design review, implementation review, and release review.

### Current-state audit

- [ ] Enumerate every direct `node:crypto`, `globalThis.crypto`, and `subtle` use in production code.
- [ ] Enumerate every X25519, Ed25519, AES-GCM, HKDF-SHA256, PBKDF2/scrypt, SHA-256, and key-encoding assumption.
- [ ] Classify each use by security domain and canonical package owner.
- [ ] Enumerate every KDF label/context string and verify documentation matches code.
- [ ] Enumerate every wire type/version and persisted crypto-state version.
- [ ] Identify every place a suite/algorithm/key type is inferred from a string, byte length, DER prefix, record version, or caller input.
- [ ] Identify direct provider bypasses that are legitimate and those that split protocol truth.
- [ ] Verify one canonical implementation/export for X3DH, ratchet, envelope, and onion constructions.
- [ ] Verify all structured and wire values touched by the work use `RRecord` or have an explicit migration ticket.
- [ ] Verify current classic wire and persistence vectors before refactoring.

### OO and ownership audit

- [ ] Platform providers execute primitives only.
- [ ] Suite classes define immutable protocol constructions only.
- [ ] Policy chooses allowed suites only.
- [ ] Registry is immutable, injected, domain-scoped, and rejects duplicates.
- [ ] No mutable global suite registry or string-based module loading exists.
- [ ] Each class has one responsibility and one file.
- [ ] No god suite/provider/coordinator accumulates negotiation, crypto, persistence, and rollout policy.
- [ ] Core suite code imports no Node/browser API and no new dependency.
- [ ] SDK/node/chat dependency directions remain correct.
- [ ] Transports remain payload-agnostic.

### Wire and state audit

- [ ] Suite IDs are immutable and exact; no aliases or arbitrary algorithm combinations.
- [ ] Legacy record meanings and bytes are unchanged.
- [ ] Offers, selections, suite IDs, identities/key epochs, nonces, and prekey references are authenticated.
- [ ] Selected suite is included in KDF transcript and key confirmation.
- [ ] Envelopes authenticate suite ID in AAD.
- [ ] Ratchet/persisted state stores suite ID explicitly.
- [ ] Legacy state maps only through a named legacy adapter.
- [ ] Onion descriptor/key/layer/packet versions agree and authenticate suite/key IDs.
- [ ] Unknown or retired suite state fails closed without destructive deletion.

### Downgrade and migration audit

- [ ] Deterministic selection is recomputed by both parties.
- [ ] No automatic weaker retry follows negotiation or crypto failure.
- [ ] Remembered peer floor blocks silent regressions.
- [ ] Explicit downgrade/reset produces a local audit receipt.
- [ ] Compatibility windows and retirement dates are policy, not hardcoded branches across protocol code.
- [ ] Active sessions do not mutate when policy changes.
- [ ] Suite upgrade creates a new authenticated session.
- [ ] Emergency disable and rollback are rehearsed.

### Identity audit

- [ ] Account, device, relay, handle, durable-record, capability, receipt, and settlement identities are all considered.
- [ ] The stable-identity decision is explicit and approved.
- [ ] Old/new cross-signature semantics and hybrid verification rule are explicit.
- [ ] Epoch, rollback floor, revocation, expiry, compromise, loss, and recovery are tested.
- [ ] Claims distinguish PQ confidentiality, PQ authentication, and ongoing PQ ratchet protection.

### Runtime and release audit

- [ ] Node and browser consume the same suite fixtures.
- [ ] Minimum supported browsers pass real crypto and end-to-end tests.
- [ ] Capability probes are truthful and fail before handshake work.
- [ ] Size/CPU/memory/DoS budgets include future larger keys and signatures.
- [ ] No private activity, peer graph, content, or destination data is added to rollout telemetry.
- [ ] Internal adversarial and required external reviews are complete.
- [ ] Documentation, security posture, runbooks, and rollback artifacts match the released code.

## 15. Overall completion criteria

Crypto-agility hardening is complete only when all of the following are true:

1. Platform crypto execution and protocol suite/policy selection are separate, enforced seams.
2. Current classic behavior is represented by registered suite classes with byte-identical compatibility vectors.
3. New structured and wire values are `RRecord` subclasses with canonical, bounded encodings.
4. Sessions and onions have authenticated, domain-scoped suite identities.
5. Suite negotiation is downgrade-resistant, persisted, mixed-version tested, and never silently retries weaker.
6. Browser and Node pass one shared suite-vector corpus and bidirectional real-crypto integration tests.
7. Persisted state resolves suites explicitly and migrates non-destructively.
8. Identity-root evolution has an approved model before signature replacement is claimed.
9. Adding an already-supported suite primarily requires new scheme/construction/suite classes, one registration, policy configuration, and tests—not scattered protocol edits.
10. Adding a new primitive changes only the bounded provider implementations, new scheme/suite classes, registration, and tests unless its construction genuinely requires a new record version.
11. `rez-core` remains dependency-free unless the repository rules are explicitly changed by a separately approved decision.
12. No package boundary, transport generality, payload agnosticism, delivery invariant, or application behavior regresses.
13. All phase gates, adversarial checks, documentation updates, and required reviews are complete.

Until these criteria pass, Rez should describe itself as having a cross-runtime crypto provider abstraction and versioned fixed constructions—not as fully crypto-agile or post-quantum secure.
