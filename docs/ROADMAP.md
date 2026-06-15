# Rez Protocol — Roadmap & Deferred Enhancements

This document lists features that are **intentionally out of scope** for the current phase but expected to be implemented later.

Purpose:
- prevent scope creep
- preserve architectural discipline
- document intent without committing to timing

Nothing in this document is required for correctness right now.

---

## Logging Enhancements (Deferred)

### 1. Log Level Filtering
Ability for RLogger to drop events below a configured minimum level.

**Deferred because**
- not required for correctness
- adds config complexity
- better handled in SDK

**Planned phase**
- Phase 8 (SDK Convenience Layer)

---

### 2. Logger Scoping / Child Loggers
Support for `logger.child("Component")`.

**Deferred because**
- ergonomic only
- can be layered later without breaking API

**Planned phase**
- Phase 8

---

### 3. Log Formatting Helpers
Human-readable formatting helpers for console/file output.

**Deferred because**
- formatting is a transport concern
- core logging must stay neutral

**Planned phase**
- Phase 8

---

## Encoding / Debug Utilities (Deferred)

### 4. Hex Encoding Helpers
Utilities like `bytesToHex` / `hexToBytes`.

**Deferred because**
- not required for crypto correctness
- mostly for debugging and CLI usage

**Planned phase**
- Phase 8 (SDK) or small util module later

---

### 5. Base64 / Base64url Helpers
Canonical base64/base64url encoding helpers.

**Deferred because**
- key export formats already defined
- human-facing encodings belong in SDK/apps

**Planned phase**
- Phase 8

---

## Crypto Enhancements (Deferred)

### 6. Algorithm Negotiation
Support multiple signing algorithms simultaneously.

**Deferred because**
- overkill for initial crypto layer
- determinism first

**Planned phase**
- Phase 7+

---

### 7. X3DH Integration
Full X3DH handshake.

**Deferred because**
- requires protocol + network decisions

**Planned phase**
- Phase 7+

---

### 8. Double Ratchet
Forward secrecy ratcheting.

**Deferred because**
- depends on X3DH and message ordering rules

**Planned phase**
- Phase 7+

---

## Runtime / Operator Enhancements (Deferred)

### 9. Runtime Metrics
Counters/timers for throughput, errors, latency.

**Deferred because**
- not protocol-critical
- deployment-specific

**Planned phase**
- Phase 8 or Phase 9

---

### 10. Diagnostic Tracing
Correlation IDs across runtime layers.

**Deferred because**
- depends on networking + runtime stability

**Planned phase**
- Phase 8+

---

## Token Economy (Tiered)

The REZ token economy ("postage, not equity") ships in tiers, each independently useful. Canonical design lives in [`rez-token-whitepaper.html`](../../rez-token-whitepaper.html); the on-chain suite is owned by `rez-contracts`.

**Beta safety property — runs through all tiers:** no real value is at risk before mainnet (Tier 6). Value-bearing beta runs on off-chain credits; on-chain modes run on testnets with test tokens. Every economic "tooth" (slashing, recognition gates) ships in a `shadow → advisory → enforce` sequence so it can be watched long before it can affect anyone. `slashBps` defaults to 0.

### Tier 1 — Wallet + paid @handles
A credits balance, starter allowance, and claim/renew/release of paid `@handles` — end-to-end in the chat app on local credits. Relays earn fee revenue here, not emissions yet.

### Tier 2 — Solidity contract suite (Base Sepolia)
The full immutable token + machinery deployed to testnet, including the no-rug invariant tests proving the token has no mint/owner/pause/upgrade surface.

### Tier 3 — Chain-settlement mode
Users deposit test REZ; relays track micro-debits off-chain and batch-settle on-chain via a non-custodial, deposit-anchored payment channel. Same chat flow, no migration.

### Tier 3.5 — Proof-of-replication
Real proof that k replicas mean k× real bytes.

### Tier 4 — Commitments + executed slashing + paid persistent storage
Per-commitment escrow bonds, executed slashing (still default-off), and paid persistent storage.

### Tier 5 — Paid large files + distributed k-replica storage
Paid large files carried by distributed k-replica storage.

### Tier 5.5 — Trust graph
The Sybil-resistant recognition and emission engine (`TrustGraph`), shipped in shadow mode first and validated against adversarial fixtures before it gates anything.

### Tier 6 — Mainnet + conversion
Recognition gates flip to `enforce`, epoch emissions go live, the token deploys to mainnet, and eligible `convertible` credits convert 1:1 to REZ. The first and only permanent deploy.

**Gate:** mainnet (Tier 6) is gated on a formal **external** security audit. The design is internally reviewed but not externally audited.

---

## Rules

- Deferred items must not be implemented without explicit approval.
- Items move into scope only by updating [`ARCHITECTURE_GUARANTEES.md`](./ARCHITECTURE_GUARANTEES.md) and the relevant per-package architecture references.

---

## Current Phase Guardrail

Current phase tracking moved out of this document.
Use canonical repo boundary docs for scope control.
