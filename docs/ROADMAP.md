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

## Rules

- Deferred items must not be implemented without explicit approval.
- Items move into scope only by updating [`ARCHITECTURE_GUARANTEES.md`](./ARCHITECTURE_GUARANTEES.md) and the relevant per-package architecture references.

---

## Current Phase Guardrail

Current phase tracking moved out of this document.
Use canonical repo boundary docs for scope control.
