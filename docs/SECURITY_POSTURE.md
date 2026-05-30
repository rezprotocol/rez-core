# Security Posture

This document summarizes how Rez approaches security: how the protocol is reviewed, what's been found and fixed, and how the project handles disclosures.

For the protocol's threat model and cryptographic guarantees, see [`security.md`](./security.md). For reporting vulnerabilities, see [`SECURITY.md`](../SECURITY.md) at the repo root.

---

## Approach

Rez treats security as a continuous, adversarial process rather than a one-time audit gate. Every meaningful change to identity, peer-link, capability, routing, or persistence code triggers an internal red-team review before landing.

The project's principles:

1. **Untrusted-by-design infrastructure.** Relay nodes are assumed to be hostile or compromised. The protocol's properties hold even if every node in the mesh colludes against a user; nodes see ciphertext and routing headers, never plaintext or long-lived secrets.
2. **No band-aids.** Findings are fixed at the architectural level, not patched around. If a fix requires reshaping an interface, the interface is reshaped.
3. **Adversarial framing.** Reviews are run against the code as it exists, looking for exploits, not theoretical hardening notes.
4. **No mocked crypto tests.** Cryptographic correctness changes require un-mocked end-to-end coverage. Mocked tests have historically hidden real bugs in this codebase.

---

## Review history

The protocol and its implementation have been subjected to three internal adversarial security reviews:

| Pass | Date | Scope | Outcome |
|---|---|---|---|
| 1 | 2026-05-13 | Identity, capability model, E2EE handshake + ratchet, relay/onion routing, invite/contacts, mailbox/handles, settlement | 3 critical, 3 high, 3 medium findings — all in-scope findings closed; 1 high deferred to invite-flow v2 |
| 2 | 2026-05-14 | Post-remediation re-audit + new settlement/storage/handle and DHT routing surfaces | 4 high, 3 medium, 2 low findings against live systems — all closed; findings against not-yet-live handle/settlement systems tabled for re-audit when those systems ship |
| 3 (delta) | 2026-05-15 | Delegation binding, session-auth, relay-provisional peer admission, DHT route hints | 1 medium opened + closed same day; 1 low opened and tracked |

**Current status (2026-05-15):**
- All findings against live systems from Passes 1 and 2 are closed.
- One open low-severity issue (LOW-6: no per-peer DHT-store quota) remains tracked as non-blocking; mitigation is in design.
- Findings against the handle and settlement systems are tabled (those systems are not live nor fully designed) and will be re-opened when those systems return.

The full audit log is maintained privately and shared with security researchers under coordinated-disclosure as appropriate. Past findings will be published in CVE-style advisories once a coordinated disclosure window has elapsed.

---

## Cryptographic primitives

Rez relies on well-studied, conservatively-chosen primitives:

- **Signing:** Ed25519 (RFC 8032)
- **Key agreement:** X25519 (RFC 7748) — used for the X3DH-v2 handshake (DH1 || DH2 || DH3 [|| DH4]) and ongoing Diffie-Hellman ratchet steps
- **AEAD:** AES-256-GCM with 96-bit nonces and 128-bit authentication tags (NIST SP 800-38D)
- **KDF:** HKDF-SHA-256 (RFC 5869)
- **Password derivation:** scrypt (RFC 7914) for keystore unlock
- **Session ratchet:** X3DH (Open Whisper Systems) + Double Ratchet (Open Whisper Systems / Signal)

No custom cryptographic constructions. No primitives selected for performance over conservatism.

---

## What's explicitly out of scope

The threat model is documented in detail in [`security.md`](./security.md). At a glance:

- **Endpoint compromise.** If an attacker has code execution on the user's device or access to the unlocked keystore, Rez offers no protection. This is a property of every E2EE system.
- **Coercion of the user.** Rez does not defend against rubber-hose attacks or legal-process-served devices.
- **Out-of-band identity verification.** Like every other E2EE protocol, an active man-in-the-middle on first contact is detectable only by out-of-band fingerprint comparison. Rez exposes the fingerprints but cannot force users to verify them.
- **Traffic analysis at the network layer.** Onion routing reduces metadata correlation between sender and recipient, but a global passive adversary observing all relay traffic can still infer some patterns.
- **Denial of service against individual operators.** Volumetric DDoS against a specific node's infrastructure is the operator's problem; the protocol is designed for relay churn.

---

## Reporting

If you've found something, please follow the responsible disclosure process in [`SECURITY.md`](../SECURITY.md).
