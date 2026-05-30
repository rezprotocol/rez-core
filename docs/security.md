# Security

This document summarizes the Rez security model: what the protocol protects against, what cryptographic guarantees it provides, and what is explicitly out of scope.

For the full cryptographic specification, see the [white paper](./WHITEPAPER.html).

---

## Threat Model

### What Rez protects against

| Threat | Mitigation |
|---|---|
| **Network eavesdropper** | All relay traffic uses TLS (≥1.2). All message content is E2E encrypted with AES-256-GCM before leaving the sender's device. |
| **Honest-but-curious relay operator** | Messages are encrypted with keys the relay does not possess. Operators see only ciphertext and minimal metadata (inbox IDs, packet sizes). |
| **Compromised relay node** | Onion routing ensures each relay sees only its own layer. An entry relay knows the sender but not the recipient. A delivery relay knows the recipient but not the sender. No single relay sees both. |
| **Malicious relay (active)** | Relay descriptor signatures (Ed25519) prevent impersonation. Route announcement validation limits poisoning. AES-256-GCM authentication tags detect any ciphertext tampering. |
| **Credential theft / password brute force** | The keystore is encrypted with PBKDF2-SHA256 at 210,000 iterations. No password material is stored on any server. |
| **Replay attacks (peer auth)** | Challenge nonces are single-use. Each nonce is consumed on first use and recorded in a TTL-expiring set. |
| **Replay attacks (messages)** | The ratchet chain index monotonically increases. A delivered message cannot be replayed at a different position. |
| **Session impersonation** | Session establishment requires three Ed25519 proofs: session auth signature, inbox delegation, and X3DH binding. All must verify against the client's claimed identity key. |
| **Buffer exhaustion (relay)** | TCP frame size is capped at 32 KB. Per-socket rate limit of 200 frames/second. |
| **Prototype pollution (JSON parsing)** | All JSON parsed from untrusted sources is validated for `__proto__`, `constructor`, and `prototype` own-properties before use. |

### Out of scope

| Threat | Notes |
|---|---|
| **Device-level compromise** | If the device running the client is compromised, the attacker can read the keystore (if unlocked) or the decrypted messages in memory. This is OS/device-level responsibility. |
| **Global passive adversary (traffic timing)** | An adversary who can observe all network links simultaneously could correlate packet timing across hops. Mitigating this requires mix networking (delayed/batched forwarding) — planned for future work. |
| **Quantum computing** | Current algorithms (X25519, Ed25519) are not quantum-resistant. Post-quantum hybrid schemes are planned for a future version. |
| **Key transparency** | There is no cryptographic mechanism to detect if a user's pre-key bundle has been replaced by a malicious relay. Out-of-band key verification (e.g., safety numbers) is not yet implemented. |
| **Metadata analysis by directory operators** | Directory servers see relay IP addresses and descriptor query patterns. This is intentional — directory operators need enough info to serve relay discovery. |

---

## Cryptographic Primitives

| Algorithm | Key size | Use | Standard |
|---|---|---|---|
| Ed25519 | 256-bit | Identity signing, invite signing, relay descriptor signing, peer auth | RFC 8032 |
| X25519 | 256-bit | X3DH, Double Ratchet DH steps, onion layer ephemeral DH | RFC 7748 |
| AES-256-GCM | 256-bit key, 96-bit nonce | Message encryption, keystore encryption, onion layer AEAD | NIST SP 800-38D |
| HKDF-SHA256 | Variable | Key derivation: ratchet chains, AEAD material, onion keys | RFC 5869 |
| PBKDF2-SHA256 | 256-bit output | Password-based keystore key derivation (210,000 iterations) | RFC 2898 |
| SHA-256 | 256-bit | Account ID fingerprinting, commitment hashes | FIPS 180-4 |

---

## Cryptographic Properties

| Property | Mechanism |
|---|---|
| **Confidentiality** | AES-256-GCM with HKDF-derived per-message keys |
| **Integrity** | GCM authentication tag on every ciphertext; AAD binds envelope header to payload |
| **Forward secrecy** | Double Ratchet: old chain keys deleted after use; X3DH ephemeral keys are single-use |
| **Break-in recovery** | DH ratchet step on each reply re-derives root/chain keys from a fresh DH exchange |
| **Sender authentication** | Ed25519 session signature at handshake; AEAD AAD binds to session identity and ratchet position |
| **Replay prevention** | Ratchet chain index (monotonic); challenge nonces consumed on first use |
| **Metadata privacy** | Onion routing: no relay sees both sender and recipient |
| **Traffic analysis resistance** | Fixed-size packet classes (4 KB / 8 KB / 16 KB / 32 KB) with random padding |

---

## Key Derivation Detail

### Keystore (PBKDF2)

```
salt          = random 16 bytes
unlockKey     = PBKDF2-SHA256(password, salt, 210_000, 32)
ciphertext    = AES-256-GCM(unlockKey, randomIV, keystoreJson)
envelope      = { saltB64, ivB64, ciphertextB64, v: "1" }
```

Minimum accepted iteration count on load: 100,000. Keystores with lower counts are rejected.

### X3DH Session Establishment

```
DH3          = X25519(initiatorEphemeral.priv, receiver.SPK.pub)
DH4          = X25519(initiatorEphemeral.priv, receiver.OPK.pub)  // if OPK present
sharedSecret = HKDF-SHA256(DH3 ‖ DH4, salt="", info="rez-x3dh-v1", len=32)
```

### Double Ratchet Root Step

```
dhOutput      = X25519(self.DH.priv, remote.DH.pub)
[newRoot, sendChain, recvChain] = HKDF-SHA256(dhOutput, salt=rootKey,
                                              info="rez-ratchet-root-v1", len=96)
```

### Per-Message AEAD Key

```
[msgKey, nextChain] = HKDF-SHA256(chainKey, salt="",
                                   info="rez-ratchet-chain-v1", len=64)

aeadMaterial  = HKDF-SHA256(msgKey, salt="",
                             info="rez-aead-v1" ‖ sessionId ‖ prevN ‖ msgN ‖ SHA256(dhPub),
                             len=44)
aeadKey       = aeadMaterial[0..32]
nonce         = aeadMaterial[32..44]
```

---

## Skipped Key Store Limits

Out-of-order messages are handled by caching skipped message keys:

| Limit | Value |
|---|---|
| Maximum stored keys | 500 |
| Maximum skip distance | 200 positions |
| Maximum total stored bytes | 64 KB |

Keys beyond these limits are discarded. Affected messages cannot be decrypted (they will fail with a decryption error).

---

## Security Hardening Applied

The following hardening measures are implemented in the current codebase:

- **Constant-time byte comparison** in `bytesEqual()` — uses XOR accumulation to prevent timing side-channels when comparing ratchet keys
- **TLS 1.2 minimum** enforced on all relay TCP connections (client and server)
- **Prototype pollution protection** on all `JSON.parse()` call sites that handle untrusted network input
- **Single-use challenge nonces** with TTL-based cleanup in relay peer authentication
- **Auth check before envelope decode** — unauthenticated relay connections cannot trigger envelope parsing
- **TCP buffer size cap** — frame accumulation buffer capped at `MAX_FRAME_BYTES + 4` before any parsing
- **Route announcement validation** — relay route announcements are validated (0-hop entries must originate from the announcing relay; max 500 entries per announcement)
- **Per-socket rate limiting** — 200 frames/second per relay socket; excess frames are dropped

---

## Reporting Security Issues

If you discover a security vulnerability in the Rez protocol or any of its packages, please report it privately before public disclosure.

Contact: [security contact TBD]

Please include:
- A description of the vulnerability
- Steps to reproduce (if applicable)
- Your assessment of impact and exploitability
- Whether you plan to publish, and on what timeline

We will acknowledge receipt within 48 hours and aim to release a fix before public disclosure.
