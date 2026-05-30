# @rezprotocol/core

Cryptographic primitives, wire-protocol encoding, and canonical record schemas for the [Rez protocol](https://github.com/rezprotocol).

`@rezprotocol/core` is the protocol foundation. It is consumed by every other Rez package — the client SDK, the node runtime, and the application layer — and intentionally contains no Node-specific or DOM-specific code. The same code runs in Electron main, browsers, and Node CLIs.

---

## What's in here

- **Cryptographic primitives** — Ed25519 signing, X25519 Diffie-Hellman, AES-256-GCM AEAD, HKDF-SHA-256, scrypt, and the X3DH + Double Ratchet construction that powers Rez's E2EE.
- **Wire-protocol encoding** — canonical JSON serialization, versioned record envelopes, signature/MAC framing.
- **Domain records** — versioned, validated schemas for identities, peer-link payloads, group operations, and the protocol-level capability model.
- **Glossary + invariants** — shared vocabulary and architecture guarantees the rest of the ecosystem builds on.

---

## Install

```bash
npm install @rezprotocol/core
```

This package has zero runtime dependencies. Crypto uses the platform's built-in `crypto` module (Node) or `crypto.subtle` (browsers).

---

## Using rez-core

`@rezprotocol/core` exposes the protocol's building blocks as a set of cohesive classes — `RCryptoProvider`, `RSigner`, `RKeyManager`, `RDh`, the `SecureChannelManager`, codecs, ID helpers, and the wire-record schemas. The crypto provider is **abstract**; concrete implementations (`BrowserCryptoProvider` for WebCrypto, a Node provider for `crypto.subtle`) ship with [`@rezprotocol/sdk`](https://github.com/rezprotocol/rez-sdk).

Most applications should consume `@rezprotocol/sdk`, which wires up the provider, manages session lifecycle, and exposes peer links and inboxes. Use `rez-core` directly when:

- You're implementing a non-JS Rez client and need the wire schemas as a reference.
- You're building a custom crypto provider (hardware-backed keystore, alternative platform).
- You're parsing or producing Rez packets / onion layers / canonical encodings outside of an SDK runtime.

```js
// Simple example: canonical JSON encoding (used everywhere on the wire)
import { canonicalize, canonicalJSONStringify } from "@rezprotocol/core";

const canonical = canonicalize({ b: 2, a: 1 });        // { a: 1, b: 2 }
const wireBytes = canonicalJSONStringify({ b: 2, a: 1 }); // '{"a":1,"b":2}'
```

For the protocol-level concepts these primitives implement, see the [documentation index](#documentation) below.

---

## Documentation

| Doc | Contents |
|---|---|
| [docs/architecture.md](./docs/architecture.md) | Layer responsibilities and dependency graph across all Rez packages |
| [docs/protocol.md](./docs/protocol.md) | Wire protocol, session handshake, WebSocket frame format |
| [docs/WS_CONTRACTS.md](./docs/WS_CONTRACTS.md) | Generated WebSocket request/result/event contracts |
| [docs/security.md](./docs/security.md) | Threat model, cryptographic properties, known limitations |
| [docs/SECURITY_POSTURE.md](./docs/SECURITY_POSTURE.md) | Audit history and security disclosure posture |
| [docs/CAPABILITY_MODEL.md](./docs/CAPABILITY_MODEL.md) | Authorization model, capability signing, delegation |
| [docs/IDENTIFIERS.md](./docs/IDENTIFIERS.md) | Account / inbox / handle encoding and canonical forms |
| [docs/INVITE_FLOW_SPEC.md](./docs/INVITE_FLOW_SPEC.md) | Invite lifecycle, security properties, contact establishment |
| [docs/GROUP_MESSAGING_SPEC.md](./docs/GROUP_MESSAGING_SPEC.md) | Group protocol, membership, forward secrecy |
| [docs/CONTACTS_SPEC.md](./docs/CONTACTS_SPEC.md) | Contact / group semantics, invite acceptance |
| [docs/ACCOUNT_SYSTEM.md](./docs/ACCOUNT_SYSTEM.md) | Account creation, recovery, identity binding |
| [docs/BACKUP_MODEL.md](./docs/BACKUP_MODEL.md) | Key backup and recovery model |
| [docs/STORAGE_MODEL.md](./docs/STORAGE_MODEL.md) | Persistence semantics, storage providers, inbox model |
| [docs/ARCHITECTURE_GUARANTEES.md](./docs/ARCHITECTURE_GUARANTEES.md) | Invariants, delivery guarantees, ordering semantics |
| [docs/GLOSSARY.md](./docs/GLOSSARY.md) | Canonical terminology across all Rez packages |
| [docs/RECEIPTS_AND_DELIVERY_STATES.md](./docs/RECEIPTS_AND_DELIVERY_STATES.md) | Message state machine |
| [docs/ROADMAP.md](./docs/ROADMAP.md) | Intentional backlog: what's not built yet and why |
| [docs/WHITEPAPER.html](./docs/WHITEPAPER.html) | Full cryptographic and architectural white paper |

---

## Related projects

- [**rez-sdk**](https://github.com/rezprotocol/rez-sdk) — client SDK that wraps core primitives in higher-level session / peer-link / inbox APIs
- [**rez-node**](https://github.com/rezprotocol/rez-node) — relay node runtime; serves the protocol over WebSocket and federates with other nodes
- [**rez-ui**](https://github.com/rezprotocol/rez-ui) — shared UI framework for Rez applications
- [**rez-chat**](https://github.com/rezprotocol/rez-chat) — reference desktop chat application

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Security disclosures: see [SECURITY.md](./SECURITY.md).

## License

Apache 2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
