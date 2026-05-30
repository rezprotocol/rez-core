# Identifier Glossary

This document is the **single source of truth** for identifier nomenclature in
the Rez monorepo. Every identifier has exactly one canonical name; any
deviation is a bug and is enforced by the `no-deprecated-id-names`
bannedSymbols rule in `guardrails.config.json`.

If you need to introduce a new identifier, add it here first, then write the
code. If you discover a deprecated name in the codebase, rename it; do not add
a translation shim.

---

## Canonical names

### Account-family identifiers

These are **all valid** — each has a distinct semantic role. They are NOT
synonyms and must not be collapsed.

| Name | Role | Where it appears |
|---|---|---|
| `accountId` | A bare account identifier, with no implied role | Vault summary, generic record fields |
| `ownerAccountId` | The account that owns a particular storage row / runtime / bus | `ownerAccountId` on every persisted record, `bus.runtime.ownerAccountId` |
| `senderAccountId` | The account that authored an outbound message / mutation | Encrypted wire payloads, store messages |
| `peerAccountId` | The other party in a peer-link or direct thread | `peer-link.updated.peerAccountId`, `Thread.peerAccountId`, mutation-dispatch context |

Banned synonyms in this family:

| Banned | Use instead | Reason |
|---|---|---|
| `remoteAccountId` | `peerAccountId` | "Remote" hid the fact that this is the *peerlink* view, distinct from the vault view. Was the source of the 2026-05-19 identity-layer bug. |
| `contactAccountId` | `accountId` (on `Contact` records) | The surrounding record name disambiguates; the prefix is vestigial. |
| `memberAccountId` | `accountId` (on `GroupMember` records) | Same as above. |

### Message identifiers

| Name | Role |
|---|---|
| `messageId` | **Sender-generated, wire-stable.** Persists unchanged to every receiver and store. |
| `eventId` | Relay-assigned per-envelope id. Used **only** for relay-level dedup; never substituted for `messageId`. |

Banned synonyms:

| Banned | Use instead | Reason |
|---|---|---|
| `clientMsgId` | `messageId` | Implied a sender/receiver asymmetry that doesn't exist; the messageId IS sender-generated. |
| `packetId` | `messageId` | Wire-layer leak into app vocabulary. |
| `localMsgId` | `messageId` | Implied a "local" variant distinct from a "wire" one; there is only one id. |
| `wireMessageId` | `messageId` | Symmetric synonym of `localMsgId`. |

### Mailbox / inbox identifiers

A peer-link has TWO inboxes — the local one and the remote one. They must be
named distinctly because both can appear in the same scope.

| Name | Owning layer | Role |
|---|---|---|
| `inboxId` (on `InboxClaimant`) | rez-chat | The **local user's own** inbox — what every cap chain anchors against |
| `peerInboxId` (on `Thread`) | rez-chat | The **peer's** inbox — the destination where outbound messages on this thread get deposited |
| `mailboxId` | rez-core / rez-node | Protocol-layer name for any inbox — substrate-only |

The local `inboxId` and the peer `peerInboxId` are two values, never the same.
`mailboxId` is the underlying protocol name and equals whichever of the two
the substrate is talking about in context. **Cross-package unification of
`mailboxId` → `inboxId` is deferred to Phase 5.**

Banned synonyms in rez-chat:

| Banned | Use instead | Reason |
|---|---|---|
| `bindingTarget` | `peerInboxId` | "Binding" was a leaky implementation term; the value is the peer's inbox. |
| `bindingTargetInboxId` | `peerInboxId` | Verbose compound; same value. |

### Other identifiers (no synonyms)

| Concept | Canonical name |
|---|---|
| Direct or group thread | `threadId` |
| Peer-link object | `peerLinkId` |
| Group object | `groupId` |
| File-transfer object | `transferId` |
| Invite code (Base64url) | `inviteCode` |
| Invite id (opaque) | `inviteId` |
| Per-process bridge identity | `deviceId` |
| Peer-link session | `sessionId` |
| Relay key authorization id | `relayKeyId` |
| Registered handle | `handle` |

---

## Rationale per row

### `messageId` (sender-generated, wire-stable)

The sender chooses this when the message is created and it survives unchanged
to every receiver, persistent store, and mutation reference. Crypto-grade
randomness or `ts_nnn` is fine; the only requirement is **the sender owns it
and the wire carries it**.

War story (2026-05-19): before consolidation, the sender used `clientMsgId`,
the receiver used the relay-assigned `eventId`, and the SQLite column was
`packetId`. Same logical message, three different identifiers depending on
which layer you asked. Mutations (edit / reaction / tombstone) reference the
sender's `messageId` over the wire — if the receiver stored anything else, the
reference dangled forever. Fix: one name, sender-owned, wire-stable, stored
as-is on both sides.

### `eventId` (relay envelope id, distinct concept)

This is the relay's per-envelope identifier on the deposit envelope (NOT the
encrypted payload). It is **not** a substitute for `messageId`. Use it only
for relay-level deduplication (the `#inboxDedup` LRU in `ServerEventService`).

### `accountId`, `ownerAccountId`, `senderAccountId`, `peerAccountId`

The four account-family names each play a distinct role; they are not
synonyms.

- `accountId` — bare account identifier, no role implied. Vault summary
  exposes it; generic records carry it.
- `ownerAccountId` — the account that *owns* a particular storage row or
  runtime context. A row stamped with `ownerAccountId` is owned by that
  local user. Distinct from `senderAccountId` because in group threads
  the row owner ≠ the message sender.
- `senderAccountId` — the author of an outbound message or mutation.
  Carried in encrypted payloads. On the receiver side, equals the
  receiver's `peerAccountId` for the corresponding direct thread.
- `peerAccountId` — each side's view of the *other* party. Replaces
  `remoteAccountId`. Appears on `peer-link.updated`, `Thread.peerAccountId`,
  and the mutation-dispatch context object.

### `inboxId` vs `peerInboxId` vs `mailboxId`

A peer-link involves two parties; each has an inbox. On a given side:

- `inboxId` — the **local** user's own inbox (lives on `InboxClaimant`)
- `peerInboxId` — the **peer's** inbox (lives on `Thread`, used as deposit destination)
- `mailboxId` — the protocol-layer name (rez-core / rez-node only); whichever inbox the substrate is naming

Never use bare `inboxId` for the peer's value or vice versa. Never use
`bindingTarget` / `bindingTargetInboxId` — they were leaky names for the
`peerInboxId` concept and are banned in rez-chat.

### `threadId`

Deterministic hash of the conversation parties:

- Direct thread: `"th_" + sha256("direct:v1|" + peerLinkId + "|" + peerAccountId)`
- Group thread: `"th_" + sha256("group:v1|" + groupId)`

The fact that both sides derive the same `threadId` independently is a
load-bearing invariant — do not assign threadIds centrally.

### `transferId` (file-transfer)

Owned by the file-transfer service. **Never** baked into a synthetic
`messageId` (the previous `"img_" + ts + "_" + transferId` pattern is banned —
see Phase 4 of the data-shape cleanup plan). A file-attached message carries
its own `messageId` and *references* the `transferId`; the two are
independent.

---

## Common confusion

### Vault `accountId` ≠ `peerAccountId`

If side A and side B have a peer-link:

- A's `vault.accountId` = A's identity = string X
- A's `peer-link.updated.peerAccountId` = A's view of B = string Y
- B's `vault.accountId` = B's identity = string Y
- B's `peer-link.updated.peerAccountId` = B's view of A = string X

These reference *different* people. Confusion arises because before
consolidation, the same field was named `accountId` on the snapshot and
`accountId` on the vault summary — making it look like "the same field".
Now: vault is `accountId`, snapshot is `peerAccountId`.

### `messageId` ≠ `eventId`

`messageId` is sender-owned and persists. `eventId` is relay-assigned per
envelope and is meaningful only inside the recipient's dedup LRU. Storing
`eventId` as the canonical message identifier is the bug that the 2026-05-19
integration test caught.

### `inboxId` is the same value as the old `bindingTarget` / `mailboxId`

If you find any of the three old names, rename it. Do not add a translation
layer.

---

## How this is enforced

The `bannedSymbols` rule `no-deprecated-id-names` in
`guardrails.config.json` greps for the deprecated names in `src/` and
`test/` across all workspaces. Allowlisted files:

- This file (`docs/IDENTIFIERS.md`) — it documents the bans
- SQLite migration files that rename columns
- The plan file at `_archive/` (if any historical references)

If a guardrail violation surfaces, the fix is to rename, not to add the file
to the allowlist.

---

## Cross-package ownership

| Workspace | Owns these identifiers' definitions |
|---|---|
| rez-sdk | `accountId` derivation; brand-typed asserters (Phase 5) |
| rez-core | `peerLinkId`, `sessionId` |
| rez-node | `inboxId`, `eventId` (envelope-level), `relayKeyId` |
| rez-chat | `threadId`, `messageId`, `groupId`, `transferId`, `handle` |
| rez-ui | (no identifier ownership; consumes records only) |

When an identifier is owned by one workspace but used in another, the
consuming workspace must import the name unchanged. No local renames.
