# INVITE_FLOW_SPEC

This document is normative. It defines Invite Protocol v1.

## 0. Scope and assumptions

- Rez Chat is a deployable consisting of a UI plus a required host runtime (node). There is no supported “web-only” mode.
- Invite creation and verification MUST be enforceable by the host runtime.
- Application semantics (invites, contacts, threads, indexes) are owned by rez-chat. `rez-sdk` exposes generic protocol and client capabilities that rez-chat consumes. The host runtime (`rez-node`) is substrate-only.

WS transport contracts:
- The chat bridge exposes `invite.create` with minimal params (e.g. expiry/maxUses).
- `invite.create` returns `{ inviteCode, expiresAtMs }`.
- The chat bridge exposes `invite.accept` with `{ inviteCode }`.
- `invite.accept` returns a chat-owned `{ threadId }` after rez-chat accepts the generic peer-link/invite result.

All required protocol fields MUST be carried inside `inviteCode`.

## 0.1 v0 defaults

- Default `maxUses = 1` for all invite kinds (`direct` and `group`).
- Default `expiresAt = now + 7 days` when request omits expiry.

## 1. Terms

- **Inviter**: The user who creates an invite.
- **Acceptor**: The user who accepts an invite.
- **Host**: The node runtime that custodies identity authority and storage substrate.
- **Invite envelope**: The structured payload that is signed and encoded into `inviteCode`.
- **Invite record**: The authoritative lifecycle record stored by inviter’s host (uses/status/expiry).

## 2. Signing authority (Decision A)

Invite envelopes MUST be signed by a keypair custodied by the host runtime.

- The signing authority is the inviter’s identity authority, custodied by the host keystore.
- Implementations MAY use either:
  1) the inviter identity signing key, or
  2) a dedicated invite signing keypair derived from the keystore root (recommended for compartmentalization).

The chosen scheme MUST provide:
- deterministic signing over canonical bytes
- deterministic verification
- a stable signer reference included in the envelope (`signerRef`)

## 3. InviteCode format (wire encoding)

`inviteCode` is an ASCII string with this structure:

rez:invite:v1:<payloadB64Url>.<sigB64Url>

Where:
- `payloadB64Url` is base64url (no padding) of the canonical JSON bytes for the Invite Envelope (section 4).
- `sigB64Url` is base64url (no padding) of the signature over the canonical payload bytes.

If a future version changes the envelope schema or signing algorithm, it MUST increment `vN` in the prefix (e.g. `v2`) and remain backward distinguishable by prefix.

## 4. Invite Envelope schema (payload)

The invite envelope is a JSON object with the following required fields (unless specified optional):

### Common fields
- `v` (number): MUST be `1`.
- `inviteId` (string): globally unique identifier (recommended: `inv_<ulid>` or equivalent).
- `kind` (string): `"direct"` or `"group"`.
- `createdAtMs` (number): inviter host epoch ms when created.
- `expiresAtMs` (number): epoch ms. MUST be > createdAtMs.
- `maxUses` (number): integer >= 1.
- `scope` (object): scope constraints. v1 MUST include:
  - `capabilities` (array of string): allowed capability operations. For v1 direct invites, this MUST include `"chat:dm"`. For group invites, MUST include `"chat:group"`.
- `binding` (object): reachability binding information required for accept.
- `signerRef` (object): identifies the signer used for verification.

### Transport request fields (create)

`invite.create` params MUST support:
- `kind`: `"direct"` or `"group"`
- `expiresAt`: request expiry timestamp in epoch ms
- `maxUses`
- optional `groupId` when `kind = "group"`

Runtime maps `expiresAt` to canonical envelope `expiresAtMs`.

### `binding` for direct invites
For `kind: "direct"`, `binding` MUST include:
- `mailboxId` (string): destination mailbox identifier where the acceptor may send first packets.
- `capabilityId` (string): capability identifier representing the current active capability for that mailbox.

Notes:
- `mailboxId` + `capabilityId` are protocol-level binding primitives. They are not UI-only concepts.

### `binding` for group invites
For `kind: "group"`, `binding` MUST include:
- `groupId` (string)
- `mailboxId` (string)
- `capabilityId` (string)
- `role` (string): `"member"` at minimum for v1.

Group rules are defined in `GROUP_MESSAGING_SPEC.md`.

### `signerRef`
`signerRef` MUST include enough information for verification:
- `accountId` (string) OR equivalent stable identity id
- `keyId` (string): identifies which signing key was used (identity signing key vs derived invite key)
- `alg` (string): signing algorithm identifier (e.g. `"ed25519"`)

## 5. Canonicalization and signing

### Canonical bytes
The payload JSON MUST be serialized deterministically before signing. Implementations MUST:
- Remove insignificant whitespace differences.
- Ensure stable key ordering.
- Ensure stable number formatting.

Canonicalization MUST be the same for signing and verification.

### Signature
- `sig = Sign(privateKey, canonicalPayloadBytes)`
- Verify MUST be `Verify(publicKey, canonicalPayloadBytes, sig)`

If verification fails, accept MUST reject without persisting success effects.

## 6. Invite lifecycle (authoritative inviter-side record)

Invites MUST be enforced by an authoritative lifecycle record stored by the inviter host runtime via SDK semantics.

Record fields:
- `inviteId`
- `kind`
- `createdAtMs`
- `expiresAtMs`
- `maxUses`
- `uses`
- `status`: `"active" | "used" | "expired" | "revoked"`
- `tokenHash`: a hash of the canonical payload bytes (or entire inviteCode). Hash algorithm MUST be stable (e.g. sha256).

Enforcement rules:
- If `now >= expiresAtMs`: reject accept, set status to `"expired"` if currently `"active"`.
- If `uses >= maxUses`: reject accept, set status to `"used"`.
- If `status` is `"revoked"`: reject accept.
- On successful accept, increment `uses`. If `uses == maxUses`, set status `"used"`.

Persistence:
- Invite records MUST be stored in app-managed namespaced KV keys (e.g. `app:chat:invites/...`).
- rez-node MUST NOT contain app namespace literals.

## 7. Accept semantics (side effects)

If and only if all checks pass (format, canonicalization, signature verification, lifecycle enforcement):

Accept MUST:
1) Create or update the Contact entry corresponding to the inviter identity.
2) Create a thread for the relationship:
   - Direct: create a DM thread bound to inviter identity.
   - Group: create/open the group thread and membership (per group spec).
3) Ensure the thread appears in `chat.listThreads` immediately.

Thread creation is a rez-chat semantic. The thread MUST exist even before any chat message is sent.

If any step fails, accept MUST be atomic:
- MUST NOT partially apply contact/thread state.
- MUST NOT increment uses on failure.

Group accept behavior in v0:
- Successful accept of a valid `kind: "group"` invite activates membership immediately.
- There is no pending/approval state in v0; user is in.

## 8. Thread identifier rules (direct invites)

For `kind: "direct"`, thread identity MUST be deterministic to prevent duplicates:

- ThreadId SHOULD be computed as a stable function of:
  - inviter identity id
  - acceptor identity id
  - and a constant domain separator `"dm:v1"`

This ensures accepting the same invite multiple times (within allowed uses) does not create multiple threads for the same pair.

If the system already has a canonical threadId derivation function, it MUST be used.

## 9. Error mapping

SDK services MUST return stable error codes for WS handlers to map:

- `INVITE_INVALID_FORMAT`
- `INVITE_UNSUPPORTED_VERSION`
- `INVITE_SIGNATURE_INVALID`
- `INVITE_EXPIRED`
- `INVITE_USED_UP`
- `INVITE_REVOKED`
- `INVITE_KIND_UNSUPPORTED`
- `INVITE_INTERNAL_ERROR`

WS layer returns these as structured errors per existing error conventions.

## 10. Security notes

- Invite envelopes are capability-bearing. The system MUST enforce maxUses/expiry authoritatively.
- `inviteCode` MUST be treated as secret. UI may present it to users but must not log it.
- `tokenHash` is stored instead of raw inviteCode where possible to reduce leakage.
- If invite payloads are shared over Rez message transport, relay operators cannot read invite contents (E2EE path).
- Out-of-band sharing is the primary practical exposure surface.
- A leaked invite does not allow impersonation; it allows join as the attacker's own account identity.
- Primary mitigation is default non-reusable invites (`maxUses = 1`) plus expiry.
