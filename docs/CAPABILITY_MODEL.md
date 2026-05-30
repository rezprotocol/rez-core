# Capability Model

Status: canonical / normative.
Scope: v1 of Rez's authorization model. Designed alongside the Shape A migration (2026-05).
Audience: rez maintainers.

This document defines who signs capability tokens, who verifies them, and what gets carried on the wire. It is the trust-root spec for every node-bound operation in Rez.

If this document and the code disagree, the document is canonical and the code is wrong. Update the code to match, or — if a deliberate design change is needed — update this document in the same PR.

## 1) Core principle

**The inbox claimant is the trust root for every capability covering that inbox. The node is a verifier only — it never signs.**

Every capability traces, through a chain of signatures, back to the keypair that originally claimed the inbox it covers. This makes capabilities portable (an inbox can move between nodes without invalidating outstanding capabilities, as long as the claimant pubkey is unchanged) and prevents any concept of "node-authority over a user's data."

A consequence: if you change nodes, your outstanding caps remain valid because they were never tied to the node's signature in the first place. Move your inbox to a different node, re-claim it with the same keypair, and previously-issued caps still verify.

## 2) Per-inbox root capability

When an SDK claims a new inbox (see §6), it locally constructs and stores a root capability:

```
RCapability {
  resource:     "inbox:<inboxId>",
  actions:      ["admin", "grant", "read", "write"],
  signerRef:    { pubkey: <claimantPublicKeyB64> },
  signatureB64: <sig by claimant privkey over canonical cap bytes>,
  constraints:  {}
}
```

The action vocabulary is shared with the rest of the cap system (`admin | connect | grant | post | read | write`). Inbox semantics map naturally:

- **`admin`** — full owner control (close the inbox, change its policy).
- **`read`** — list and fetch items; subscribe to deposit events.
- **`write`** — modify inbox state including delete-by-id and inbox settings.
- **`grant`** — sign sub-caps delegating limited rights to other principals.
- **`post`** — open deposits are allowed without any cap presented; the action is reserved if a future inbox wants restricted deposits.

- The cap lives on the SDK side, in the SDK's storage.
- It never travels alone to the node. The node knows the claimant pubkey from the inbox-claim registry (§5); the root cap is only presented as the head of a delegation chain (§3), or implicitly proven by the session binding (§4).
- Anonymous deposits are allowed by default. To restrict who can deposit, the inbox owner publishes a `deposit-policy` record signed with the claimant key — outside the scope of the cap chain.

## 3) Delegation (sub-capabilities)

To grant another principal limited rights, the holder of a cap that includes `"grant"` signs a sub-cap:

```
RCapability {
  resource:     "inbox:<inboxId>",     // same as parent (or a sub-resource)
  actions:      <subset of parent actions, typically excludes "grant">,
  signerRef:    { pubkey: <granter pubkey> },     // claimant for first-level grants
  signatureB64: <sig by granter privkey>,
  grantee:      { pubkey: <recipient pubkey> },
  parent:       <ref to parent cap (cap id or full chain)>,
  constraints:  { expiresAtMs?, maxUses?, ... }
}
```

Chains are presented as ordered arrays. Each link's signature is verified against the previous link's grantee. The chain root's signature is verified against the inbox's registered claimant pubkey.

**v1 scope: root caps only, with sub-cap machinery in place from day one.** No v1 product feature uses delegation. The record shape, signing API, and verification logic exist and are tested, but no chat / SDK code path produces or consumes sub-caps. Delegation becomes a live feature when first needed.

## 4) Session binding (the fast path)

Most operations are an SDK operating on inboxes it owns itself. Carrying a full cap chain for each is unnecessary overhead.

On `session.authenticate`, the SDK presents:

```
{
  claimedInboxIds:   [<inboxId>, ...],
  signedChallengeB64: <sig over (challenge, claimedInboxIds) by claimant privkey>
}
```

The node validates the signature against each `claimedInboxId`'s registered claimant pubkey. The session is then bound to that claimant pubkey and the set of validated inboxes.

For the duration of the session:
- Operations targeting any inbox in the bound set are authorized implicitly — the session binding is the proof. No cap chain needed on the wire.
- Operations targeting other inboxes (delegated access) require an explicit cap chain.

This keeps the common case (chat-server operating on its own inbox) zero-overhead.

If an SDK claims new inboxes mid-session, it sends an incremental binding update with the same shape and the node extends the bound set.

## 5) Inbox-claim registry (node-side state)

The node maintains, persistently, one mapping:

```
inboxId → {
  claimantPublicKeyB64,
  claimedAtMs
}
```

This is the entire universe of what the node knows about an inbox's ownership. The node does **not** know which account claims it, does **not** know the claimant's other identifiers, does **not** correlate inboxes by claimant pubkey or otherwise.

Lookups: O(1) by `inboxId`.

## 6) First-time claim (open registration)

A new wire op `inbox.claim`:

```
Request:
{
  inboxId:              "inbox:<random>",        // SDK-generated
  claimantPublicKeyB64: "<pubkey>",
  claimedAtMs:          <ms>,
  signatureB64:         "<sig over (inboxId, claimantPublicKey, claimedAtMs)>"
}

Response (success):
{ ok: true, inboxId }

Response (failure):
{ error: { code: "INBOX_ALREADY_CLAIMED" | "INVALID_SIGNATURE" | ... } }
```

Node accepts (open registration: no allowlist, no gate). Stores `inboxId → claimantPublicKeyB64`. If `inboxId` already exists, claim fails. Collision is statistically impossible with random IDs but defended explicitly.

After claim, subsequent sessions use `session.authenticate` (§4) to bind.

The inbox ID itself is generated client-side as an opaque random value. It MUST NOT be derived from the claimant pubkey or any account identifier — derivation creates a correlation primitive a node operator could exploit.

## 7) Verification flow (node-side, for owner-scoped requests)

For each owner-scoped request on `inbox:<X>`:

1. If the WS session is bound to a claimant pubkey that owns `X`: pass — session-binding is the proof.
2. Else, the request must carry an explicit cap chain:
   - Validate each link's signature against the previous link's grantee pubkey.
   - The chain root's signature must verify against the registered claimant pubkey for `X`.
   - The leaf cap's `actions` must cover the requested operation.
   - All `constraints` (expiry, etc.) must be satisfied.
   - The request itself must be signed by the leaf cap's grantee pubkey (proves the principal, not just a holder of a stolen cap).

The node performs no signing operations during this flow.

## 8) Multi-account, multi-inbox

An SDK may hold many `(inboxId, claimantPublicKeyB64, nodeId, wsUrl)` rows in its storage. Each pair can use a different claimant keypair — the node cannot correlate inboxes claimed under distinct pubkeys, even from the same SDK instance.

The SDK is responsible for the user-side mapping of `accountId → set-of-(inboxId, ...)`. None of that flows to a node.

This is a privacy primitive, not just a convenience: a single account can spread its inboxes across multiple nodes with different keypairs per inbox, and no node operator (or anyone with traffic visibility at one node) can prove two inboxes belong to the same account.

## 9) What changes from the pre-rework state

Before this rework:
- The node minted `mailbox:<localInboxId>` and `object:<accountId>` caps at `session.authenticate`, signed with its own privkey.
- `session.authenticate` carried `accountId + signed challenge`. Caps referenced `accountId` in the resource string.
- The `object:` namespace existed as half-built scaffolding with no consumers.
- Inbox derivation on the node side used a deterministic transform of accountId (`inbox:hosted:<sanitized accountId>`), making inbox→account correlation trivial.

After this rework:
- The node does not sign caps. Anywhere in code where the node's privkey was passed to `CapabilitySigner.createRootCapability`, that call is removed.
- `session.authenticate` carries `claimedInboxIds[] + signed challenge`. No `accountId` on the wire to the node.
- The `object:` namespace is removed wholesale. Architecture preserved in memory for a future correctly-shaped rebuild.
- Inbox IDs are SDK-generated random tokens. The node never derives them.

## 10) Primitives that survive unchanged

`RCapability`, `CapabilitySigner`, `CapabilityVerifier`, `RootCapability` (in rez-core / rez-sdk) keep their shape and semantics. What changes is **who calls them with what key**: today the node calls `CapabilitySigner` with its own privkey; after the rework, the SDK calls it with the claimant privkey. Both ends use `CapabilityVerifier` against the correct trust root (the node for incoming requests; the SDK if it ever needs to validate a cap presented to it).

Any default-signer / default-pubkey baked into these primitives that assumes node-authority must be audited and removed.

## 11) Out of scope for v1

- Delegation use cases (covered in §3 but not exercised). Sub-cap signing, multi-link chain verification, and constraint enforcement (expiry, max uses) are implemented and tested, but no v1 product surface produces or consumes a sub-cap.
- Capability revocation lists. v1 relies on `expiresAtMs` for time-bounded delegation. Revocation-before-expiry needs a published-revocations record published by the inbox owner; design deferred.
- Cross-inbox capability composition (e.g., a cap that covers two inboxes simultaneously). v1 caps are scoped to a single `inbox:<inboxId>` resource.
- Hierarchical resource scopes within an inbox (`inbox:X/folder:Y/object:Z`). Single-level only in v1.
