# GROUP_MESSAGING_SPEC

This document is normative. It defines group messaging semantics required by Invite Protocol v1.

## 0. Scope

This spec defines:
- group identity (`groupId`)
- membership persistence rules
- thread mapping rules
- the minimum fields required for group invites

It does not define UI rendering.

## 1. Terms

- **Group**: a chat context with 3+ members.
- **Membership**: association of an identity with a group with a role.
- **Group thread**: a thread representing the group chat.

## 2. Group identifiers

- `groupId` is a globally unique identifier, recommended format: `grp_<ulid>`.

## 3. Roles (v1 minimum)

v1 roles:
- `"member"` (minimum)
Implementations MAY add `"admin"` later, but v1 MUST at least support `"member"`.

## 3.1 v0 Authority Rules

v0 authority is explicit and immediate:
- Group creator is admin.
- Only admin can create invites.
- Only admin can remove members.
- Only admin can trigger key/material rotations (when enabled).
- Members can read and send messages.

## 4. Membership persistence (SDK-owned)

Membership MUST be persisted via SDK semantics using StorageProvider primitives and namespaced keys.

Minimum membership record:

```json
{
  "groupId": "grp_...",
  "memberAccountId": "rez:acct:...",
  "role": "member",
  "joinedAtMs": 0
}
```

Required KV layout (SDK-only namespace):
- `app:chat:groups/<groupId>` → group record (at minimum: `{ groupId, createdAtMs }`)
- `app:chat:groups/<groupId>/members/<accountId>` → membership record
- Optional index:
- `app:chat:groups/<groupId>/members/index` → list of members (bounded)

rez-node MUST NOT contain these namespace literals.

## 5. Group thread mapping rules

A group MUST map to exactly one group thread.

ThreadId derivation:
- ThreadId SHOULD be deterministic from:
- `groupId`
- domain separator `"group:v1"`

If a canonical threadId derivation exists, use it.

The group thread record MUST include:
- `threadId`
- `kind: "group"`
- `groupId`
- `createdAtMs`

Stored under SDK thread store keys (as defined in INVITE spec thread store rules).

## 6. Group invite required fields (from INVITE_FLOW_SPEC binding)

For `kind: "group"`, invite binding MUST include:
- `groupId`
- `mailboxId`
- `capabilityId`
- `role` (minimum `"member"`)

The invite scope MUST include `"chat:group"`.

## 6.1 Invite delivery modes

Invite Member flow MUST support two delivery modes:
- Out-of-band invite sharing (copy string / QR): required to invite strangers without an existing DM.
- In-app DM delivery: optional convenience path when a DM thread already exists.

Out-of-band flow is first-class and not a fallback-only mode.

## 6.2 Invite safety defaults

- Group invites are non-reusable by default (`maxUses = 1`).
- Default expiry is inherited from invite spec defaults.
- Reusable group invites are optional advanced behavior and are not the v0 default.

## 7. Accepting a group invite (required side effects)

On successful accept of a group invite:
1. Ensure group record exists:
- create `app:chat:groups/<groupId>` if absent.
2. Ensure membership record exists for acceptor:
- create `members/<accountId>` if absent.
3. Ensure group thread exists:
- `threadStore.ensureThread({ threadId, kind:"group", groupId })`
4. Ensure it appears in `chat.listThreads` immediately:
- upsert a thread index entry with a system preview such as `"Joined group"`.

All steps MUST be atomic with respect to accept success; partial membership without thread is not allowed.
There is no admin approval gate in v0; valid invite acceptance joins immediately.

## 8. Error mapping (group)

- `GROUP_INVITE_MISSING_FIELDS`
- `GROUP_ROLE_UNSUPPORTED`
- `GROUP_ALREADY_MEMBER` (non-fatal; accept may be idempotent)
- `GROUP_INTERNAL_ERROR`
