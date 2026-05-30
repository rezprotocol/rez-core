# CONTACTS_SPEC

This document is normative for Contacts behavior in v0.

Related specs:
- `docs/STORAGE_MODEL.md`
- `docs/INVITE_FLOW_SPEC.md`
- `docs/GROUP_MESSAGING_SPEC.md`

## 0. Scope

v0 contacts is a lightweight identity relationship layer used by chat threads and invites.
It is SDK-owned semantics persisted in app namespace storage.

## 1. v0 Actions

The v0 contact surface MUST support:
- list contacts
- filter contacts
- rename contact (local alias)
- block contact
- unblock contact

These actions are state/semantics requirements, not UI requirements.

## 2. Invite Integration

- Direct and group invites can be initiated from contacts.
- Contact records are created/updated on successful invite acceptance.
- Invite defaults are inherited from invite spec:
  - invites are non-reusable by default (`maxUses = 1`)
  - default expiry applies per invite spec defaults

## 3. v0 Non-Goals

- No manual “add contact by account id” in v0.
- No separate approval workflow for invite-based contact creation in v0.

## 4. Contact States

Minimum relationship states:
- `active`
- `blocked`

Blocked contacts MUST be preserved in storage and shown as blocked in contact state.

## 5. Storage Ownership

- Contacts semantics and persistence are owned by SDK services.
- `rez-chat` consumes SDK contact state and actions.
- `rez-node` does not own contact semantics.
