# Storage Model

Status: canonical app-level storage model for chat v0/v1.

## 1. Operating Environments

### 1.1 Browser runtime
- IndexedDB is the browser storage substrate.
- App semantics are owned by SDK services, not by node runtime or UI framework.

### 1.2 Host runtime
- `rez-node` provides storage substrate implementations and transport runtime.
- `rez-node` remains substrate-only and unaware of app-level key semantics.

## 2. Application Namespace Rule

App-level state MUST use namespaced keys:
- `app:chat:*`
- `app::*`

`rez-node` storage providers are substrate only.
They are unaware of app semantics.

## 3. Chat Workload Requirements

### 3.1 Write pattern
- High append volume for messages.
- Frequent updates to message delivery state (`pending -> sent -> delivered` or `failed`).
- Thread metadata updates (`lastActivityAt`, preview, unread counters).

### 3.2 Read pattern
Required efficient reads:
- recent messages by thread with pagination
- thread list ordered by last activity
- unread counts per thread
- delivery status lookups by idempotency key/message id
- contact lookups by relationship state
- group membership lookups by `groupId` and by member

## 4. Conceptual Schema

All records are scoped by `accountId`.

### 4.1 `threads` store
Record:
- `threadId` (PK)
- `accountId`
- `kind` (`dm` | `group` | `unknown`)
- `createdAtMs`
- `updatedAtMs`

Indexes:
- `(accountId, threadId)` unique
- `(accountId, updatedAtMs DESC)`

### 4.2 `messages` store
Record:
- `messageId` (PK)
- `accountId`
- `threadId`
- `senderAccountId`
- `clientMsgId` (nullable)
- `status` (`pending` | `sent` | `delivered` | `failed`)
- `sentAtMs`
- `createdAtMs`

Indexes:
- `(accountId, threadId, createdAtMs DESC)`
- `(accountId, clientMsgId)` unique when present

### 4.3 `threadIndex` store
Record:
- `threadId` (PK)
- `accountId`
- `lastActivityAtMs`
- `lastActivityMsgId` (tie-breaker key)
- `lastMessagePreview` (nullable summary tag)
- `unreadCount`
- `lastReadAtMs` (nullable)
- `lastReadMsgId` (nullable)
- `lastUnreadCountedAtMs` (nullable)
- `lastUnreadCountedMsgId` (nullable)
- `updatedAtMs`

Rules:
- Ordering is deterministic:
  - `lastActivityAtMs DESC`, then `lastActivityMsgId DESC`, then `threadId ASC`.
- Preview is monotonic:
  - only messages with strictly newer `(createdAtMs, messageId)` may replace preview.
- `unreadCount` is idempotent and derived against read cursor fields.

### 4.4 `contacts` store (KV)

Contacts are stored in a key-value store. There is no separate primary key field; identity is derived from the key.

**Canonical key format:**
- `app:chat:contacts/{ownerAccountId}/{contactAccountId}`

**Stored value (per key):**
- `accountId` (owner; redundant with key, for convenience)
- `contactAccountId` (contact; redundant with key)
- `displayName` (optional alias; nullable)
- `relationshipState` (`invited` | `active` | `blocked`)
- `createdAtMs`, `updatedAtMs`
- `avatarFileHash`, `lastSeenAtMs` (optional; implementation-defined)

**Query patterns:**
- List by owner: list keys under prefix `app:chat:contacts/{ownerAccountId}/`, then get values.
- Fetch specific contact: get key `app:chat:contacts/{ownerAccountId}/{contactAccountId}`.
- Filter by relationship state: list by owner, filter in memory by `relationshipState`.

### 4.5 `invites` store
Record:
- `inviteId` (PK)
- `accountId`
- `kind` (`direct` | `group`)
- `groupId` (nullable)
- `tokenHash`
- `scope`
- `expiresAt`
- `maxUses`
- `uses`
- `status` (`active` | `used` | `expired` | `revoked`)
- `createdAtMs`

Indexes:
- `(accountId, status, expiresAt)`
- `(accountId, groupId, status)`
- `(accountId, tokenHash)` unique

v0 defaults:
- `maxUses = 1` unless explicitly overridden

### 4.6 `groups` store
Record:
- `groupId` (PK)
- `accountId`
- `title`
- `createdByAccountId`
- `createdAtMs`
- `updatedAtMs`

Indexes:
- `(accountId, createdAtMs DESC)`

### 4.7 `groupMembership` store
Record:
- `membershipId` (PK)
- `accountId`
- `groupId`
- `memberAccountId`
- `role` (`admin` | `member`)
- `state` (`active` | `left` | `removed`)
- `joinedAtMs`
- `updatedAtMs`

Indexes:
- `(accountId, groupId, state)`
- `(accountId, memberAccountId, state)`
- `(accountId, groupId, memberAccountId)` unique

## 5. Consistency Rules

- Storage writes for invite accept side effects must be atomic at service level.
- `chat.listThreads` is derived from SDK-owned persisted index state.
- Group join via valid invite creates/ensures membership with `state = active`.
