# Rez Architecture Guarantees (Canonical)

**Status:** Canonical  
**Applies to:** `rez-core`, `rez-sdk`, `rez-chat`, `rez-ui`, `rez-node`
**Rule:** If implementation violates these guarantees, implementation is incorrect.

---

## 1) Boundary guarantees

### 1.1 `rez-ui` is framework-only
- `rez-ui` owns rendering primitives/components/assets only.
- `rez-ui/src/apps`, `rez-ui/src/bootstrap`, and `rez-ui/src/platform` must not exist.
- `rez-ui` must not import `@rezprotocol/sdk`, `@rezprotocol/node`, or `@rezprotocol/core`.

**Enforcement**
- `rez-ui/test/framework.boundary.test.js`
- `scripts/invariants.mjs` (`scanUiFrameworkShape`, `scanUiForbiddenImports`, `scanUiForbiddenTerms`)

### 1.2 `rez-chat` app runtime integrates through SDK facade
- `rez-chat/src/app/**` must not import `@rezprotocol/core` or `@rezprotocol/node`.
- App runtime uses SDK facade + UI framework APIs.

**Enforcement**
- `rez-chat/test/app.boundary.test.js`
- `scripts/invariants.mjs` (`scanRezChatAppImportsSdkOnly`)

### 1.3 `rez-sdk` app-facing surface hides core primitive exports
- SDK may use core/node internals behind its facade.
- SDK client entrypoint must not re-export protocol/crypto primitive APIs from `@rezprotocol/core`.

**Enforcement**
- `rez-sdk/test/nomenclature.guardrails.test.js`
- `scripts/invariants.mjs` (`scanRezSdkClientSurface`)

---

## 2) Packaging/portability guarantees

### 2.1 SDK npm-style consumption must work from tarball
- `npm pack` tarball install must succeed in an isolated sample app.
- No workspace symlink assumptions are allowed.
- SDK tarball dependencies must not rely on `file:` or `workspace:*` declarations in the packaged manifest.

**Enforcement**
- `rez-chat/test/sdk.portability.test.js`

---

## 3) Runtime guarantees (chat app)

### 3.1 Chat boots from `rez-chat` browser runtime
- `rez-chat` owns browser entrypoints and build outputs under repo-root `artifacts/`.
- Chat app output is `artifacts/rez-chat`; UI framework output is `artifacts/rez-ui`.
- Host shell serves chat-owned artifacts from `artifacts/rez-chat` by default and may override via `CHAT_UI_ROOT`.
- `dist/` directories inside the repo tree are forbidden; guardrails fail when `dist/` appears.

### 3.2 App engine drives UI by intents/state
- App engine reduces SDK events to UI state.
- UI emits intents consumed by app engine.

**Enforcement**
- `rez-chat` runtime/integration tests (`test/index.wsUrl.integration.test.js`, `test/shell.startShellServer.test.js`)

---

## 4) Security/privacy guarantees

### 4.1 Protocol/crypto primitive ownership stays in core
- Primitive protocol/crypto definitions remain owned by `rez-core`.
- App and UI layers do not define primitive crypto behavior.

### 4.2 SDK is the only app-facing integration layer for internals
- Apps consume high-level SDK APIs, not primitive core types.

---

## Storage Ownership Doctrine

The rez-node package owns only:
- Transport (relay / ws)
- Protocol runtime
- StorageProvider implementations (fs, memory, future sqlite/redis)

rez-node MUST NOT contain application-specific storage semantics.
This includes (but is not limited to):
- Thread indexes
- Contact lists
- Invite lifecycle state
- Application-specific key namespaces

Application semantics are owned by rez-sdk (server layer).
All app-level data MUST be persisted via StorageProvider primitives
(ObjectStore, MailboxStore, KeyValueStore) using explicit app namespaces.

rez-chat MUST NEVER interact with storage directly.
rez-chat interacts only with rez-sdk.

Violations of this doctrine are considered architectural regressions.

---

## 5) Change control

Any intentional boundary/guarantee change requires all of:

1. Update this document.
2. Update tests/guardrails so the new rule is enforced.
