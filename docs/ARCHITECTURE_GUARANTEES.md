# Rez Architecture Guarantees (Canonical)

**Status:** Canonical  
**Applies to:** `rez-core`, `rez-sdk`, `rez-chat`, `rez-ui`, `rez-node`, `rez-contracts`
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

## 5) Economic guarantees

These hold for the token economy described in `rez-token-whitepaper.html`. Beta enforces them over off-chain credits; chain mode (testnet until mainnet) enforces the same invariants on-chain.

### 5.1 Atomic multi-leg settlement
- A paid service settles as one indivisible `settleService` operation: linked legs (debit / relay-credit / optional fee-credit) sharing one `settlementId`. Value is moved, never created or destroyed.
- The append-only `SettlementJournal` of `SettlementEntryV1` records is the single source of truth for balances and audit. `ReceiptLog` is a capped, user-facing projection and is never authoritative.
- Retries are idempotent (idempotency key); a crash mid-write heals on journal replay.

### 5.2 Fail-closed payment gating
- All paid services pass through one enforcement point (`ServiceGate`): capability check → pricing → settlement.
- An underfunded request fails closed with `PAYMENT_REQUIRED`; no service is rendered without a recorded settlement.

### 5.3 networkId binding
- Every economic artifact (settlement entries, receipts, attestations, storage proofs) is bound to an immutable pre-genesis `networkId`.
- Only artifacts carrying the official `networkId` may earn or convert. Private forks run on a distinct id and have no claim on the official economy.

### 5.4 Credit-class conservation
- Off-chain credits are one of two classes: `convertible` (capped at the 100M conversion reserve; converts 1:1 to REZ at mainnet) or `promotional` (never convertible).
- Class is conserved through every transfer, escrow, and slash (promotional in → promotional out; convertible in → convertible out).
- Class affects conversion and the liability cap only. It has zero bearing on emissions.

### 5.5 Immutable token & non-upgradeable custody
- The REZ token (owned by `rez-contracts`) is immutable: fixed 1B supply minted once, with no mint, owner, pause, blacklist, fee-on-transfer, or upgrade path. No staking, yield, or founder allocation.
- Undistributed pools sit in non-upgradeable custody vaults (`TreasuryVault`, `RewardsVault`, `ConversionDistributor`) that adjudicate their own release. Upgradeable machinery may propose distributions but can never drain beyond capped, finalized roots.
- These are concrete, testable invariants; `rez-contracts` carries the invariant tests that prove the absent surfaces.

**Enforcement**
- `rez-contracts` invariant/property tests (token surface, vault release caps).
- Settlement/journal and `ServiceGate` tests in `rez-node`.

**Honesty caveat:** the economic design is internally reviewed but **not externally audited**; a formal third-party audit is required before any mainnet deployment.

---

## 6) Change control

Any intentional boundary/guarantee change requires all of:

1. Update this document.
2. Update tests/guardrails so the new rule is enforced.
