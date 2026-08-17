# Consolidated Security Findings

Original audit: 2026-06-07 · **Re-baselined: 2026-08-17** (rez-core#2)

Scope: `rez-core`, `rez-sdk`, and `rez-chat` security audit findings. This document is a working remediation tracker, not a disclosure advisory.

> **Moved 2026-08-17.** This lived at the polyrepo root, which is not a git repo — so
> the tracker for three repos' security findings was itself unversioned, unbacked-up,
> and invisible to anyone who did not have the working tree. It now lives in
> `rez-core/docs/` and is tracked. It spans three repos and is filed under `rez-core`
> because that is where the issue tracking it lives (rez-core#2); cross-repo findings
> stay in this one file rather than being split, so there is a single place to look.

> **Suspected vulnerabilities do not belong here.** This is a tracker for findings
> already known to the maintainers. Report new ones privately per
> `rez-chat/SECURITY.md` — not as a public issue, and not by appending here.

## Re-baseline, 2026-08-17

Every finding was re-checked against the tree at `v0.6.0-rc.6`. Each now carries a
**Re-baselined** line with the evidence that decided it. Two things changed the
picture more than any individual fix:

**The desktop shell changed.** CHAT-1/2/3 were written against `electron/main.mjs`.
The shipped app is now Tauri — `src-tauri/src/*.rs` is a *port* of the Electron
runtime, and `desktop-build.yml` builds only the Tauri bundle. The Electron tree
still exists and still has its `desktop:pack:*` scripts, but nothing a tester
installs runs it. Findings against it were re-checked **against the Tauri shell**,
which is the one that ships; where the answer differs, both are stated.

**"Open" was doing too much work.** The old table counted a wrong-but-unreachable
guard the same as a live gap. Status is now split: *Open* means reachable today,
*Open (not reachable)* means the code is wrong but no caller can get there — worth
fixing, not worth alarm.

### Status summary

| Repo | Open | Open (not reachable) | Closed | Not applicable |
| --- | ---: | ---: | ---: | ---: |
| `rez-core` | 3 | 0 | 1 | 0 |
| `rez-sdk` | 5 | 0 | 0 | 0 |
| `rez-chat` | 0 | 0 | 2 | 2 |

- **Fixed in this pass:** CORE-1.
- **Closed on re-check:** CHAT-1 (has regression cover), CHAT-4 (was already fixed).
- **Not applicable to the shipped app:** CHAT-2, CHAT-3 — both are Electron-shell IPC
  findings, and the shipped Tauri shell exposes neither surface.
- **Still open, unchanged:** CORE-2, CORE-3, CORE-4, SDK-1 … SDK-5.

None of the still-open findings is an alpha blocker: none is remotely reachable by
an unauthenticated party, and the highest-severity two (SDK-1, SDK-2) are hardening
of a trust boundary rather than a known bypass. That is an assessment, not a
dismissal — see each finding.

## Canonical Specs Checked

- `rez-core/docs/security.md`
- `rez-core/docs/SECURITY_POSTURE.md`
- `rez-core/docs/CAPABILITY_MODEL.md`
- `rez-core/docs/ACCOUNT_SYSTEM.md`
- `rez-chat/ARCHITECTURE.md`
- `rez-chat/docs/CHAT_APP_SPEC.md`
- `rez-chat/docs/SECURITY_AUDIT.md`
- `rez-chat/SECURITY.md`

## rez-core

### CORE-1: Filesystem datastore path containment is prefix-based

Status: **CLOSED 2026-08-17** (was Open / High)

Re-baselined 2026-08-17 — FIXED. Both halves, and they had different severities:

- **`#pruneEmptyDirs` prefix check** — real bug, **never reachable**. Prune is only
  ever seeded from an already-validated in-base path and stops the moment it walks
  up to the root, so no caller could hand it an outside path. Tests pinning this are
  labelled characterization, not regression: they pass against the old code too, and
  the test file says so rather than implying a catch.
- **`list(prefix)`** — this one WAS reachable. `list` is public and joined prefix
  segments raw, with none of the `.`/`..` validation keys get, so `list("../../etc")`
  built a path outside the store and `#collectFiles` walked it. The containment
  assert in `#pathToKey` only fired afterwards, once the traversal had happened.

Validation is now centralized in one `#validatedSegments` helper shared by keys and
prefixes, and containment uses `path.relative` (the form already correct in
`#pathToKey` — the two had simply drifted). Prefixes still tolerate a trailing empty
segment, because `list("mbox/a/evt/")` is an established convention and the empty
segment is inert; an existing test caught that on the first attempt.

Also removed the catch-all in `#pruneEmptyDirs` that swallowed every error: benign
races (ENOENT, ENOTEMPTY) are absorbed, real storage faults (EIO, EACCES) now
surface. That one IS a behavioural regression guard and fails against the old code.

Cover: 8 cases in `rez-core/test/storage.filesystem.test.js`.

Severity: High

Evidence:
- `rez-core/src/storage/fs/FileSystemDataStore.js:19` builds paths from key segments.
- `rez-core/src/storage/fs/FileSystemDataStore.js:57` builds `list(prefix)` paths directly from `prefix.split("/")`.
- `rez-core/src/storage/fs/FileSystemDataStore.js:151` uses `resolved.startsWith(this.#basePath)` for containment.

Impact:
`startsWith` is not a safe filesystem containment check because sibling paths can share a string prefix, for example `/tmp/base2` starts with `/tmp/base`. `list(prefix)` also does not run the same segment validation as `#keyToPath`, so hostile prefixes can make the store touch directories outside the intended tree before later checks trip.

Recommended fix:
Centralize key/prefix validation. Resolve every candidate path and require `path.relative(base, candidate)` to be non-empty, not start with `..`, and not be absolute. Apply the same containment helper to `put`, `get`, `list`, `delete`, and prune paths.

### CORE-2: `ProfilePayloadV1` preserves untrusted extras with prototype-mutable objects

Status: Open

Re-baselined 2026-08-17 — UNCHANGED, still open. `ProfilePayloadV1.js:46` still does
`Object.assign({}, rest)` and `:76` still parses untrusted bytes with bare
`JSON.parse`. Reachable by any peer that can send a profile.

Severity: Medium

Evidence:
- `rez-core/src/objects/profile/ProfilePayloadV1.js:46` stores `extras` via `Object.assign({}, rest)`.
- `rez-core/src/objects/profile/ProfilePayloadV1.js:50` merges extras back into the JSON object.
- `rez-core/src/objects/profile/ProfilePayloadV1.js:74` parses untrusted bytes with `JSON.parse`.

Impact:
Profile payloads accept arbitrary extra fields and copy them through normal objects. Payloads containing `__proto__`, `constructor`, or `prototype` keys can mutate object prototypes or poison downstream consumers that spread/assign the payload again.

Recommended fix:
Reject dangerous keys at parse/construction boundaries or clone into `Object.create(null)`. Prefer an explicit typed schema for extension fields.

### CORE-3: Stale object/capability namespace surfaces remain after capability rework

Status: Open

Re-baselined 2026-08-17 — UNCHANGED, and now with sharper evidence: the split-brain
is confirmed in both directions. `CAPABILITY_MODEL.md:162` still says the `object:`
namespace "is removed wholesale", while `rez-core/src/index.js:31` still does
`export * from "./objectstore/index.js"` — so the surface the spec calls removed is
exported from the package root. Documentation drift, not an exploit.

Severity: Medium

Evidence:
- `rez-core/docs/CAPABILITY_MODEL.md:151` says `object:` was removed in the rework.
- `rez-core/docs/CAPABILITY_MODEL.md:162` says the `object:` namespace is removed wholesale.
- `rez-core/src/objectstore/RObjectStore.js` still provides object-store primitives.

Impact:
The canonical capability model says object namespace support was removed, but code paths and exports still present object storage concepts. That creates split-brain ownership and risks future callers binding authorization to stale semantics.

Recommended fix:
Either remove the stale object-store surface from public exports or update the capability spec with the current owner, authorization model, and tests. Do not leave the namespace half-live.

### CORE-4: `E2eePacketCodec.decryptIncoming` drops handshake signature context

Status: Open

Re-baselined 2026-08-17 — UNCHANGED. `E2eePacketCodec.js:81` still returns
`handshake: record.handshake` with no `signatureB64`. Note the live E2EE path does
not use this codec for handshakes (see `reference_rezsdk_e2ee_stale_shims`), so this
is an API that invites an unsafe split rather than a live one.

Severity: Medium

Evidence:
- `rez-core/src/e2ee/E2eePacketCodec.js:74` detects handshake control messages.
- `rez-core/src/e2ee/E2eePacketCodec.js:76` validates the handshake packet record.
- `rez-core/src/e2ee/E2eePacketCodec.js:77` returns only `record.handshake`, not `signatureB64`.
- `rez-core/src/e2ee/E2eePacketCodec.js:127` documents that `signatureB64` is required.

Impact:
Callers using this generic codec receive a handshake object without the signature needed to authenticate it. Other code may parse packets directly and preserve signatures, but the codec API itself encourages an unsafe split.

Recommended fix:
Return the full validated handshake packet record or include both `handshake` and `signatureB64` in the structured result. Add a regression test that a codec round trip preserves signature material.

## rez-sdk

### SDK-1: `FrameCodec` forwards untrusted JSON bodies without prototype hardening

Status: Open

Re-baselined 2026-08-17 — UNCHANGED. `FrameCodec.js:17` still `JSON.parse`s raw
frames and `:37` still returns `parsed.body` directly. Highest-value remaining item:
it is the trust boundary every remote frame crosses.

Severity: High

Evidence:
- `rez-sdk/src/transport/FrameCodec.js:17` parses raw JSON frames.
- `rez-sdk/src/transport/FrameCodec.js:33` returns frame fields.
- `rez-sdk/src/transport/FrameCodec.js:37` returns `parsed.body` directly when it is an object.

Impact:
Remote frame JSON can carry dangerous object keys into SDK handlers. Even if individual handlers validate some fields, the codec is the trust boundary and should not pass mutable, prototype-bearing objects into the rest of the system.

Recommended fix:
Parse into hardened/plain-data records. Strip or reject `__proto__`, `constructor`, and `prototype` recursively before returning frame bodies.

### SDK-2: Session identity still has account/inbox split-brain

Status: Open

Re-baselined 2026-08-17 — UNCHANGED. `rez-sdk/src/protocol/index.js:61` still
resolves `accountId` from `sessionInfo.accountId` with a fallback and returns it as
session identity.

Severity: High

Evidence:
- `rez-core/docs/CAPABILITY_MODEL.md:161` says session auth carries `claimedInboxIds[]` and no account id on the wire.
- `rez-sdk/src/protocol/index.js:59` resolves session identity from `sessionInfo.accountId` or a fallback.
- `rez-sdk/src/client/WsConnection.js:58` passes `accountId` into the auth state machine.
- `rez-sdk/src/client/WsConnection.js:63` separately passes `accountIdentityPublicKeyB64`.

Impact:
The SDK still has two notions of identity: account identity and claimed inbox identity. This can confuse callers about what the node actually authenticated and can accidentally reintroduce account-to-inbox correlation that the capability model explicitly tries to avoid.

Recommended fix:
Make the public session result inbox-first. Treat account id as local SDK/app metadata only, never as node-authenticated remote state. Add tests proving `session.ready` cannot establish account ownership without local account-binding verification.

### SDK-3: Public client surface exposes low-level capabilities directly

Status: Open

Re-baselined 2026-08-17 — UNCHANGED. `RezClient.js` still exposes `mailbox` (:601),
`durableRecords` (:605), `node` (:609) and `mesh` (:638) as public getters. Line
numbers moved; the surface did not.

Severity: Medium

Evidence:
- `rez-sdk/src/client/RezClient.js:82` constructs low-level capabilities.
- `rez-sdk/src/client/RezClient.js:444` exposes `mailbox`.
- `rez-sdk/src/client/RezClient.js:448` exposes `durableRecords`.
- `rez-sdk/src/client/RezClient.js:452` exposes `node`.
- `rez-sdk/src/client/RezClient.js:468` exposes `mesh`.

Impact:
Applications can bypass higher-level sealed/message-safe flows and invoke mailbox/node primitives directly. That increases the chance of plaintext deposits, incorrect authorization, and app-specific protocol logic leaking into app code.

Recommended fix:
Keep low-level capabilities internal or explicitly mark them as privileged/advanced. Provide narrow app-safe operations for common workflows and enforce encrypted-by-default paths.

### SDK-4: `sendPayload` remains a plaintext footgun

Status: Open

Re-baselined 2026-08-17 — UNCHANGED. `RezClient.js:295` still exposes `sendPayload`,
which base64s caller bytes into a field named `ciphertextB64`. The safer
`sealForPeer` (:339) exists alongside it, which is precisely the confusion.

Severity: Medium

Evidence:
- `rez-sdk/src/client/RezClient.js:287` exposes `sendPayload`.
- `rez-sdk/src/client/RezClient.js:295` base64-encodes `params.payloadBytes` directly into `ciphertextB64`.
- `rez-sdk/src/client/RezClient.js:324` separately provides the safer `sealForPeer` API.

Impact:
The field name `ciphertextB64` implies encrypted data, but `sendPayload` accepts arbitrary caller bytes. A caller can accidentally deposit plaintext while believing the SDK encrypted it.

Recommended fix:
Rename or deprecate `sendPayload`, or require a sealed/encrypted packet type. Route direct-message sends through `sealForPeer` plus `mesh.dispatch`.

### SDK-5: Non-crypto randomness is used for IDs/keys

Status: Open

Re-baselined 2026-08-17 — UNCHANGED in substance, narrowed in scope. `Math.random()`
remains in `UplinkPoolClient.js:29` (device id — the one that matters, it
participates in session identity metadata), `RezClient.js:297`,
`MeshCapability.js:70` and `SubscriptionCapability.js:41`.

One call site should be struck from this finding: `ConnectionStateMachine.js:112`
uses `Math.random()` for **reconnect jitter**, which is not an identifier and where
non-crypto randomness is correct.

Severity: Low / Medium

Evidence:
- `rez-sdk/src/client/UplinkPoolClient.js:29` falls back to `Math.random()` for device ids.
- `rez-sdk/src/client/RezClient.js:289` uses `Math.random()` for payload object ids.
- `rez-sdk/src/capabilities/MeshCapability.js:72` uses `Math.random()` for object ids.
- `rez-sdk/src/capabilities/SubscriptionCapability.js:41` uses `Math.random()` for subscription keys.

Impact:
Most of these IDs are not cryptographic secrets, but collisions and predictability are avoidable. The device-id fallback is especially worth tightening because it participates in session identity metadata.

Recommended fix:
Require `crypto.randomUUID()` or `crypto.getRandomValues()` for SDK-generated identifiers. If unavailable, throw a clear configuration error rather than silently weakening randomness.

## rez-chat

### CHAT-1: Vault lock/autolock does not always disconnect chat runtime

Status: **CLOSED**

Re-baselined 2026-08-17 — closed, with regression cover that pins the exact failure
modes this finding described. `rez-chat/test/desktop.vault-lock-fail-closed.test.js`
asserts that `lock()` tears the chat runtime down and not just the vault, that a
teardown which throws escalates to terminal shutdown, that one which fails SILENTLY
is caught by a post-condition and escalated, that `LOCK_INCOMPLETE` is raised when
even that fails, and — closing the original evidence directly — that the supervisor
constructor ALWAYS registers the auto-lock handler.

Severity: High

Evidence:
- `rez-chat/docs/CHAT_APP_SPEC.md:130` requires fail-closed locked-state teardown.
- `rez-core/docs/ACCOUNT_SYSTEM.md:70` requires logout to disconnect active transport/session and clear secret handles.
- `rez-chat/electron/main.mjs:542` constructs `DesktopVaultService` without `onAutoLock`.
- `rez-chat/electron/runtime/DesktopVaultService.mjs:1188` autolock calls `this.lock()`.
- `rez-chat/electron/runtime/DesktopSupervisor.mjs:140` `lock()` only locks the vault.
- `rez-chat/src/ui/services/bus/SessionService.js:364` is the normal UI path that disconnects first.

Impact:
The ordinary UI lock path disconnects correctly, but lower-level Electron/vault paths do not. Direct `desktop:vault:lock` and idle/absolute autolock can leave the bus bridge/chat server alive after the vault reports locked, retaining active runtime state longer than the fail-closed spec permits.

Recommended fix:
Make `DesktopSupervisor.lock()` own the full teardown: detach bus bridge, stop chat server, then lock vault. Pass an `onAutoLock` callback from `main.mjs` that calls supervisor disconnect/lock lifecycle. Add tests for explicit lock and timer autolock.

### CHAT-2: `desktop:scrypt` IPC allows renderer-driven main-process DoS

Status: **NOT APPLICABLE to the shipped app** (open in the legacy Electron shell)

Re-baselined 2026-08-17. The shipped Tauri shell has **no scrypt IPC at all** — its
entire invoke surface is seven commands (`desktop_get_app_info`,
`desktop_open_external`, `desktop_notify`, `updates_get_status`,
`updates_restart_and_install`, `backup_save_to_file`, `backup_open_file`), and
`grep -rn scrypt src-tauri/src/` returns nothing.

The handler still exists at `electron/main.mjs:300`, which is not built by
`desktop-build.yml` and not in any release artifact. It has also since grown the
bounds checks the finding asked for (power-of-two `N` capped at 2^20, salt ≥ 16
bytes). Kept on the tracker rather than deleted, because the Electron tree is still
in the repo with working `desktop:pack:*` scripts — if it is ever revived, this
comes back with it.

Severity: Medium

Evidence:
- `rez-chat/electron/main.mjs:277` exposes `desktop:scrypt`.
- `rez-chat/electron/main.mjs:290` caps `N`.
- `rez-chat/electron/main.mjs:293` only requires `r >= 1`.
- `rez-chat/electron/main.mjs:294` only requires `p >= 1`.
- `rez-chat/electron/main.mjs:300` computes memory from caller-controlled `N * r`.

Impact:
A compromised renderer can request expensive scrypt parameters and tie up or crash the main process. The IPC exists for legitimate auth work, but it needs bounded profiles rather than arbitrary work factors.

Recommended fix:
Use named KDF profiles or strict caps for `N`, `r`, `p`, and total `maxmem`. Reject values outside the profiles used by the vault/keystore.

### CHAT-3: Vault metadata mutation IPC is available without unlock/password confirmation

Status: **NOT APPLICABLE to the shipped app** (Electron-shell only)

Re-baselined 2026-08-17. No vault-metadata mutation command exists in the shipped
Tauri invoke surface (see CHAT-2 for the full seven-command list). Same standing
caveat: the Electron tree remains in the repo, so this returns if that shell is
revived.

Severity: Low / Medium

Evidence:
- `rez-chat/electron/runtime/registerDesktopIpc.mjs:79` exposes `disableDeviceUnlock`.
- `rez-chat/electron/runtime/registerDesktopIpc.mjs:83` exposes `setProfileName`.
- `rez-chat/electron/runtime/DesktopVaultService.mjs:411` disables device unlock by account id.
- `rez-chat/electron/runtime/DesktopVaultService.mjs:421` mutates profile name by account id.

Impact:
This does not expose private keys or mnemonic material, but a compromised renderer can alter account metadata or disable biometric convenience while locked. That is local integrity degradation and can create account confusion.

Recommended fix:
Require an active unlocked account, password confirmation, or a narrower trusted UI flow for mutating vault metadata. At minimum, treat `disableDeviceUnlock` as a sensitive operation.

### CHAT-4: Direct-thread fallback resolver could misroute messages

Status: Closed in current workspace / needs regression

Severity: High

Evidence:
- Earlier audit found `ServerEventService.#resolveDirectThreadForSender` shadowing `peerAccountId`, making the comparison self-equal.
- Current code at `rez-chat/src/server/services/ServerEventService.js:543` defines the target `peerAccountId`.
- Current code at `rez-chat/src/server/services/ServerEventService.js:556` uses `candidatePeer`.
- Current code at `rez-chat/src/server/services/ServerEventService.js:557` compares `candidatePeer === peerAccountId`.

Impact:
The original defect could have routed an authenticated peer message without a valid `threadId` into the first ready direct thread. The current workspace appears corrected, but the issue deserves a regression test because it is a message-integrity boundary.

Recommended fix:
Add a regression test with at least two direct threads where a malformed/no-thread inbound message from peer B cannot land in peer A's thread.

## Verification Notes

**As of the 2026-08-17 re-baseline** (all suites re-run, not quoted from notes):

- `rez-core` 559 pass / 0 fail · `rez-sdk` 439 / 0 · `rez-node` 1261 / 0 (3 skip) ·
  `rez-chat` 913 / 0 (3 skip) · `e2e-local-mesh` green · `e2e.internet` 8/8 against
  the live relay mesh.
- The June note about `server.inbound-pipeline.ordering.e2e.test.js:204` failing is
  **stale** — that suite is green. It was test-alignment drift, as suspected, and has
  since been resolved.
- The June SDK count (194) is superseded by 439.

Still true, and still worth fixing:

- Optional chaining remains in `rez-chat/test/**` although repository policy forbids
  it everywhere. Source is clean; the tests are not.

## Suggested Remediation Order

Re-ordered 2026-08-17 for what is actually left. `CHAT-1` and `CORE-1` are done, and
`CHAT-2`/`CHAT-3` dropped off the shipped path with the move to Tauri.

1. **`SDK-1`** — the frame codec is the trust boundary every remote frame crosses, and
   it still hands un-hardened parsed JSON to handlers. Highest blast radius left.
2. **`SDK-2`** — identity semantics. Worth doing before more app code grows around the
   account/inbox split, because the cost rises with every caller.
3. **`CORE-2`** — the other untrusted-JSON boundary, reachable by any peer that can
   send a profile. Same class as SDK-1 and probably the same fix.
4. **`SDK-4`**, then **`SDK-5`** — a plaintext footgun named `ciphertextB64`, then
   non-crypto randomness (the `UplinkPoolClient` device id is the one that matters;
   strike the jitter call site from the finding).
5. **`CORE-3`**, **`CORE-4`** — ownership/API drift rather than live exposure. Cheap,
   and each removes a way for a future caller to do the wrong thing by default.

`CHAT-2` and `CHAT-3` stay on the tracker with NOT-APPLICABLE status rather than being
deleted: the Electron tree is still in the repo with working `desktop:pack:*` scripts,
so reviving that shell revives both findings.
