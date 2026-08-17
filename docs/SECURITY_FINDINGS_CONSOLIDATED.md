# Consolidated Security Findings

Original audit: 2026-06-07 · Re-baselined: 2026-08-17 (rez-core#2) ·
**All core/SDK findings remediated: 2026-08-17**

Scope: `rez-core`, `rez-sdk`, and `rez-chat` security audit findings, plus the
one `rez-node` defect this remediation surfaced. This document is a working remediation tracker, not a disclosure advisory.

> **Moved 2026-08-17.** This lived at the polyrepo root, which is not a git repo — so
> the tracker for three repos' security findings was itself unversioned, unbacked-up,
> and invisible to anyone who did not have the working tree. It now lives in
> `rez-core/docs/` and is tracked. It spans three repos and is filed under `rez-core`
> because that is where the issue tracking it lives (rez-core#2); cross-repo findings
> stay in this one file rather than being split, so there is a single place to look.

> **Suspected vulnerabilities do not belong here.** This is a tracker for findings
> already known to the maintainers. Report new ones privately per
> `rez-chat/SECURITY.md` — not as a public issue, and not by appending here.

## Remediation pass, 2026-08-17

Every remaining `rez-core` and `rez-sdk` finding is now closed. Two things this
pass established that the re-baseline had not:

**CORE-2 was live, not theoretical.** The re-baseline recorded it as "reachable
by any peer that can send a profile" without demonstrating the mechanism. It is
worse than that reads: `Object.assign` copies by `[[Set]]`, so it *walks*
`Object.prototype.__proto__`'s setter. Against the pre-fix tree a profile
carrying `"__proto__": {"isAdmin": true}` produced a `ProfilePayloadV1` whose
`extras` object inherited from the sender's payload — `payload.extras.isAdmin`
returned `true`. (Rest/spread is safe; it defines rather than sets. That
difference is why the bug was invisible on inspection.) Contamination was
per-object, not process-wide, so the severity is High-but-scoped.

**One rule, one place.** CORE-2, SDK-1 and the e2ee packet boundary were the
same defect at three doors. The check now lives once, in
`rez-core/src/util/safeJson.js`, and all three call it — a second implementation
would be a second thing to drift, which is how CORE-1's two halves ended up
disagreeing in the first place.

The pass also turned up a finding of its own. SDK-1's fix required reading the
codec's twin in `rez-node`, which had the identical defect on the unauthenticated
server side — see NODE-1. Auditing a boundary means auditing every door onto it,
not the one the ticket names.

Everything else was mechanical by comparison: identity ownership (SDK-2), a
public surface that exposed a raw-deposit verb next to the sealed seam (SDK-3),
a method whose wire field claims an encryption it does not perform (SDK-4), and
`Math.random()` where crypto randomness belongs (SDK-5).

### What changed

| Finding | Resolution |
| --- | --- |
| CORE-2 | Reject `__proto__`/`constructor`/`prototype` at every profile entry point; `extras` is null-prototype. |
| CORE-3 | Object-store surface removed from the package barrel; two guardrails hold it out. |
| CORE-4 | `decryptIncoming` returns `handshakeSignatureB64` alongside `handshake`; all branches share one result shape. |
| SDK-1 | `FrameCodec` parses through the shared guard; hostile frames are distinguishable from malformed ones. |
| SDK-2 | A remote `accountId` can never outrank or supply local identity; disagreement ends the session. |
| SDK-3 | `RezClient.mailbox` is a frozen drain-only view — `deposit` is unreachable from application code. |
| SDK-4 | `sendPayload` requires `preSealed: true`; it encrypts nothing and now says so at the call site. |
| SDK-5 | Identifiers come from `util/randomId.js` (crypto-grade, throws rather than degrading). |
| NODE-1 | The server-side frame codec gets the same guard; hostile frames are logged distinctly. |

### NODE-1: the server-side twin of SDK-1

Status: **CLOSED 2026-08-17** · Severity: High

Found while fixing SDK-1, not part of the original audit.
`rez-node/src/network/ws/JsonFrameCodec.js` was the SDK frame codec's near-twin —
same `JSON.parse`, same pass-`parsed.body`-through to the handler layer — and it
is the *server* side. `decodeFrame` runs BEFORE session authentication, so anyone
able to open a socket reached it. Strictly more exposed than the finding that
led to it.

Fixed the same way, with the same shared guard, so the two files cannot drift
apart again — which they already had, in the sense that fixing one alone would
have left the worse half open. The peer is told "Invalid JSON" either way (an
attacker learns nothing from probing), but `GatewaySession` now logs a hostile
frame distinctly instead of silently, since a poison attempt and an encoding bug
send an operator to entirely different places.

The log line carries `unsafeKey` — one of three constants — and deliberately NOT
the error path, which is assembled from attacker-chosen key names and has no
business being interpolated into a log. A test pins that.

Cover: `rez-node/test/network.json-frame-codec.test.js`.

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
| `rez-core` | 0 | 0 | 4 | 0 |
| `rez-sdk` | 0 | 0 | 5 | 0 |
| `rez-chat` | 0 | 0 | 2 | 2 |

- **Fixed 2026-08-17, re-baseline pass:** CORE-1.
- **Fixed 2026-08-17, remediation pass:** CORE-2, CORE-3, CORE-4, SDK-1 … SDK-5.
- **Closed on re-check:** CHAT-1 (has regression cover), CHAT-4 (was already fixed).
- **Not applicable to the shipped app:** CHAT-2, CHAT-3 — both are Electron-shell IPC
  findings, and the shipped Tauri shell exposes neither surface.

Nothing on this tracker is open. One item was ADDED by the remediation rather
than left over — NODE-1, the server-side twin of SDK-1 — and it is closed too.

One earlier assessment did not survive contact: the re-baseline called SDK-1 and
SDK-2 "hardening of a trust boundary rather than a known bypass", and grouped
CORE-2 with them. CORE-2 was a working prototype injection, demonstrated against
the pre-fix tree. The assessment was too generous.

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

Status: **CLOSED 2026-08-17** (was Open / Medium — severity was understated)

Fixed. This one was demonstrated, not inferred: against the pre-fix tree a profile
carrying `"__proto__": {"isAdmin": true}` was accepted, and the resulting
`payload.extras.isAdmin` returned `true` — the extras bag inherited from the
sender's payload. `Object.assign` copies by `[[Set]]`, which walks
`Object.prototype.__proto__`'s setter; rest/spread does not, which is why the two
adjacent lines behaved differently and the bug read as safe.

Both entry points now refuse the payload (`fromJSON` and the constructor, since
neither is reachable only through the other), `fromBytes` parses via
`parseUntrustedJson`, and `extras` is built on a null prototype so nothing can be
inherited even by a future route. Rejecting rather than stripping matters here:
extras exists FOR forward compatibility, so silently dropping a field would hand
the caller a profile that differs from what the peer sent.

Cover: 4 cases in `rez-core/test/objects.profile-payload.test.js`, including one
proving ordinary forward-compatible extras still round-trip untouched.

Severity: High (was recorded Medium; per-object contamination, not process-wide)

Evidence:
- `rez-core/src/objects/profile/ProfilePayloadV1.js:46` stores `extras` via `Object.assign({}, rest)`.
- `rez-core/src/objects/profile/ProfilePayloadV1.js:50` merges extras back into the JSON object.
- `rez-core/src/objects/profile/ProfilePayloadV1.js:74` parses untrusted bytes with `JSON.parse`.

Impact:
Profile payloads accept arbitrary extra fields and copy them through normal objects. Payloads containing `__proto__`, `constructor`, or `prototype` keys can mutate object prototypes or poison downstream consumers that spread/assign the payload again.

Recommended fix:
Reject dangerous keys at parse/construction boundaries or clone into `Object.create(null)`. Prefer an explicit typed schema for extension fields.

### CORE-3: Stale object/capability namespace surfaces remain after capability rework

Status: **CLOSED 2026-08-17** (was Open / Medium)

Fixed by making the code match the canonical spec rather than the reverse. The
barrel export is gone, so the surface `CAPABILITY_MODEL.md` §9 calls "removed
wholesale" is no longer rez-core's public API.

The finding read as documentation drift; the sharper framing is that
`export * from "./objectstore/index.js"` was the module's ONLY importer in the
entire polyrepo. The dead namespace was not merely mentioned in a stale doc — it
was published to every consumer, which is what would have let a future caller bind
authorization to semantics that no longer exist.

Two guardrails hold it shut, because prose could not: one asserts `RObjectStore`
is absent from the package namespace, the other that nothing under `src/` imports
the module. Cover: `rez-core/test/architecture.no-object-namespace.test.js`.

`src/objectstore/` and its test file are **deleted** (2026-08-17), not merely
unexported: a dead module with fifteen passing tests looks maintained, which is
the condition that invites a caller. Three guardrails now cover the three ways it
could return — the export without the files, the files without the export, or an
internal importer of either.

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

Status: **CLOSED 2026-08-17** (was Open / Medium)

Fixed. `decryptIncoming` now returns `handshakeSignatureB64` alongside `handshake`,
so a caller holding a handshake also holds the only thing that authenticates it.

The more durable fix is structural: the seven non-handshake exits from that method
were each hand-writing their own result object, and the finding is precisely what
happens when one of them drifts. They now share a single `_nonHandshake` helper,
and a test pins the key set of EVERY branch rather than only the one that was
wrong. An unsigned handshake packet is still rejected outright by the record, so
"handshake present, signature absent" is not a state the API can produce.

Assessment unchanged and still worth stating: the live E2EE path does not use this
codec for handshakes, so this was an unsafe-by-invitation API rather than a live
break.

Cover: `rez-core/test/e2ee.packet-codec.test.js`.

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

Status: **CLOSED 2026-08-17** (was Open / High) — *but see the rez-node twin*

Fixed. `decodeFrame` parses through the shared `parseUntrustedJson` guard, so a
frame body carrying `__proto__`, `constructor`, or `prototype` is refused at the
boundary instead of being handed to every handler in the SDK.

Two distinguishable refusals, deliberately: `BAD_FRAME` means "not JSON" (a broken
or mismatched sender) and `UNSAFE_JSON_KEY` means "JSON built to poison us" (a
hostile one). Flattening them would send an operator hunting an encoding bug while
under attack. Both are `retryable: false` — resending identical bytes cannot help
either way. `WsTransport`'s existing bad-frame rate limiter treats both the same,
so a hostile peer still gets disconnected after ten.

**The same defect exists in `rez-node/src/network/ws/JsonFrameCodec.js` and is NOT
fixed.** That codec is the server side, facing unauthenticated remotes, which makes
it the more exposed of the two. Tracked separately; SDK-1 is closed for the SDK, not
for the protocol.

Cover: `rez-sdk/test/security.findings-remediation.test.js`.

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

Status: **CLOSED 2026-08-17** (was Open / High)

Fixed. The defect was an ownership inversion, and the `||` chain is what encoded
it: reading `sessionInfo.accountId` FIRST made a remote claim outrank local truth.
A remote value is now never a source, only a cross-check, and it fails in exactly
two ways — it disagrees with the account we authenticated as, or it appears when
we hold no local account id at all (the adoption case the finding is really about).
Both end the session.

One correction to the recommended fix: "the SDK still has two notions of identity"
turned out to be understated — `resolveSessionIdentity` is also called by rez-chat
on its OWN runtime client, where `accountId` is the app echoing back the account it
just connected as. Two different session descriptors wearing one shape. So the
first implementation, which refused any `accountId` outright, was wrong: it broke a
legitimate caller to defend against a field that caller owns. Refusing only on
DISAGREEMENT closes the attack and leaves local truth alone. Four rez-chat tests
caught this.

`deviceId` gets the same treatment for the same reason — `capabilities.deviceId` is
an echo of what we sent in `session.hello`, so a mismatch means the session is not
the one we opened.

Worth recording: the rez-chat test fixture that failed had been modelling a
`session.ready` carrying `accountId`. No node ever sends one — `SessionReadyEvent`
is `serverTime` + `capabilities`, full stop. The fixture had been teaching the code
a wire shape that does not exist, which is part of why the inversion survived.

Cover: `rez-sdk/test/security.findings-remediation.test.js`.

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

Status: **CLOSED 2026-08-17** (was Open / Medium)

Fixed, though not the way the finding proposed — and the difference is the point.

"Keep low-level capabilities internal" is not available: rez-chat's server services
legitimately need `durableRecords` (signed record publication), `node` (status) and
`accountOutbox` (authority propagation) across roughly a dozen call sites. Those are
the app-server API, not accidental exposure.

What WAS wrong is narrower and worse: `mailbox.deposit` sat on the public client at
the same level as the sealed `mesh.dispatch` seam, with nothing marking the
difference. It takes a `ciphertextB64` and encodes whatever bytes it is given, so an
app holding it can deposit plaintext believing the SDK sealed something.

Auditing every caller settled it: `mailbox.deposit` has exactly ONE in the whole
polyrepo — `MeshCapability.#dispatchToInbox`, which seals first — and rez-chat uses
only the drain half (`list`/`fetch`/`ack`/`cursorAck`). So `RezClient.mailbox` is
now a frozen drain-only view and `deposit` is simply unreachable from application
code, while `MeshCapability` holds the full capability directly. Structural, not
conventional: an app cannot misuse a method it was never handed.

A guardrail covers the silent-omission failure mode — adding a `MailboxCapability`
method without classifying it as drain-side or producer-side fails the suite,
rather than leaving apps quietly unable to reach it.

The remaining privileged getters are documented as such on the class. **Residual,
stated plainly:** they are still low-level and still app-reachable. That is a
deliberate API-shape decision, not an oversight — what has been removed is the
ability to put UNSEALED bytes on the wire.

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

Status: **CLOSED 2026-08-17** (was Open / Medium)

Fixed by making the caller state the assumption instead of holding it silently:
`sendPayload` now requires `preSealed: true` and throws without it, with a message
that says the call encrypts nothing and points at `sealForPeer` + `mesh.dispatch`.

Neither of the recommended fixes was quite right. Renaming is off the table — the
frozen delivery-transports plan (v6, DT-003) refers to `RezClient.sendPayload` by
name and Phase 1 is open against it. "Require a sealed packet type" cannot be
enforced: bytes are bytes, and the SDK has no way to tell sealed ones from
plaintext. The lie is also unfixable at the wire level, because `ciphertextB64` is
the MAILBOX_DEPOSIT contract's field name, not this method's invention.

So the fix is at the only layer that can carry it: the call site. `preSealed`
enables no behaviour and is not a feature flag — its single job is to make the
wrong assumption impossible to hold in silence. Strict `=== true`, so a truthy
string or `1` is data passing through rather than someone asserting.

This composes with, and does not replace, the existing no-new-callers freeze
(`architecture.carrier-boundary.test.js`). Production callers: still zero.

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

Status: **CLOSED 2026-08-17** (was Open / Low-Medium)

Fixed. All four identifier sites draw from `rez-sdk/src/util/randomId.js`, which
uses Web Crypto and **throws** when it is unavailable rather than degrading. The
old device-id shape was the exact anti-pattern: `crypto.randomUUID?.() ?? Math.random()`
silently produced weaker ids on precisely the runtime where you would most want to
know. A runtime with no Web Crypto cannot run this SDK's actual cryptography
either, so failing loudly costs nothing real.

The jitter call site is struck from the finding as the re-baseline recommended, and
is now the sole entry on a guardrail allowlist that fails the suite on any other
`Math.random()` under `src/` — including a check that the exemption still points at
a site that exists, so it cannot rot into a blanket pass.

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

**As of the 2026-08-17 remediation pass** (all suites re-run, not quoted from notes):

- `rez-core` 564 pass / 0 fail (577 before deleting the 15 dead object-store
  tests) · `rez-sdk` 451 / 0 · `rez-node` 1266 / 0 (3 skip) ·
  `rez-chat` 913 / 0 (3 skip) · `rez-ui` 12 / 0 · `e2e-local-mesh` 8 pass / 0 fail
  (3 pg-skip) against real transports.
- Earlier at the re-baseline: `rez-core` 559 · `rez-sdk` 439 · `e2e.internet` 8/8
  against the live relay mesh.
- The June note about `server.inbound-pipeline.ordering.e2e.test.js:204` failing is
  **stale** — that suite is green. It was test-alignment drift, as suspected, and has
  since been resolved.
- The June SDK count (194) is superseded by 439.

Still true, and still worth fixing:

- Optional chaining remains in `rez-chat/test/**` although repository policy forbids
  it everywhere. Source is clean; the tests are not.

## Remediation Order — DISCHARGED 2026-08-17

The queue below is kept as a record of what was prioritised and why, not as work
outstanding. Every item on it is closed.

1. ~~**`SDK-1`**~~ — done. Prediction held: it was the same fix as CORE-2, and both
   now call one shared guard in `rez-core`. What the ordering missed is that the
   *node's* frame codec is the same code and more exposed — filed and fixed as
   NODE-1. Ranking a boundary by blast radius is only as good as the inventory of
   doors onto it.
2. ~~**`SDK-2`**~~ — done, and the reasoning ("worth doing before more app code
   grows around the split") was right for the wrong reason: app code had ALREADY
   grown around it, which is why the first, stricter fix broke rez-chat.
3. ~~**`CORE-2`**~~ — done. Predicted "same class as SDK-1 and probably the same
   fix"; that was correct. Its severity was not — see the finding.
4. ~~**`SDK-4`**, **`SDK-5`**~~ — done. The jitter call site was struck from SDK-5
   as planned and is now the one entry on a guardrail allowlist.
5. ~~**`CORE-3`**, **`CORE-4`**~~ — done. Both were cheaper than the queue implied,
   and CORE-3 was more than "ownership drift": the dead namespace was being
   published from the package root.

`CHAT-2` and `CHAT-3` stay on the tracker with NOT-APPLICABLE status rather than being
deleted: the Electron tree is still in the repo with working `desktop:pack:*` scripts,
so reviving that shell revives both findings.

### Next

Nothing. Every finding on this tracker — the original twelve plus NODE-1, which
the remediation itself surfaced — is closed.
