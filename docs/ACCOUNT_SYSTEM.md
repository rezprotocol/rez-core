# Account System

## 1. Account/Auth State Machine

The account and session state machine is owned by `rez-chat`.

Canonical states:
- `NO_KEYSTORE`
- `LOCKED`
- `UNLOCKING`
- `UNLOCKED`
- `LOCKING`

`rez-chat` receives user intents and drives this state machine through app services.

## 2. Unlock and Connect Rules

- App starts in `NO_KEYSTORE` or `LOCKED` depending on keystore presence.
- Unlock transitions `LOCKED -> UNLOCKING -> UNLOCKED` only on valid credentials.
- Connect is allowed only after unlock succeeds.
- Wrong password fails closed and returns to `LOCKED` with an error.
- Logout transitions `UNLOCKED -> LOCKING -> LOCKED`, clears in-memory secrets, and disconnects transport.

## 3. Repo Ownership Mapping

- `rez-ui` = UI framework only.
- `rez-chat` = app runtime + state machine.
- `rez-sdk` = keystore + connect helpers.
- `rez-core` = crypto/protocol primitives.

## 4. Data Responsibility

- App state and transition policy live in `rez-chat` stores/services.
- Keystore persistence and crypto helpers live in `rez-sdk`.
- Protocol internals remain in `rez-core`.
- `rez-ui` renders state and emits intents; it does not own auth/network logic.

## 5. Identity and Account Semantics

- `accountId` is deterministically derived from the identity signing public key fingerprint.
- Derivation requirement:
  - fingerprint = `sha256(identity signing public key bytes)`
  - accountId = stable encoded representation of that fingerprint (canonical account-id format).
- `deviceId` is stable per local device registration and persisted in keystore data.
- `accountId` and `deviceId` are never invented in `rez-chat`; they are produced/validated by SDK keystore flows.

## 6. Keystore Contents

Keystore plaintext (before encryption) must include:
- `keystoreVersion`
- `createdAtMs`
- `updatedAtMs`
- `identity` key material (signing public/private keypair representation)
- `accountId` (validated against derived identity fingerprint)
- `deviceId` (stable local device registration ID)
- capability metadata references needed by runtime session setup
- optional user-facing metadata such as `profileName`

On unlock, SDK must fail closed if stored `accountId` does not match the value derived from identity signing public key material.

## 7. Storage Location

- Browser v0 keystore persistence uses IndexedDB.
- localStorage is not used for keystore persistence (except potentially non-secret UI prefs only).

## 8. Fail-Closed and Teardown Semantics

- Unlock failures always return the app to `LOCKED` with an explicit error.
- Connect is blocked unless state is `UNLOCKED`.
- Logout teardown must:
  - transition `UNLOCKED -> LOCKING -> LOCKED`
  - disconnect active transport/session
  - clear in-memory secret/session handles.
