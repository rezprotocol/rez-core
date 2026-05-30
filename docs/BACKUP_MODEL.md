# Encrypted Backup Model (chat.backup.v1)

Status: v1 technical architecture and contract.

## Threat Model

- Node operators are assumed honest-but-curious.
- Operators may inspect storage contents and metadata.
- Operators must not receive backup plaintext or recovery secrets.

## Ciphertext-Only Invariants

- Client encrypts backup artifacts before upload.
- Node stores opaque ciphertext blobs only.
- Node never derives or receives recovery key material.
- Recovery secret is never transmitted over ws/http.

## Storage Keys

Per-account namespace uses a stable account hash (not raw account id):

- `app:chat:backup/{accountHash}/manifest`
- `app:chat:backup/{accountHash}/meta`
- `app:chat:backup/{accountHash}/checkpoint/{seq}`
- `app:chat:backup/{accountHash}/delta/{seq}`

`manifest` and `meta` contain metadata only.
`checkpoint/*` and `delta/*` contain ciphertext envelopes and minimal metadata.

## Metadata Minimization

Allowed operator-visible metadata:

- `accountHash`
- `type` (`checkpoint` | `delta`)
- `seq`
- `createdAtMs`
- `expiresAtMs`
- `sizeClass`

Disallowed metadata in node-visible storage/logs:

- plaintext message/account state
- recovery secret or derived key bytes
- message previews/contact graph from backup artifacts

## Retention Semantics

- Default retention: 90 days.
- Operator may override retention in node config (`node.backup.retentionDays`).
- Expired artifacts are removed by prune workflow (`chat.backup.prune`/service prune).

## Restore Precedence

v1 restore source precedence:

1. currently connected node (required)
2. additional multi-node merge sources are out of scope for v1

Restore order:

1. fetch list
2. pick latest checkpoint
3. fetch checkpoint blob
4. fetch deltas with `seq > checkpoint.seq`
5. decrypt locally and rehydrate client state

## Logging Guardrails

- Backup handlers must not log payload bytes.
- Backup handlers must not log decrypted fields or recovery material.
- Failures should log only codes and coarse reasons.
