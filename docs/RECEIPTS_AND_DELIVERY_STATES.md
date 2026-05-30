# Receipts and Delivery States

## Overview
Receipts are **cryptographically verifiable relay attestations**. They indicate network acceptance and/or delivery, not user read.

Canonical states:
- Pending (local only)
- Accepted (entry relay accepted custody)
- Delivered (deposit relay stored in inbox)

Envelope type: `rez.receipt.v1`

## Receipt Body (v1)

```json
{
  "v": 1,
  "kind": "accepted" | "delivered",
  "msg": {
    "innerHash": [byte, ...],
    "clientMsgId": "string",
    "atMs": 1234567890,

    // Delivered-only fields
    "inboxId": "string",
    "depositId": "string"
  },
  "sig": {
    "alg": "ed25519",
    "relayKeyId": "string",
    "sig": [byte, ...]
  }
}
```

Notes:
- `innerHash` is `sha256(innerBytes)` and is required for all receipts.
- `clientMsgId` is a client-supplied identifier that binds the receipt to the sender’s original message intent.
- `atMs` is the relay’s timestamp in milliseconds.
- `sig` is the relay’s signature over the **canonical JSON bytes of the receipt body without the `sig` field**.

## Signing rules
- The relay signs canonical JSON bytes of the receipt body **excluding** the `sig` field.
- The signed content must include: `v`, `kind`, and `msg` (including `innerHash`).
- Signature algorithm: Ed25519.
- The signing key must be the relay’s long-term identity key (the key that defines `relayKeyId`).

## Verification rules
- The verifier retrieves the relay’s public key using `relayKeyId` from a trusted relay descriptor source.
- Verify the signature against the canonical JSON bytes of the receipt body without `sig`.
- If verification fails, discard the receipt.

## Emission rules
- **Accepted**: emitted by the entry relay that first receives the onion packet from a gateway.
- **Delivered**: emitted by the relay that deposits the payload into the destination inbox.

State transitions:
- Pending → Accepted → Delivered
- Pending → Delivered is allowed (if acceptance and delivery happen in the same relay).
