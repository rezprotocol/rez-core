import { RSerializable } from "../../base/index.js";
import { isNonEmptyString } from "../../util/strings.js";
import { isFiniteNumber } from "../../util/settlement.js";
import { canonicalJSONStringify } from "../../util/canonicalize.js";
import { base64ToBytes, bytesToBase64 } from "../../util/bytes.js";

/**
 * TerminalInboxClose — the mailbox kill switch (portable inbox lease L1,
 * plans/PORTABLE_INBOX_LEASE_SPEC.md §4).
 *
 * Signed by the inbox's CLOSE key — the random per-inbox keypair whose
 * private half is custodied in account state and never held by any provider.
 * The claim key CANNOT close (a stolen device can renew; only the account
 * kills); the close key cannot renew. The record AUTHORIZES ITSELF: the
 * provider verifies the signature against the closePublicKey registered in
 * the stored claim, and the transport session's principal contributes no
 * authority — any authenticated session may carry it.
 *
 * Semantics (frozen at spec approval):
 * - Idempotent and monotonic: a valid close for (inboxId, finalGeneration G)
 *   permanently kills generation G and any lease at ≤ G. Never recoverable —
 *   unlike expiry, which is recoverable during grace.
 * - The provider keeps the (inboxId, finalGeneration) tombstone through
 *   RECLAIMED; already-stored ciphertext survives the terminal grace window
 *   so the claimant can drain (admission dies immediately; retention does
 *   not).
 * - A closed inbox is never reincarnated: want another mailbox, mint another
 *   random inboxId.
 */
const PAYLOAD_KIND = "terminal-inbox-close";

export class TerminalInboxCloseV1 extends RSerializable {
  static type = "TerminalInboxCloseV1";

  constructor({ v = 1, inboxId, finalGeneration, closedAtMs, signatureB64 } = {}) {
    super();
    this.assert(v === 1, "TerminalInboxCloseV1.v must be 1", { v });
    this.assert(isNonEmptyString(inboxId), "TerminalInboxCloseV1.inboxId must be non-empty string");
    this.assert(
      Number.isInteger(finalGeneration) && finalGeneration >= 1,
      "TerminalInboxCloseV1.finalGeneration must be a positive integer",
    );
    this.assert(isFiniteNumber(closedAtMs) && closedAtMs > 0, "TerminalInboxCloseV1.closedAtMs must be positive");
    this.assert(isNonEmptyString(signatureB64), "TerminalInboxCloseV1.signatureB64 must be non-empty string");
    this.v = 1;
    this.inboxId = inboxId;
    this.finalGeneration = finalGeneration;
    this.closedAtMs = closedAtMs;
    this.signatureB64 = signatureB64;
  }

  toJSON() {
    return {
      v: 1,
      inboxId: this.inboxId,
      finalGeneration: this.finalGeneration,
      closedAtMs: this.closedAtMs,
      signatureB64: this.signatureB64,
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("TerminalInboxCloseV1.fromJSON requires object");
    }
    return new TerminalInboxCloseV1(json);
  }
}

/** Canonical bytes the close key signs. */
export function canonicalTerminalCloseBytes({ inboxId, finalGeneration, closedAtMs }) {
  return new TextEncoder().encode(canonicalJSONStringify({
    kind: PAYLOAD_KIND,
    inboxId,
    finalGeneration,
    closedAtMs,
  }));
}

/**
 * Sign a terminal close with the CLOSE private key. Sanity-verifies the
 * key pair alignment before returning, same discipline as signDepositPolicy.
 */
export async function signTerminalInboxClose({
  inboxId,
  finalGeneration,
  closedAtMs,
  closePublicKeyB64,
  crypto,
  closePrivateKey,
}) {
  if (!crypto || typeof crypto.sign !== "function") {
    throw new Error("signTerminalInboxClose requires crypto with sign");
  }
  if (!(closePrivateKey instanceof Uint8Array)) {
    throw new Error("signTerminalInboxClose requires closePrivateKey Uint8Array");
  }
  const msg = canonicalTerminalCloseBytes({ inboxId, finalGeneration, closedAtMs });
  const sig = await crypto.sign({ privateKey: closePrivateKey, msg });
  if (!(sig instanceof Uint8Array)) {
    throw new Error("crypto.sign returned non-bytes signature");
  }
  const verified = await crypto.verify({
    publicKey: base64ToBytes(closePublicKeyB64),
    msg,
    sig,
  });
  if (verified !== true) {
    throw new Error("signTerminalInboxClose: closePrivateKey does not match closePublicKeyB64");
  }
  return new TerminalInboxCloseV1({
    inboxId,
    finalGeneration,
    closedAtMs,
    signatureB64: bytesToBase64(sig),
  });
}

/**
 * Verify a terminal close against the closePublicKey registered in the
 * stored claim (which the provider looks up itself — the record never
 * carries the key it is verified against).
 */
export async function verifyTerminalInboxClose({ close, expectedClosePublicKeyB64, crypto }) {
  if (!(close instanceof TerminalInboxCloseV1)) {
    throw new Error("verifyTerminalInboxClose requires TerminalInboxCloseV1");
  }
  if (typeof expectedClosePublicKeyB64 !== "string" || expectedClosePublicKeyB64.length === 0) {
    return false;
  }
  let pubKey;
  let sig;
  try {
    pubKey = base64ToBytes(expectedClosePublicKeyB64);
    sig = base64ToBytes(close.signatureB64);
  } catch {
    return false;
  }
  const msg = canonicalTerminalCloseBytes(close);
  try {
    const ok = await crypto.verify({ publicKey: pubKey, msg, sig });
    return ok === true;
  } catch {
    return false;
  }
}
