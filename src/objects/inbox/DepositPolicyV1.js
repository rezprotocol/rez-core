import { RSerializable } from "../../base/index.js";
import { isNonEmptyString } from "../../util/strings.js";
import { isFiniteNumber } from "../../util/settlement.js";
import { canonicalJSONStringify } from "../../util/canonicalize.js";
import { base64ToBytes, bytesToBase64 } from "../../util/bytes.js";

/**
 * Inbox deposit policy — claimant-signed blocklist (and optional allowlist)
 * enforced by the receiving relay before storing a deposit.
 *
 * Default semantics: if no policy is published for an inbox, the relay
 * accepts anonymous deposits per `docs/CAPABILITY_MODEL.md §2`. When a
 * policy exists, the relay rejects deposits whose depositor pubkey
 * (session.ownerPublicKeyB64) appears in `blockedDepositorPubkeys`. If
 * `allowedDepositorPubkeys` is non-empty, deposits from senders NOT in the
 * list are also rejected.
 *
 * Closes docs/SECURITY_AUDIT.md HIGH-1.
 *
 * Signature: Ed25519 by the inbox's claimant private key over canonical
 * (inboxId, policyVersion, blockedDepositorPubkeys, allowedDepositorPubkeys,
 * issuedAtMs, expiresAtMs). The relay verifies against the claimant pubkey
 * from its InboxClaimRegistry.
 */
const PAYLOAD_KIND = "inbox-deposit-policy";

export class DepositPolicyV1 extends RSerializable {
  static type = "DepositPolicyV1";

  constructor({
    v = 1,
    inboxId,
    policyVersion,
    blockedDepositorPubkeys = [],
    allowedDepositorPubkeys = [],
    issuedAtMs,
    expiresAtMs,
    claimantPublicKeyB64,
    signatureB64,
  } = {}) {
    super();
    this.assert(v === 1, "DepositPolicyV1.v must be 1", { v });
    this.assert(isNonEmptyString(inboxId), "DepositPolicyV1.inboxId must be non-empty string");
    this.assert(Number.isInteger(policyVersion) && policyVersion >= 1, "DepositPolicyV1.policyVersion must be positive integer");
    this.assert(Array.isArray(blockedDepositorPubkeys), "DepositPolicyV1.blockedDepositorPubkeys must be array");
    this.assert(Array.isArray(allowedDepositorPubkeys), "DepositPolicyV1.allowedDepositorPubkeys must be array");
    for (const pk of blockedDepositorPubkeys) {
      this.assert(isNonEmptyString(pk), "DepositPolicyV1.blockedDepositorPubkeys entries must be non-empty strings");
    }
    for (const pk of allowedDepositorPubkeys) {
      this.assert(isNonEmptyString(pk), "DepositPolicyV1.allowedDepositorPubkeys entries must be non-empty strings");
    }
    this.assert(isFiniteNumber(issuedAtMs) && issuedAtMs > 0, "DepositPolicyV1.issuedAtMs must be positive");
    this.assert(isFiniteNumber(expiresAtMs) && expiresAtMs > issuedAtMs, "DepositPolicyV1.expiresAtMs must be > issuedAtMs");
    this.assert(isNonEmptyString(claimantPublicKeyB64), "DepositPolicyV1.claimantPublicKeyB64 must be non-empty string");
    this.assert(isNonEmptyString(signatureB64), "DepositPolicyV1.signatureB64 must be non-empty string");

    this.v = 1;
    this.inboxId = inboxId;
    this.policyVersion = policyVersion;
    this.blockedDepositorPubkeys = [...blockedDepositorPubkeys];
    this.allowedDepositorPubkeys = [...allowedDepositorPubkeys];
    this.issuedAtMs = issuedAtMs;
    this.expiresAtMs = expiresAtMs;
    this.claimantPublicKeyB64 = claimantPublicKeyB64;
    this.signatureB64 = signatureB64;
  }

  /** @returns {boolean} */
  isExpired(nowMs = Date.now()) {
    return nowMs >= this.expiresAtMs;
  }

  /** @param {string} depositorPubkeyB64 */
  isDepositorBlocked(depositorPubkeyB64) {
    if (typeof depositorPubkeyB64 !== "string" || depositorPubkeyB64.length === 0) {
      return false;
    }
    if (this.blockedDepositorPubkeys.indexOf(depositorPubkeyB64) !== -1) {
      return true;
    }
    if (this.allowedDepositorPubkeys.length > 0
      && this.allowedDepositorPubkeys.indexOf(depositorPubkeyB64) === -1) {
      return true;
    }
    return false;
  }

  toJSON() {
    return {
      v: 1,
      inboxId: this.inboxId,
      policyVersion: this.policyVersion,
      blockedDepositorPubkeys: [...this.blockedDepositorPubkeys],
      allowedDepositorPubkeys: [...this.allowedDepositorPubkeys],
      issuedAtMs: this.issuedAtMs,
      expiresAtMs: this.expiresAtMs,
      claimantPublicKeyB64: this.claimantPublicKeyB64,
      signatureB64: this.signatureB64,
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("DepositPolicyV1.fromJSON requires object");
    }
    return new DepositPolicyV1(json);
  }
}

/** Canonical bytes for signing/verifying a deposit policy. */
export function canonicalDepositPolicyBytes({
  inboxId,
  policyVersion,
  blockedDepositorPubkeys,
  allowedDepositorPubkeys,
  issuedAtMs,
  expiresAtMs,
}) {
  return new TextEncoder().encode(canonicalJSONStringify({
    kind: PAYLOAD_KIND,
    inboxId,
    policyVersion,
    blockedDepositorPubkeys: [...(blockedDepositorPubkeys || [])].sort(),
    allowedDepositorPubkeys: [...(allowedDepositorPubkeys || [])].sort(),
    issuedAtMs,
    expiresAtMs,
  }));
}

/**
 * Sign a deposit-policy payload with the claimant's Ed25519 private key.
 * Returns the full record. The signing key MUST match the claimant pubkey
 * registered for `inboxId` in the relay's InboxClaimRegistry, or the relay
 * will reject the policy.
 */
export async function signDepositPolicy({
  inboxId,
  policyVersion,
  blockedDepositorPubkeys = [],
  allowedDepositorPubkeys = [],
  issuedAtMs,
  expiresAtMs,
  claimantPublicKeyB64,
  crypto,
  signingPrivateKey,
}) {
  if (!crypto || typeof crypto.sign !== "function") {
    throw new Error("signDepositPolicy requires crypto with sign");
  }
  if (!(signingPrivateKey instanceof Uint8Array)) {
    throw new Error("signDepositPolicy requires signingPrivateKey Uint8Array");
  }
  const msg = canonicalDepositPolicyBytes({
    inboxId,
    policyVersion,
    blockedDepositorPubkeys,
    allowedDepositorPubkeys,
    issuedAtMs,
    expiresAtMs,
  });
  const sig = await crypto.sign({ privateKey: signingPrivateKey, msg });
  if (!(sig instanceof Uint8Array)) {
    throw new Error("crypto.sign returned non-bytes signature");
  }
  // Sanity check the privkey/pubkey alignment before shipping.
  const verified = await crypto.verify({
    publicKey: base64ToBytes(claimantPublicKeyB64),
    msg,
    sig,
  });
  if (verified !== true) {
    throw new Error("signDepositPolicy: signingPrivateKey does not match claimantPublicKeyB64");
  }
  return new DepositPolicyV1({
    inboxId,
    policyVersion,
    blockedDepositorPubkeys,
    allowedDepositorPubkeys,
    issuedAtMs,
    expiresAtMs,
    claimantPublicKeyB64,
    signatureB64: bytesToBase64(sig),
  });
}

/**
 * Verify a deposit-policy signature against the expected claimant pubkey
 * (which the relay looks up in its InboxClaimRegistry).
 */
export async function verifyDepositPolicy({ policy, expectedClaimantPublicKeyB64, crypto }) {
  if (!(policy instanceof DepositPolicyV1)) {
    throw new Error("verifyDepositPolicy requires DepositPolicyV1");
  }
  if (typeof expectedClaimantPublicKeyB64 !== "string" || expectedClaimantPublicKeyB64.length === 0) {
    return false;
  }
  if (policy.claimantPublicKeyB64 !== expectedClaimantPublicKeyB64) {
    return false;
  }
  let pubKey;
  let sig;
  try {
    pubKey = base64ToBytes(policy.claimantPublicKeyB64);
    sig = base64ToBytes(policy.signatureB64);
  } catch {
    return false;
  }
  const msg = canonicalDepositPolicyBytes(policy);
  try {
    const ok = await crypto.verify({ publicKey: pubKey, msg, sig });
    return ok === true;
  } catch {
    return false;
  }
}
