import { canonicalJSONStringify } from "../util/canonicalize.js";
import { toSigBytes } from "../util/settlement.js";

/**
 * Verify the Ed25519 signature on a settlement receipt or attestation record.
 *
 * Works with any record that follows the settlement signature convention:
 *   - Record has a `sig` field: { alg: "ed25519", relayKeyId, sig: Uint8Array|Array }
 *   - Signature is over canonicalJSONStringify(record fields minus sig)
 *
 * Compatible record types:
 *   DebitReceiptV1, CreditReceiptV1, EscrowReceiptV1, ReleaseReceiptV1,
 *   SlashReceiptV1, StorageChallengeV1, StorageChallengeResponseV1,
 *   PeerUptimeAttestationV1
 *
 * @param {object} opts
 * @param {object} opts.receipt — the receipt as a plain object (from toJSON())
 * @param {function(string): Promise<Uint8Array>} opts.lookupRelayPublicKey — resolves relayKeyId → public key
 * @param {object} opts.crypto — { verify({ publicKey, msg, sig }): Promise<boolean> }
 * @returns {Promise<{ok: boolean, reason?: string}>}
 */
export async function verifySettlementReceipt({ receipt, lookupRelayPublicKey, crypto }) {
  if (!receipt || typeof receipt !== "object") {
    return { ok: false, reason: "invalid receipt" };
  }
  if (!receipt.sig || typeof receipt.sig !== "object") {
    return { ok: false, reason: "missing signature" };
  }

  const { alg, relayKeyId, sig } = receipt.sig;
  if (alg !== "ed25519") {
    return { ok: false, reason: "unsupported alg" };
  }
  if (typeof relayKeyId !== "string" || relayKeyId.length === 0) {
    return { ok: false, reason: "relayKeyId missing" };
  }

  let signature;
  try {
    signature = toSigBytes(sig, "sig");
  } catch (_err) {
    return { ok: false, reason: "sig must be bytes" };
  }
  if (signature.length === 0) {
    return { ok: false, reason: "sig is empty" };
  }

  const publicKey = await lookupRelayPublicKey(relayKeyId);
  if (!(publicKey instanceof Uint8Array)) {
    return { ok: false, reason: "relay public key not found" };
  }

  const bodyToSign = { ...receipt };
  delete bodyToSign.sig;
  const bytes = new TextEncoder().encode(canonicalJSONStringify(bodyToSign));
  const ok = await crypto.verify({ publicKey, msg: bytes, sig: signature });
  return ok ? { ok: true } : { ok: false, reason: "signature invalid" };
}
