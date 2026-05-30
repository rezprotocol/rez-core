import { canonicalJSONStringify } from "../util/canonicalize.js";
import { toSigBytes as toBytes } from "../util/settlement.js";

export async function verifyReceiptV1({ receiptBody, lookupRelayPublicKey, crypto }) {
  if (!receiptBody || typeof receiptBody !== "object") {
    return { ok: false, reason: "invalid receipt body" };
  }
  if (!receiptBody.sig || typeof receiptBody.sig !== "object") {
    return { ok: false, reason: "missing signature" };
  }
  const { alg, relayKeyId, sig } = receiptBody.sig;
  if (alg !== "ed25519") return { ok: false, reason: "unsupported alg" };
  if (typeof relayKeyId !== "string" || relayKeyId.length === 0) return { ok: false, reason: "relayKeyId missing" };
  const signature = toBytes(sig, "sig");

  if (!receiptBody.msg || typeof receiptBody.msg !== "object") {
    return { ok: false, reason: "msg missing" };
  }
  if (!Array.isArray(receiptBody.msg.innerHash) || receiptBody.msg.innerHash.length !== 32) {
    return { ok: false, reason: "innerHash invalid" };
  }

  const publicKey = await lookupRelayPublicKey(relayKeyId);
  if (!(publicKey instanceof Uint8Array)) {
    return { ok: false, reason: "relay public key missing" };
  }

  const bodyToSign = { ...receiptBody };
  delete bodyToSign.sig;
  const bytes = new TextEncoder().encode(canonicalJSONStringify(bodyToSign));
  const ok = await crypto.verify({ publicKey, msg: bytes, sig: signature });
  return ok ? { ok: true } : { ok: false, reason: "signature invalid" };
}
