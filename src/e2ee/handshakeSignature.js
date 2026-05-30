import { canonicalJSONStringify } from "../util/canonicalize.js";
import { base64ToBytes, bytesToBase64 } from "../util/bytes.js";

/**
 * Sign and verify the X3DH handshake envelope.
 *
 * The signature is an Ed25519 signature, by the private key matching the
 * handshake's `senderIdentitySigningPubKeyB64` field, over the canonical-JSON
 * bytes of the `handshake` object. The signature lives at the packet level
 * (sibling to `handshake`) so the handshake's canonical bytes are exactly
 * what's signed — no signature field to strip out.
 *
 * This closes CRITICAL-1 from docs/SECURITY_AUDIT.md: without an
 * identity-bound signature over the envelope, a receiver could be persuaded
 * to accept a handshake forged with substituted X3DH identity material.
 */

function isBytes(value) {
  return value instanceof Uint8Array;
}

function assertHandshakeShape(handshake) {
  if (!handshake || typeof handshake !== "object" || Array.isArray(handshake)) {
    throw new Error("handshake must be a plain object");
  }
  const pubkey = handshake.senderIdentitySigningPubKeyB64;
  if (typeof pubkey !== "string" || pubkey.length === 0) {
    throw new Error("handshake.senderIdentitySigningPubKeyB64 must be a non-empty string");
  }
}

/**
 * Produce the canonical bytes that will be signed.
 * @param {object} handshake
 * @returns {Uint8Array}
 */
export function canonicalHandshakeBytes(handshake) {
  assertHandshakeShape(handshake);
  return new TextEncoder().encode(canonicalJSONStringify(handshake));
}

/**
 * Sign a handshake envelope with the initiator's identity signing private key.
 *
 * Caller is responsible for ensuring `signingPrivateKey` matches
 * `handshake.senderIdentitySigningPubKeyB64`. This is asserted in a
 * sanity-check verify pass before returning.
 *
 * @param {{ handshake: object, crypto: import("../crypto/RCryptoProvider.js").RCryptoProvider, signingPrivateKey: Uint8Array }} opts
 * @returns {Promise<string>} base64 signature
 */
export async function signHandshakeEnvelope({ handshake, crypto, signingPrivateKey } = {}) {
  assertHandshakeShape(handshake);
  if (!crypto || typeof crypto.sign !== "function" || typeof crypto.verify !== "function") {
    throw new Error("signHandshakeEnvelope requires crypto with sign/verify");
  }
  if (!isBytes(signingPrivateKey)) {
    throw new Error("signHandshakeEnvelope requires signingPrivateKey Uint8Array");
  }
  const msg = canonicalHandshakeBytes(handshake);
  const sig = await crypto.sign({ privateKey: signingPrivateKey, msg });
  if (!isBytes(sig)) {
    throw new Error("crypto.sign returned non-bytes signature");
  }
  // Sanity: confirm the signing key actually matches the pubkey embedded in
  // the handshake. Catches keystore-mismatch bugs before they hit the wire.
  const claimedPubKey = base64ToBytes(handshake.senderIdentitySigningPubKeyB64);
  const verified = await crypto.verify({ publicKey: claimedPubKey, msg, sig });
  if (verified !== true) {
    throw new Error("signHandshakeEnvelope: signingPrivateKey does not match handshake.senderIdentitySigningPubKeyB64");
  }
  return bytesToBase64(sig);
}

/**
 * Verify a handshake envelope signature against the pubkey embedded in the
 * handshake. The caller is still responsible for verifying the binding chain
 * (senderAccountBinding) that ties senderIdentitySigningPubKeyB64 to the
 * claimed accountId — this function only proves "the handshake was authored
 * by whoever holds the privkey matching senderIdentitySigningPubKeyB64".
 *
 * @param {{ handshake: object, signatureB64: string, crypto: import("../crypto/RCryptoProvider.js").RCryptoProvider }} opts
 * @returns {Promise<boolean>}
 */
export async function verifyHandshakeEnvelope({ handshake, signatureB64, crypto } = {}) {
  assertHandshakeShape(handshake);
  if (!crypto || typeof crypto.verify !== "function") {
    throw new Error("verifyHandshakeEnvelope requires crypto with verify");
  }
  if (typeof signatureB64 !== "string" || signatureB64.length === 0) {
    return false;
  }
  let publicKey;
  let sig;
  try {
    publicKey = base64ToBytes(handshake.senderIdentitySigningPubKeyB64);
    sig = base64ToBytes(signatureB64);
  } catch {
    return false;
  }
  const msg = canonicalHandshakeBytes(handshake);
  try {
    const ok = await crypto.verify({ publicKey, msg, sig });
    return ok === true;
  } catch {
    return false;
  }
}
