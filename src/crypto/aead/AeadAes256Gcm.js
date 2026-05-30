import { RCryptoProvider } from "../RCryptoProvider.js";
import { isBytes } from "../../util/bytes.js";
const TAG_BITS = 128;

export async function encryptAes256Gcm(crypto, key, nonce, plaintext, aad) {
  if (!(crypto instanceof RCryptoProvider)) {
    throw new Error("encryptAes256Gcm requires crypto (RCryptoProvider)");
  }
  if (!isBytes(key) || key.length !== 32) {
    throw new Error("encryptAes256Gcm requires 32-byte key");
  }
  if (!isBytes(nonce) || nonce.length !== 12) {
    throw new Error("encryptAes256Gcm requires 12-byte nonce");
  }
  if (!isBytes(plaintext)) {
    throw new Error("encryptAes256Gcm requires plaintext Uint8Array");
  }
  if (!isBytes(aad)) {
    throw new Error("encryptAes256Gcm requires aad Uint8Array");
  }

  return crypto.aeadEncrypt({ key, nonce, plaintext, aad });
}

export async function decryptAes256Gcm(crypto, key, nonce, ct, aad) {
  if (!(crypto instanceof RCryptoProvider)) {
    throw new Error("decryptAes256Gcm requires crypto (RCryptoProvider)");
  }
  if (!isBytes(key) || key.length !== 32) {
    throw new Error("decryptAes256Gcm requires 32-byte key");
  }
  if (!isBytes(nonce) || nonce.length !== 12) {
    throw new Error("decryptAes256Gcm requires 12-byte nonce");
  }
  if (!isBytes(ct) || ct.length < 16) {
    throw new Error("decryptAes256Gcm requires ciphertext+tag");
  }
  if (!isBytes(aad)) {
    throw new Error("decryptAes256Gcm requires aad Uint8Array");
  }

  return crypto.aeadDecrypt({ key, nonce, ciphertext: ct, aad });
}

export { TAG_BITS as AES_GCM_TAG_BITS };
