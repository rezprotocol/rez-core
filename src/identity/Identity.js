import {
  bytesToBase64,
  base64ToBytes,
  cloneNonEmptyBytes,
} from "../util/bytes.js";
import { bytesToBase32 } from "../util/base32.js";
import { Hash } from "../base/index.js";

function resolveCrypto(cryptoProvider = null) {
  const direct = cryptoProvider && typeof cryptoProvider === "object" ? cryptoProvider : null;

  // If provider has generateSigningKeyPair (RCryptoProvider), use it directly for Ed25519
  if (direct && typeof direct.generateSigningKeyPair === "function") {
    return { rcrypto: direct };
  }

  const cryptoObj = (direct && direct.crypto) || direct || globalThis.crypto;
  const subtle = (direct && direct.subtle) || (cryptoObj && cryptoObj.subtle);
  if (!subtle || typeof subtle.generateKey !== "function") {
    throw new Error("WebCrypto subtle API or RCryptoProvider is required for identity operations");
  }
  return { subtle };
}

export function deriveAccountIdFromPublicKey(publicKeyBytes) {
  const normalized = cloneNonEmptyBytes(publicKeyBytes, "publicKeyBytes");
  const fingerprint = Hash.sha256(normalized);
  return `rez:acct:${bytesToBase32(fingerprint)}`;
}

export class Identity {
  constructor({ publicKeyBytes, privateKeyBytes } = {}) {
    this._publicKeyBytes = cloneNonEmptyBytes(publicKeyBytes, "publicKeyBytes");
    this._privateKeyBytes = cloneNonEmptyBytes(privateKeyBytes, "privateKeyBytes");
    this._accountId = deriveAccountIdFromPublicKey(this._publicKeyBytes);
  }

  getPublicKeyBytes() {
    return new Uint8Array(this._publicKeyBytes);
  }

  getPrivateKeyBytes() {
    return new Uint8Array(this._privateKeyBytes);
  }

  getAccountId() {
    return this._accountId;
  }

  static async generate({ cryptoProvider = null } = {}) {
    const resolved = resolveCrypto(cryptoProvider);

    if (resolved.rcrypto) {
      // RCryptoProvider path: Ed25519 via generateSigningKeyPair()
      const { publicKey, privateKey } = await resolved.rcrypto.generateSigningKeyPair();
      return new Identity({ publicKeyBytes: publicKey, privateKeyBytes: privateKey });
    }

    // WebCrypto subtle path: Ed25519
    const keyPair = await resolved.subtle.generateKey(
      "Ed25519",
      true,
      ["sign", "verify"],
    );
    const publicKeyBytes = new Uint8Array(await resolved.subtle.exportKey("spki", keyPair.publicKey));
    const privateKeyBytes = new Uint8Array(await resolved.subtle.exportKey("pkcs8", keyPair.privateKey));
    return new Identity({ publicKeyBytes, privateKeyBytes });
  }

  static fromObject(obj = {}) {
    if (!obj || typeof obj !== "object") throw new Error("Identity.fromObject requires object payload");
    const publicKeyBytes = base64ToBytes(obj.publicKeyB64);
    const privateKeyBytes = base64ToBytes(obj.privateKeyB64);
    return new Identity({ publicKeyBytes, privateKeyBytes });
  }

  toObject() {
    return {
      publicKeyB64: bytesToBase64(this._publicKeyBytes),
      privateKeyB64: bytesToBase64(this._privateKeyBytes),
    };
  }
}
