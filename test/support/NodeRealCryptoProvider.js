import crypto from "node:crypto";
import { RCryptoProvider } from "../../src/crypto/RCryptoProvider.js";

/**
 * A REAL RCryptoProvider over node:crypto for high-risk protocol tests —
 * byte-compatible with BrowserCryptoProvider semantics (Ed25519/X25519 as
 * SPKI/PKCS8 DER Uint8Arrays, AES-256-GCM ciphertext = ct || 16-byte tag,
 * HKDF-SHA256). FakeCryptoProvider's toy hash/AEAD cannot prove ceremony
 * properties (AAD binding, forward secrecy), so ceremony suites use this.
 */
export class NodeRealCryptoProvider extends RCryptoProvider {
  randomBytes(len) {
    return new Uint8Array(crypto.randomBytes(len));
  }

  hashSha256(bytes) {
    return new Uint8Array(crypto.createHash("sha256").update(Buffer.from(bytes)).digest());
  }

  hkdfSha256(ikm, { salt = new Uint8Array(0), info = new Uint8Array(0), length = 32 } = {}) {
    const out = crypto.hkdfSync("sha256", Buffer.from(ikm), Buffer.from(salt), Buffer.from(info), length);
    return new Uint8Array(out);
  }

  aeadEncrypt({ key, nonce, plaintext, aad }) {
    const cipher = crypto.createCipheriv("aes-256-gcm", Buffer.from(key), Buffer.from(nonce));
    if (aad && aad.length > 0) cipher.setAAD(Buffer.from(aad));
    const ct = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
    const tag = cipher.getAuthTag();
    return new Uint8Array(Buffer.concat([ct, tag]));
  }

  aeadDecrypt({ key, nonce, ciphertext, aad }) {
    const buf = Buffer.from(ciphertext);
    if (buf.length < 16) throw new Error("NodeRealCryptoProvider.aeadDecrypt: ciphertext too short");
    const ct = buf.subarray(0, buf.length - 16);
    const tag = buf.subarray(buf.length - 16);
    const decipher = crypto.createDecipheriv("aes-256-gcm", Buffer.from(key), Buffer.from(nonce));
    if (aad && aad.length > 0) decipher.setAAD(Buffer.from(aad));
    decipher.setAuthTag(tag);
    return new Uint8Array(Buffer.concat([decipher.update(ct), decipher.final()]));
  }

  sign({ privateKey, msg }) {
    const keyObj = crypto.createPrivateKey({ key: Buffer.from(privateKey), format: "der", type: "pkcs8" });
    return new Uint8Array(crypto.sign(null, Buffer.from(msg), keyObj));
  }

  verify({ publicKey, msg, sig }) {
    let keyObj;
    try {
      keyObj = crypto.createPublicKey({ key: Buffer.from(publicKey), format: "der", type: "spki" });
    } catch (err) {
      return false;
    }
    try {
      return crypto.verify(null, Buffer.from(msg), keyObj, Buffer.from(sig));
    } catch (err) {
      return false;
    }
  }

  generateSigningKeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    return {
      publicKey: new Uint8Array(publicKey.export({ format: "der", type: "spki" })),
      privateKey: new Uint8Array(privateKey.export({ format: "der", type: "pkcs8" })),
    };
  }

  dhGenerateKeyPair({ alg = "X25519", fmt = "spki" } = {}) {
    if (String(alg).toLowerCase() !== "x25519" || fmt !== "spki") {
      throw new Error("NodeRealCryptoProvider.dhGenerateKeyPair supports X25519 spki only");
    }
    const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519");
    return {
      publicKey: new Uint8Array(publicKey.export({ format: "der", type: "spki" })),
      privateKey: new Uint8Array(privateKey.export({ format: "der", type: "pkcs8" })),
    };
  }

  dhDerive({ privateKey, publicKey, alg = "X25519", fmt = "spki" } = {}) {
    if (String(alg).toLowerCase() !== "x25519" || fmt !== "spki") {
      throw new Error("NodeRealCryptoProvider.dhDerive supports X25519 spki only");
    }
    const priv = crypto.createPrivateKey({ key: Buffer.from(privateKey), format: "der", type: "pkcs8" });
    const pub = crypto.createPublicKey({ key: Buffer.from(publicKey), format: "der", type: "spki" });
    return new Uint8Array(crypto.diffieHellman({ privateKey: priv, publicKey: pub }));
  }
}
