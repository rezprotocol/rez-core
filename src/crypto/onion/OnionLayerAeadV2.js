import { RCryptoProvider } from "../RCryptoProvider.js";
import { encryptAes256Gcm, decryptAes256Gcm } from "../aead/AeadAes256Gcm.js";
import { deriveOnionAeadKeyNonceV2 } from "./deriveOnionAeadKeyNonceV2.js";
import { canonicalJSONStringify } from "../../util/canonicalize.js";
import { base64ToBytes, isBytes } from "../../util/bytes.js";

const encoder = new TextEncoder();

function toBytes(value, label) {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return new Uint8Array(value);
  if (typeof value === "string") return base64ToBytes(value);
  throw new Error(`OnionLayerAeadV2.${label} must be Uint8Array`);
}

function aadBytes(hopIndex, ttl, onionKeyId) {
  const obj = { v: 2, hopIndex, ttl, onionKeyId };
  return encoder.encode(canonicalJSONStringify(obj));
}

export class OnionLayerAeadV2 {
  constructor({ crypto } = {}) {
    if (!(crypto instanceof RCryptoProvider)) {
      throw new Error("OnionLayerAeadV2 requires crypto (RCryptoProvider)");
    }
    this.crypto = crypto;
  }

  async encryptLayerV2({ relayPubKeyBytes, plaintextBytes, hopIndex, ttl, onionKeyId }) {
    const relayPub = toBytes(relayPubKeyBytes, "relayPubKeyBytes");
    const plain = toBytes(plaintextBytes, "plaintextBytes");
    if (!Number.isInteger(hopIndex) || hopIndex < 0) {
      throw new Error("OnionLayerAeadV2.encryptLayerV2 requires hopIndex >= 0");
    }
    if (!Number.isInteger(ttl) || ttl < 0) {
      throw new Error("OnionLayerAeadV2.encryptLayerV2 requires ttl >= 0");
    }
    if (typeof onionKeyId !== "string" || onionKeyId.length === 0) {
      throw new Error("OnionLayerAeadV2.encryptLayerV2 requires onionKeyId");
    }

    const eph = await this.crypto.dhGenerateKeyPair({ alg: "X25519", fmt: "spki" });
    const sharedSecret = await this.crypto.dhDerive({
      privateKey: eph.privateKey,
      publicKey: relayPub,
      alg: "X25519",
      fmt: "spki",
    });
    const { aeadKey, nonce } = await deriveOnionAeadKeyNonceV2(this.crypto, sharedSecret, hopIndex);
    const aad = aadBytes(hopIndex, ttl, onionKeyId);
    const ct = await encryptAes256Gcm(this.crypto, aeadKey, nonce, plain, aad);

    return { v: 2, onionKeyId, ephPub: eph.publicKey, ct };
  }

  async decryptLayerV2({ relayPrivKeyBytes, layerObj, hopIndex }) {
    const relayPriv = toBytes(relayPrivKeyBytes, "relayPrivKeyBytes");
    if (!Number.isInteger(hopIndex) || hopIndex < 0) {
      throw new Error("OnionLayerAeadV2.decryptLayerV2 requires hopIndex >= 0");
    }
    if (!layerObj || typeof layerObj !== "object") {
      throw new Error("OnionLayerAeadV2.decryptLayerV2 requires layerObj");
    }

    const onionKeyId = layerObj.onionKeyId;
    if (typeof onionKeyId !== "string" || onionKeyId.length === 0) {
      throw new Error("OnionLayerAeadV2.decryptLayerV2 requires onionKeyId");
    }
    const ttl = layerObj.ttl;
    if (!Number.isInteger(ttl) || ttl < 0) {
      throw new Error("OnionLayerAeadV2.decryptLayerV2 requires layerObj.ttl >= 0");
    }

    const ephPub = toBytes(layerObj.ephPub, "ephPub");
    const ct = toBytes(layerObj.ct, "ct");
    const sharedSecret = await this.crypto.dhDerive({
      privateKey: relayPriv,
      publicKey: ephPub,
      alg: "X25519",
      fmt: "spki",
    });
    const { aeadKey, nonce } = await deriveOnionAeadKeyNonceV2(this.crypto, sharedSecret, hopIndex);
    const aad = aadBytes(hopIndex, ttl, onionKeyId);
    const pt = await decryptAes256Gcm(this.crypto, aeadKey, nonce, ct, aad);
    return pt;
  }
}
