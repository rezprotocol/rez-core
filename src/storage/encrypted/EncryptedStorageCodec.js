import { RCryptoProvider } from "../../crypto/RCryptoProvider.js";
import { EncryptedStoreEnvelopeV1 } from "./EncryptedStoreEnvelopeV1.js";
import { StorageRecordRegistry } from "./StorageRecordRegistry.js";

function isBytes(value) {
  return value instanceof Uint8Array;
}

function toBase64(bytes) {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  // Fallback for non-Node environments
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function fromBase64(str) {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(str, "base64"));
  }
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

const NONCE_BYTES = 12;
const KEY_BYTES = 32;

/**
 * EncryptedStorageCodec — encrypts validated records for at-rest storage
 * and decrypts them back into validated record instances.
 *
 * seal(record) → EncryptedStoreEnvelopeV1
 *   1. record.toJSON() → plain object
 *   2. JSON.stringify → UTF-8 bytes
 *   3. AES-256-GCM encrypt with random nonce, contentType as AAD
 *   4. Wrap in EncryptedStoreEnvelopeV1
 *
 * open(envelope, registry) → typed record
 *   1. Validate envelope is EncryptedStoreEnvelopeV1
 *   2. AES-256-GCM decrypt with contentType as AAD
 *   3. JSON.parse → plain object
 *   4. registry.rehydrate(contentType, json) → validated record
 */
export class EncryptedStorageCodec {
  #crypto;
  #key;

  /**
   * @param {object} options
   * @param {RCryptoProvider} options.crypto — crypto provider with aeadEncrypt/aeadDecrypt
   * @param {Uint8Array} options.key — 32-byte AES-256 encryption key
   */
  constructor({ crypto, key } = {}) {
    if (!(crypto instanceof RCryptoProvider)) {
      throw new Error("EncryptedStorageCodec requires crypto (RCryptoProvider)");
    }
    if (!isBytes(key) || key.length !== KEY_BYTES) {
      throw new Error("EncryptedStorageCodec requires 32-byte key");
    }
    this.#crypto = crypto;
    this.#key = key;
  }

  /**
   * Encrypt a validated record into a sealed envelope.
   *
   * @param {RSerializable} record — must have static type and toJSON()
   * @returns {EncryptedStoreEnvelopeV1}
   */
  seal(record) {
    if (!record || typeof record.toJSON !== "function") {
      throw new Error("EncryptedStorageCodec.seal requires record with toJSON()");
    }
    const contentType = record.constructor && record.constructor.type;
    if (typeof contentType !== "string" || contentType.length === 0) {
      throw new Error("EncryptedStorageCodec.seal requires record with static type");
    }

    const json = record.toJSON();
    const plaintext = new TextEncoder().encode(JSON.stringify(json));
    const nonce = this.#crypto.randomBytes(NONCE_BYTES);
    const aad = new TextEncoder().encode(contentType);

    const ciphertext = this.#crypto.aeadEncrypt({
      key: this.#key,
      nonce,
      plaintext,
      aad,
    });

    return new EncryptedStoreEnvelopeV1({
      contentType,
      nonceB64: toBase64(nonce),
      ciphertextB64: toBase64(ciphertext),
    });
  }

  /**
   * Decrypt an envelope and rehydrate the inner record via registry.
   *
   * @param {EncryptedStoreEnvelopeV1} envelope
   * @param {StorageRecordRegistry} registry
   * @returns {RSerializable} — validated record instance
   */
  open(envelope, registry) {
    if (!(envelope instanceof EncryptedStoreEnvelopeV1)) {
      throw new Error("EncryptedStorageCodec.open requires EncryptedStoreEnvelopeV1");
    }
    if (!(registry instanceof StorageRecordRegistry)) {
      throw new Error("EncryptedStorageCodec.open requires StorageRecordRegistry");
    }

    // Verify the type is allowed BEFORE decryption
    if (!registry.isRegistered(envelope.contentType)) {
      throw new Error("EncryptedStorageCodec.open: unknown contentType \"" + envelope.contentType + "\"");
    }

    const nonce = fromBase64(envelope.nonceB64);
    const ciphertext = fromBase64(envelope.ciphertextB64);
    const aad = new TextEncoder().encode(envelope.contentType);

    const plaintext = this.#crypto.aeadDecrypt({
      key: this.#key,
      nonce,
      ciphertext,
      aad,
    });

    const json = JSON.parse(new TextDecoder().decode(plaintext));
    return registry.rehydrate(envelope.contentType, json);
  }
}
