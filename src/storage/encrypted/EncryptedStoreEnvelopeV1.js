import { RSerializable } from "../../base/index.js";

/**
 * Sealed envelope for encrypted-at-rest records.
 *
 * Every value written to persistent storage goes through this envelope.
 * On read, the envelope is validated first (shape check), then decrypted,
 * then the inner record is rehydrated via a StorageRecordRegistry.
 *
 * Fields:
 *   v             — envelope version (always 1)
 *   contentType   — the inner record's type name (e.g. "SecureSessionRecord")
 *   nonceB64      — base64-encoded 12-byte AES-GCM nonce
 *   ciphertextB64 — base64-encoded ciphertext (includes 16-byte auth tag)
 */
export class EncryptedStoreEnvelopeV1 extends RSerializable {
  static type = "EncryptedStoreEnvelopeV1";

  constructor({ contentType, nonceB64, ciphertextB64 } = {}) {
    super();

    this.assert(
      typeof contentType === "string" && contentType.length > 0,
      "EncryptedStoreEnvelopeV1.contentType must be non-empty string",
      { contentType },
    );
    this.assert(
      typeof nonceB64 === "string" && nonceB64.length > 0,
      "EncryptedStoreEnvelopeV1.nonceB64 must be non-empty string",
      { nonceB64 },
    );
    this.assert(
      typeof ciphertextB64 === "string" && ciphertextB64.length > 0,
      "EncryptedStoreEnvelopeV1.ciphertextB64 must be non-empty string",
      { ciphertextB64 },
    );

    this.v = 1;
    this.contentType = contentType;
    this.nonceB64 = nonceB64;
    this.ciphertextB64 = ciphertextB64;
  }

  toJSON() {
    return {
      v: 1,
      contentType: this.contentType,
      nonceB64: this.nonceB64,
      ciphertextB64: this.ciphertextB64,
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("EncryptedStoreEnvelopeV1.fromJSON requires object");
    }
    if (json.v !== 1) {
      throw new Error("EncryptedStoreEnvelopeV1.fromJSON requires v=1, got " + json.v);
    }
    return new EncryptedStoreEnvelopeV1({
      contentType: json.contentType,
      nonceB64: json.nonceB64,
      ciphertextB64: json.ciphertextB64,
    });
  }
}
