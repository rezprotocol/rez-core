import { RRecord } from "../base/index.js";

export class RProtocolObject extends RRecord {
  static type = "RProtocolObject";

  constructor({ objectId, ciphertextB64, metadata = {}, signatureB64 = null, signerPublicKeyB64 = null }) {
    super();
    this.objectId = objectId;
    this.ciphertextB64 = ciphertextB64;
    this.metadata = Object.freeze({ ...metadata });
    this.signatureB64 = signatureB64;
    this.signerPublicKeyB64 = signerPublicKeyB64;
    this._seal();
  }

  validate() {
    this.assert(typeof this.objectId === "string" && this.objectId.length > 0,
      "RProtocolObject.objectId must be a non-empty string");

    this.assert(typeof this.ciphertextB64 === "string" && this.ciphertextB64.length > 0,
      "RProtocolObject.ciphertextB64 must be a non-empty string");

    this.assert(typeof this.metadata === "object" && this.metadata !== null,
      "RProtocolObject.metadata must be an object");

    if (this.metadata.contentType != null) {
      this.assert(typeof this.metadata.contentType === "string",
        "RProtocolObject.metadata.contentType must be a string");
    }
    if (this.metadata.sizeBytes != null) {
      this.assert(typeof this.metadata.sizeBytes === "number" && this.metadata.sizeBytes >= 0,
        "RProtocolObject.metadata.sizeBytes must be a non-negative number");
    }
    if (this.metadata.createdAtMs != null) {
      this.assert(typeof this.metadata.createdAtMs === "number",
        "RProtocolObject.metadata.createdAtMs must be a number");
    }

    const hasSig = this.signatureB64 !== null;
    const hasSigner = this.signerPublicKeyB64 !== null;
    this.assert(hasSig === hasSigner,
      "RProtocolObject: signatureB64 and signerPublicKeyB64 must both be present or both null");

    if (hasSig) {
      this.assert(typeof this.signatureB64 === "string",
        "RProtocolObject.signatureB64 must be a string");
      this.assert(typeof this.signerPublicKeyB64 === "string" && this.signerPublicKeyB64.length > 0,
        "RProtocolObject.signerPublicKeyB64 must be a non-empty string");
    }
  }
}
