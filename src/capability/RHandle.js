import { RRecord } from "../base/index.js";
import { canonicalJSONStringify } from "../util/canonicalize.js";

const HANDLE_PATTERN = /^[a-z0-9][a-z0-9_-]{0,62}[a-z0-9]$/;

export class RHandle extends RRecord {
  static type = "RHandle";

  constructor({ name, resourceId, ownerAccountId, registeredAtMs, signatureB64 = null }) {
    super();
    this.name = name;
    this.resourceId = resourceId;
    this.ownerAccountId = ownerAccountId;
    this.registeredAtMs = registeredAtMs;
    this.signatureB64 = signatureB64;
    this._seal();
  }

  validate() {
    this.assert(typeof this.name === "string" && this.name.length > 0,
      "RHandle.name must be a non-empty string");
    this.assert(this.name.length <= 64,
      "RHandle.name must be at most 64 characters");
    this.assert(HANDLE_PATTERN.test(this.name),
      "RHandle.name must be lowercase alphanumeric with hyphens/underscores, min 2 chars");

    this.assert(typeof this.resourceId === "string" && this.resourceId.length > 0,
      "RHandle.resourceId must be a non-empty string");

    this.assert(typeof this.ownerAccountId === "string" && this.ownerAccountId.length > 0,
      "RHandle.ownerAccountId must be a non-empty string");

    this.assert(typeof this.registeredAtMs === "number" && this.registeredAtMs > 0,
      "RHandle.registeredAtMs must be a positive number");

    this.assert(this.signatureB64 === null || typeof this.signatureB64 === "string",
      "RHandle.signatureB64 must be null or string");
  }

  _toSignablePayload() {
    this._assertSealed();
    const { signatureB64: _, ...fields } = this.toJSON();
    return canonicalJSONStringify(fields);
  }
}
