import { RRecord } from "../base/index.js";
import { canonicalJSONStringify } from "../util/canonicalize.js";
import { RResource } from "./RResource.js";

const ACTIONS = Object.freeze(["admin", "connect", "grant", "post", "read", "write"]);

export class RCapability extends RRecord {
  static type = "RCapability";
  static ACTIONS = ACTIONS;

  constructor({ capId, parentCapId = null, resource, actions, constraints = {},
                signerPublicKeyB64, granteePublicKeyB64 = null, signatureB64 = null }) {
    super();
    this.capId = capId;
    this.parentCapId = parentCapId;
    this.resource = resource;
    this.actions = Object.freeze([...actions].sort());
    this.constraints = Object.freeze({ ...constraints });
    this.signerPublicKeyB64 = signerPublicKeyB64;
    this.granteePublicKeyB64 = granteePublicKeyB64;
    this.signatureB64 = signatureB64;
    this._seal();
  }

  validate() {
    this.assert(typeof this.capId === "string" && this.capId.length > 0,
      "RCapability.capId must be a non-empty string");

    this.assert(this.parentCapId === null || typeof this.parentCapId === "string",
      "RCapability.parentCapId must be null or string");

    this.assert(typeof this.resource === "string" && this.resource.length > 0,
      "RCapability.resource must be a non-empty string");
    RResource.parse(this.resource);

    this.assert(Array.isArray(this.actions) && this.actions.length > 0,
      "RCapability.actions must be a non-empty array");
    for (const a of this.actions) {
      this.assert(ACTIONS.includes(a),
        `RCapability.actions contains invalid action: "${a}"`);
    }

    this.assert(typeof this.constraints === "object" && this.constraints !== null,
      "RCapability.constraints must be an object");
    if (this.constraints.expiresAt != null) {
      this.assert(typeof this.constraints.expiresAt === "number",
        "RCapability.constraints.expiresAt must be a number");
    }
    if (this.constraints.maxUses != null) {
      this.assert(typeof this.constraints.maxUses === "number" && this.constraints.maxUses > 0,
        "RCapability.constraints.maxUses must be a positive number");
    }
    if (this.constraints.maxDelegationDepth != null) {
      this.assert(typeof this.constraints.maxDelegationDepth === "number" && this.constraints.maxDelegationDepth >= 0,
        "RCapability.constraints.maxDelegationDepth must be a non-negative number");
    }

    this.assert(typeof this.signerPublicKeyB64 === "string" && this.signerPublicKeyB64.length > 0,
      "RCapability.signerPublicKeyB64 must be a non-empty string");

    this.assert(this.granteePublicKeyB64 === null
      || (typeof this.granteePublicKeyB64 === "string" && this.granteePublicKeyB64.length > 0),
      "RCapability.granteePublicKeyB64 must be null or a non-empty string");

    this.assert(this.signatureB64 === null || typeof this.signatureB64 === "string",
      "RCapability.signatureB64 must be null or string");
  }

  _toSignablePayload() {
    this._assertSealed();
    const { signatureB64: _, ...fields } = this.toJSON();
    return canonicalJSONStringify(fields);
  }
}
