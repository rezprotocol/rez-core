import { RObject } from "./RObject.js";

export class RRecord extends RObject {
  static type = "RRecord";

  constructor() {
    super();
    this._sealed = false;
  }

  // subclasses override
  validate() {}

  _seal() {
    this.assert(this._sealed === false, "RRecord already sealed");
    this.validate();
    this._sealed = true;
    deepFreeze(this);
    return this;
  }

  _assertSealed() {
    this.assert(this._sealed === true, "RRecord not sealed");
  }

  toJSON() {
    this._assertSealed();
    const out = {};
    for (const [k, v] of Object.entries(this)) {
      if (k.startsWith("_")) continue;
      if (k === "type") continue;
      out[k] = v;
    }
    return out;
  }

  static tryCreate(raw) {
    try {
      return new this(raw ?? {});
    } catch {
      return null;
    }
  }

  static fromJSON(raw) {
    if (!raw || typeof raw !== "object") {
      const err = new Error("Expected object");
      err.name = "RezContractDecodeError";
      throw err;
    }
    return new this(raw);
  }

  /**
   * Check whether raw input would pass validation without creating an instance.
   * Returns { valid: true } or { valid: false, errors: string[] }.
   * Subclasses may override to return multiple errors without constructing.
   */
  static validateRaw(raw) {
    try {
      new this(raw);
      return { valid: true };
    } catch (err) {
      const msg = err?.message ?? "Invalid";
      return { valid: false, errors: [msg] };
    }
  }

  static newId(prefix = "rec", randomBytes) {
    if (typeof randomBytes !== "function") {
      throw new Error("RRecord.newId requires randomBytes(length) function");
    }
    const bytes = randomBytes(16);
    if (!(bytes instanceof Uint8Array) || bytes.length !== 16) {
      throw new Error("RRecord.newId randomBytes must return Uint8Array(16)");
    }
    let hex = "";
    for (const b of bytes) hex += b.toString(16).padStart(2, "0");
    return `${prefix}_${hex}`;
  }
}

function deepFreeze(obj) {
  if (!obj || typeof obj !== "object" || Object.isFrozen(obj)) return obj;
  Object.freeze(obj);
  for (const v of Object.values(obj)) deepFreeze(v);
  return obj;
}
