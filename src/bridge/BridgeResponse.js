import { RRecord } from "../base/RRecord.js";

export class BridgeResponse extends RRecord {
  static type = "bridge.res";

  constructor(raw = {}) {
    super();
    if (raw === null || raw === undefined || typeof raw !== "object") {
      throw new Error("BridgeResponse requires object input");
    }
    this.ns = String(raw.ns || "").trim();
    this.reqId = String(raw.reqId || "").trim();
    this.ok = raw.ok === true;
    this.method = String(raw.method || "").trim();
    this.data = this.ok && raw.data && typeof raw.data === "object" ? raw.data : null;
    if (this.ok === false && raw.error && typeof raw.error === "object") {
      this.error = Object.freeze({
        code: String(raw.error.code || ""),
        message: String(raw.error.message || ""),
      });
    } else {
      this.error = null;
    }
    this._seal();
  }

  validate() {
    this.assert(typeof this.ns === "string" && this.ns.length > 0, "BridgeResponse requires ns");
    this.assert(typeof this.reqId === "string" && this.reqId.length > 0, "BridgeResponse requires reqId");
    this.assert(typeof this.method === "string" && this.method.length > 0, "BridgeResponse requires method");
  }
}
