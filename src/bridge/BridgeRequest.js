import { RRecord } from "../base/RRecord.js";

export class BridgeRequest extends RRecord {
  static type = "bridge.req";

  constructor(raw = {}) {
    super();
    if (raw === null || raw === undefined || typeof raw !== "object") {
      throw new Error("BridgeRequest requires object input");
    }
    this.ns = String(raw.ns || "").trim();
    this.reqId = String(raw.reqId || "").trim();
    this.method = String(raw.method || "").trim();
    this.params = raw.params && typeof raw.params === "object" ? raw.params : {};
    this._seal();
  }

  validate() {
    this.assert(typeof this.ns === "string" && this.ns.length > 0, "BridgeRequest requires ns");
    this.assert(typeof this.reqId === "string" && this.reqId.length > 0, "BridgeRequest requires reqId");
    this.assert(typeof this.method === "string" && this.method.length > 0, "BridgeRequest requires method");
    this.assert(this.params !== null && typeof this.params === "object", "BridgeRequest requires params object");
  }
}
