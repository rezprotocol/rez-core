import { RRecord } from "../base/RRecord.js";

export class BridgeEvent extends RRecord {
  static type = "bridge.evt";

  constructor(raw = {}) {
    super();
    if (raw === null || raw === undefined || typeof raw !== "object") {
      throw new Error("BridgeEvent requires object input");
    }
    this.ns = String(raw.ns || "").trim();
    this.event = String(raw.event || "").trim();
    this.data = raw.data && typeof raw.data === "object" ? raw.data : {};
    this._seal();
  }

  validate() {
    this.assert(typeof this.ns === "string" && this.ns.length > 0, "BridgeEvent requires ns");
    this.assert(typeof this.event === "string" && this.event.length > 0, "BridgeEvent requires event");
    this.assert(this.data !== null && typeof this.data === "object", "BridgeEvent requires data object");
  }
}
