import { RAbstract } from "../../base/index.js";

export class RRelayRole extends RAbstract {
  getRelayId() {
    return this.abstract("getRelayId");
  }

  getTransport() {
    return this.abstract("getTransport");
  }

  getRuntime() {
    return this.abstract("getRuntime");
  }

  start() {
    return this.abstract("start");
  }

  stop() {
    return this.abstract("stop");
  }
}
