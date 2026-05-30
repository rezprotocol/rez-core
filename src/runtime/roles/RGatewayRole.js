import { RAbstract } from "../../base/index.js";

export class RGatewayRole extends RAbstract {
  getGatewayId() {
    return this.abstract("getGatewayId");
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
