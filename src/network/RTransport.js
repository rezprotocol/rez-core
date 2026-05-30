import { RAbstract } from "../base/index.js";

export class RTransport extends RAbstract {
  send(_packet) {
    return this.abstract("send");
  }

  onPacket(_handler) {
    return this.abstract("onPacket");
  }

  start() {
    return this.abstract("start");
  }

  stop() {
    return this.abstract("stop");
  }
}
