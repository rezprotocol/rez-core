import { RAbstract } from "../base/index.js";

export class RChannel extends RAbstract {
  static type = "RChannel";

  open(_channelId, _capability) {
    return this.abstract("open");
  }

  close(_channelId) {
    return this.abstract("close");
  }

  send(_channelId, _data) {
    return this.abstract("send");
  }

  onData(_channelId, _handler) {
    return this.abstract("onData");
  }

  onClose(_channelId, _handler) {
    return this.abstract("onClose");
  }
}
