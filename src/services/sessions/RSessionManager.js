import { RAbstract } from "../../base/index.js";

export class RSessionManager extends RAbstract {
  createInitiatorSession(_args) {
    return this.abstract("createInitiatorSession");
  }

  createResponderSession(_args) {
    return this.abstract("createResponderSession");
  }

  getSendContext(_peerId) {
    return this.abstract("getSendContext");
  }

  getRecvContext(_sid) {
    return this.abstract("getRecvContext");
  }

  rotateDh(_peerId) {
    return this.abstract("rotateDh");
  }
}
