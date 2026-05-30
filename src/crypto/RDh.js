import { RAbstract } from "../base/index.js";

export class RDh extends RAbstract {
  generateKeyPair() {
    return this.abstract("generateKeyPair");
  }

  deriveSecret(_privateKeyBytes, _publicKeyBytes) {
    return this.abstract("deriveSecret");
  }

  getAlgId() {
    return this.abstract("getAlgId");
  }
}
