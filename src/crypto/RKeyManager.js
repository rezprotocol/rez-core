import { RAbstract } from "../base/index.js";

export class RKeyManager extends RAbstract {
  exportPublicKey(_publicKey) {
    return this.abstract("exportPublicKey");
  }

  exportPrivateKey(_privateKey) {
    return this.abstract("exportPrivateKey");
  }

  importPublicKey(_bytes) {
    return this.abstract("importPublicKey");
  }

  importPrivateKey(_bytes) {
    return this.abstract("importPrivateKey");
  }
}
