import { RAbstract } from "../base/index.js";

export class RSigner extends RAbstract {
  generateSigningKeyPair() {
    return this.abstract("generateSigningKeyPair");
  }

  sign(_privateKey, _bytes) {
    return this.abstract("sign");
  }

  verify(_publicKey, _bytes, _signature) {
    return this.abstract("verify");
  }
}
