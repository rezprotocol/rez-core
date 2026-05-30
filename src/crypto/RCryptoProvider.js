import { RAbstract } from "../base/index.js";

export class RCryptoProvider extends RAbstract {
  randomBytes(_len) {
    return this.abstract("randomBytes");
  }

  hashSha256(_bytes) {
    return this.abstract("hashSha256");
  }

  hkdfSha256(_ikm, _options = {}) {
    return this.abstract("hkdfSha256");
  }

  aeadEncrypt(_params = {}) {
    return this.abstract("aeadEncrypt");
  }

  aeadDecrypt(_params = {}) {
    return this.abstract("aeadDecrypt");
  }

  sign(_params = {}) {
    return this.abstract("sign");
  }

  verify(_params = {}) {
    return this.abstract("verify");
  }

  dhGenerateKeyPair(_params = {}) {
    return this.abstract("dhGenerateKeyPair");
  }

  dhDerive(_params = {}) {
    return this.abstract("dhDerive");
  }
}
