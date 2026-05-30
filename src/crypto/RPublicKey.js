import { RObject } from "../base/index.js";

export class RPublicKey extends RObject {
  constructor({ alg, raw } = {}) {
    super();
    this._alg = alg;
    this._raw = raw;
  }

  get alg() {
    return this._alg;
  }

  get raw() {
    return this._raw;
  }
}
