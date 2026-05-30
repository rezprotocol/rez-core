import { RAbstract } from "../base/index.js";

export class KeyValueStore extends RAbstract {
  set(_key, _value) {
    return this.abstract("set");
  }

  get(_key) {
    return this.abstract("get");
  }

  delete(_key) {
    return this.abstract("delete");
  }

  keys(_prefix = "") {
    return this.abstract("keys");
  }
}
