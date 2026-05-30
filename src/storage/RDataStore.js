import { RAbstract } from "../base/index.js";

export class RDataStore extends RAbstract {
  static type = "RDataStore";

  put(_key, _value) {
    return this.abstract("put");
  }

  get(_key) {
    return this.abstract("get");
  }

  list(_prefix, _opts) {
    return this.abstract("list");
  }

  remove(_key) {
    return this.abstract("remove");
  }

  has(_key) {
    return this.abstract("has");
  }

  clear() {
    return this.abstract("clear");
  }
}
