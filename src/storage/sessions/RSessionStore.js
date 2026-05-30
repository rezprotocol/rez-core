import { RAbstract } from "../../base/RAbstract.js";

export class RSessionStore extends RAbstract {
  async get(_sidBytes) {
    return this.abstract("get");
  }

  async put(_record) {
    return this.abstract("put");
  }

  async delete(_sidBytes) {
    return this.abstract("delete");
  }

  async list() {
    return this.abstract("list");
  }
}
