import { RAbstract } from "./RAbstract.js";

export class RSerializable extends RAbstract {
  static schemaVersion = 1;

  toJSON() {
    return this.abstract("toJSON");
  }

  static fromJSON(_json) {
    throw new Error(`${this.name} must implement static fromJSON(json)`);
  }

  toCanonical() {
    return this.toJSON();
  }
}
