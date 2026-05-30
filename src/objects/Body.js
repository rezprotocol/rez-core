import { RSerializable } from "../base/index.js";

export class Body extends RSerializable {
  static type = "Body";

  constructor() {
    super();
    if (new.target === Body) {
      throw new Error("Body is abstract and cannot be instantiated directly");
    }
  }
}
