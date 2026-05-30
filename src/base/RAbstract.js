import { RObject } from "./RObject.js";

export class RAbstract extends RObject {
  abstract(methodName) {
    const err = new Error(`${this.type} must implement ${methodName}()`);
    err.name = "RezAbstractError";
    throw err;
  }
}
