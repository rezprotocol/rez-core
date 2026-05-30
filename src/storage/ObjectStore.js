import { RAbstract } from "../base/index.js";
import { Envelope } from "../objects/Envelope.js";

export class ObjectStore extends RAbstract {
  put(envelope) {
    if (!(envelope instanceof Envelope)) {
      throw new Error("ObjectStore.put(envelope) requires an Envelope");
    }
    if (!envelope.header || typeof envelope.header.id !== "string") {
      throw new Error("ObjectStore.put(envelope) requires envelope.header.id string");
    }
    // validation only; implementation must store in subclass
  }

  get(_id) {
    return this.abstract("get");
  }

  has(_id) {
    return this.abstract("has");
  }

  delete(_id) {
    return this.abstract("delete");
  }

  listIds() {
    return this.abstract("listIds");
  }
}
