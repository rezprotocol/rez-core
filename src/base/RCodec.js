import { RAbstract } from "./RAbstract.js";

export class RCodec extends RAbstract {
  constructor() {
    super();
    this.name = this.constructor.name;
  }

  encode(_ctx) {
    return this.abstract("encode");
  }

  decode(_ctx) {
    return this.abstract("decode");
  }
}
