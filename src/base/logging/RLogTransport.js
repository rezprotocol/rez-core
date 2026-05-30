import { RAbstract } from "../RAbstract.js";

export class RLogTransport extends RAbstract {
  handle(_event) {
    return this.abstract("handle");
  }
}
