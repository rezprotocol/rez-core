import { RAbstract } from "../../base/index.js";

export class RRoutingTable extends RAbstract {
  resolveNextHop(_to) {
    return this.abstract("resolveNextHop");
  }
}
