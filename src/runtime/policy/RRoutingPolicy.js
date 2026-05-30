import { RAbstract } from "../../base/index.js";

export class RRoutingPolicy extends RAbstract {
  decide(_packet, _resolution) {
    return this.abstract("decide");
  }
}
