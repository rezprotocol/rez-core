import { RRoutingTable } from "./RRoutingTable.js";
import { isNonEmptyString } from "../../util/strings.js";

export class SimpleRoutingTable extends RRoutingTable {
  constructor({ localIds = [], routes = new Map(), defaultUpstream = null } = {}) {
    super();

    if (!Array.isArray(localIds)) {
      throw new Error("SimpleRoutingTable requires localIds array");
    }
    if (!(routes instanceof Map)) {
      throw new Error("SimpleRoutingTable requires routes Map");
    }
    if (defaultUpstream != null && !isNonEmptyString(defaultUpstream)) {
      throw new Error("SimpleRoutingTable defaultUpstream must be a non-empty string");
    }

    this.localIds = new Set(localIds);
    this.routes = routes;
    this.defaultUpstream = defaultUpstream;
  }

  resolveNextHop(to) {
    if (!isNonEmptyString(to)) {
      throw new Error("SimpleRoutingTable.resolveNextHop(to) requires non-empty string");
    }

    if (this.localIds.has(to)) {
      return { disposition: "LOCAL", nextHop: null };
    }

    if (this.routes.has(to)) {
      return { disposition: "FORWARD", nextHop: this.routes.get(to) };
    }

    if (this.defaultUpstream) {
      return { disposition: "FORWARD", nextHop: this.defaultUpstream };
    }

    return { disposition: "DROP", nextHop: null };
  }
}
