import { RRoutingPolicy } from "./RRoutingPolicy.js";
import { isNonEmptyString } from "../../util/strings.js";

const DEFAULT_MAX_PACKET_BYTES = 8 * 1024 * 1024;

export class DefaultRoutingPolicy extends RRoutingPolicy {
  constructor({ maxPacketBytes = DEFAULT_MAX_PACKET_BYTES } = {}) {
    super();
    this.maxPacketBytes = maxPacketBytes;
  }

  decide(packet, resolution) {
    if (!packet || !isNonEmptyString(packet.to)) {
      return { disposition: "DROP", nextHop: null, reason: "INVALID_TO" };
    }
    if (!(packet.bytes instanceof Uint8Array)) {
      return { disposition: "DROP", nextHop: null, reason: "INVALID_BYTES" };
    }
    if (packet.bytes.length > this.maxPacketBytes) {
      return { disposition: "DROP", nextHop: null, reason: "OVERSIZE" };
    }

    if (resolution?.disposition === "LOCAL") {
      return { disposition: "LOCAL", nextHop: null };
    }
    if (resolution?.disposition === "FORWARD") {
      return { disposition: "FORWARD", nextHop: resolution.nextHop ?? null };
    }
    return { disposition: "DROP", nextHop: null };
  }
}

export { DEFAULT_MAX_PACKET_BYTES };
