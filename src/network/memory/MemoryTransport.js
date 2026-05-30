import { RTransport } from "../RTransport.js";
import { WirePacket } from "../WirePacket.js";
import { isNonEmptyString } from "../../util/strings.js";

export class MemoryTransport extends RTransport {
  constructor({ endpointId, network } = {}) {
    super();

    if (!isNonEmptyString(endpointId)) {
      throw new Error("MemoryTransport requires endpointId");
    }
    if (!network) {
      throw new Error("MemoryTransport requires network");
    }

    this.endpointId = endpointId;
    this.network = network;
    this.handlers = new Set();
    this.started = false;
  }

  start() {
    if (this.started) return;
    this.started = true;
    this.network.register(this.endpointId, this);
  }

  stop() {
    if (!this.started) return;
    this.started = false;
    this.network.unregister(this.endpointId);
  }

  onPacket(handler) {
    if (typeof handler !== "function") {
      throw new Error("MemoryTransport.onPacket(handler) requires a function");
    }

    this.handlers.add(handler);
    return () => {
      this.handlers.delete(handler);
    };
  }

  send(packet) {
    if (!this.started) {
      throw new Error("MemoryTransport.send(packet) called before start()");
    }

    const wire = packet instanceof WirePacket ? packet : new WirePacket(packet);
    const delivered = this.network.deliver(wire);
    if (!delivered) {
      const err = new Error(`MemoryTransport could not deliver to ${wire.to}`);
      err.code = "REZ_UNDELIVERABLE";
      throw err;
    }
  }

  deliver(packet) {
    if (!this.started) return;
    for (const handler of this.handlers) {
      handler(packet);
    }
  }
}
