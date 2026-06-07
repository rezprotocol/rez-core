import { RService } from "../base/index.js";
import { RTransport } from "../network/RTransport.js";
import { WirePacket } from "../network/WirePacket.js";
import { RRoutingTable } from "../runtime/routing/RRoutingTable.js";
import { RRoutingPolicy } from "../runtime/policy/RRoutingPolicy.js";
import { RLogger } from "../base/index.js";
import { NullLogTransport } from "../base/index.js";
import { isNonEmptyString } from "../util/strings.js";

export class ForwardingDispatcher extends RService {
  constructor({ transport, routingTable, policy, localHandler, logger } = {}) {
    const log = logger || new RLogger({ transports: [new NullLogTransport()] });
    super({ log });

    if (!(transport instanceof RTransport)) {
      throw new Error("ForwardingDispatcher requires transport (RTransport)");
    }
    if (!(routingTable instanceof RRoutingTable)) {
      throw new Error("ForwardingDispatcher requires routingTable (RRoutingTable)");
    }
    if (!(policy instanceof RRoutingPolicy)) {
      throw new Error("ForwardingDispatcher requires policy (RRoutingPolicy)");
    }
    if (typeof localHandler !== "function") {
      throw new Error("ForwardingDispatcher requires localHandler function");
    }
    if (!(log instanceof RLogger)) {
      throw new Error("ForwardingDispatcher requires logger (RLogger)");
    }

    this.transport = transport;
    this.routingTable = routingTable;
    this.policy = policy;
    this.localHandler = localHandler;
    this.log = log;
    this._unsubscribe = null;
  }

  _forward(packet, nextHop) {
    if (!isNonEmptyString(nextHop)) {
      throw new Error("ForwardingDispatcher FORWARD requires nextHop");
    }
    const existingMeta = packet.meta || {};
    const meta = existingMeta.finalTo ? { ...existingMeta } : { ...existingMeta, finalTo: packet.to };
    const forwardPacket = new WirePacket({
      bytes: packet.bytes,
      to: nextHop,
      from: packet.from,
      meta,
      id: packet.id,
    });
    this.transport.send(forwardPacket);
  }

  handlePacket(packet) {
    if (!(packet && packet.bytes instanceof Uint8Array)) {
      throw new Error("ForwardingDispatcher received packet without bytes");
    }
    const hasValidTo = isNonEmptyString(packet.to);
    const resolution = hasValidTo
      ? this.routingTable.resolveNextHop(packet.to)
      : { disposition: "DROP", nextHop: null };
    const decision = this.policy.decide(packet, resolution);
    if (decision.disposition === "LOCAL") {
      try {
        const result = this.localHandler(packet);
        if (result && typeof result.then === "function") {
          result.catch((err) => {
            if (this.log && this.log.error) this.log.error("ForwardingDispatcher localHandler failed", { err });
          });
        }
      } catch (err) {
        throw err;
      }
      return;
    }

    if (decision.disposition === "FORWARD") {
      this._forward(packet, decision.nextHop);
      return;
    }

    if (decision.disposition === "DROP") {
      if (this.log && this.log.debug) this.log.debug("ForwardingDispatcher dropped packet", { to: packet.to, reason: decision.reason });
      return;
    }

    throw new Error("ForwardingDispatcher received invalid routing disposition");
  }

  async start() {
    if (this._unsubscribe) return;
    this._unsubscribe = this.transport.onPacket((packet) => {
      this.handlePacket(packet);
    });
    await super.start();
  }

  async stop() {
    if (this._unsubscribe) {
      this._unsubscribe();
      this._unsubscribe = null;
    }
    await super.stop();
  }
}
