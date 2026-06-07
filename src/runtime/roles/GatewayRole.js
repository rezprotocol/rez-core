// NOTE:
// This class enforces dependency injection and lifecycle wiring only.
// It MUST NOT implement routing, forwarding, discovery, or protocol logic.
// Those belong to later phases.
import { RTransport } from "../../network/RTransport.js";
import { RezRuntime } from "../../services/RezRuntime.js";
import { isNonEmptyString } from "../../util/strings.js";

export class GatewayRole {
  constructor({ id, transport, runtime, dispatcher = null } = {}) {
    if (!isNonEmptyString(id)) {
      throw new Error("GatewayRole requires id");
    }
    if (!(transport instanceof RTransport)) {
      throw new Error("GatewayRole requires transport (RTransport)");
    }
    if (!(runtime instanceof RezRuntime)) {
      throw new Error("GatewayRole requires runtime (RezRuntime)");
    }

    this.id = id;
    this.transport = transport;
    this.runtime = runtime;
    this.dispatcher = dispatcher;
  }

  getGatewayId() {
    return this.id;
  }

  getTransport() {
    return this.transport;
  }

  getRuntime() {
    return this.runtime;
  }

  async start() {
    await this.transport.start();
    if (typeof this.runtime.start === "function") {
      await this.runtime.start();
    }
    if (this.dispatcher && this.dispatcher.start) {
      await this.dispatcher.start();
    }
  }

  async stop() {
    if (this.dispatcher && this.dispatcher.stop) {
      await this.dispatcher.stop();
    }
    if (typeof this.runtime.stop === "function") {
      await this.runtime.stop();
    }
    await this.transport.stop();
  }
}
