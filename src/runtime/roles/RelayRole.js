// NOTE:
// This class enforces dependency injection and lifecycle wiring only.
// It MUST NOT implement routing, forwarding, discovery, or protocol logic.
// Those belong to later phases.
import { RTransport } from "../../network/RTransport.js";
import { RezRuntime } from "../../services/RezRuntime.js";
import { isNonEmptyString } from "../../util/strings.js";

export class RelayRole {
  constructor({ id, transport, runtime, dispatcher = null, forwardingDispatcher = null } = {}) {
    if (!isNonEmptyString(id)) {
      throw new Error("RelayRole requires id");
    }
    if (!(transport instanceof RTransport)) {
      throw new Error("RelayRole requires transport (RTransport)");
    }
    if (!(runtime instanceof RezRuntime)) {
      throw new Error("RelayRole requires runtime (RezRuntime)");
    }

    this.id = id;
    this.transport = transport;
    this.runtime = runtime;
    this.dispatcher = dispatcher;
    this.forwardingDispatcher = forwardingDispatcher;
  }

  getRelayId() {
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
    if (this.dispatcher?.start) {
      await this.dispatcher.start();
    }
    if (this.forwardingDispatcher?.start) {
      await this.forwardingDispatcher.start();
    }
  }

  async stop() {
    if (this.forwardingDispatcher?.stop) {
      await this.forwardingDispatcher.stop();
    }
    if (this.dispatcher?.stop) {
      await this.dispatcher.stop();
    }
    if (typeof this.runtime.stop === "function") {
      await this.runtime.stop();
    }
    await this.transport.stop();
  }
}
