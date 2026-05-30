import { RService } from "../base/index.js";
import { RTransport } from "../network/RTransport.js";
import { RezRuntime } from "./RezRuntime.js";
import { RLogger } from "../base/index.js";
import { NullLogTransport } from "../base/index.js";

export class InboxDispatcher extends RService {
  constructor({ transport, runtime, logger } = {}) {
    const log = logger || runtime?.log || new RLogger({ transports: [new NullLogTransport()] });
    super({ log });

    if (!(transport instanceof RTransport)) {
      throw new Error("InboxDispatcher requires transport (RTransport)");
    }
    if (!(runtime instanceof RezRuntime)) {
      throw new Error("InboxDispatcher requires runtime (RezRuntime)");
    }
    if (!(log instanceof RLogger)) {
      throw new Error("InboxDispatcher requires logger (RLogger)");
    }

    this.transport = transport;
    this.runtime = runtime;
    this.log = log;
    this._unsubscribe = null;
  }

  handlePacket(packet) {
    if (!(packet?.bytes instanceof Uint8Array)) {
      throw new Error("InboxDispatcher received packet without bytes");
    }
    try {
      const result = this.runtime.receivePacket(packet);
      if (result && typeof result.then === "function") {
        result.catch((err) => {
          this.log?.error?.("InboxDispatcher receivePacket failed", { err });
        });
      }
    } catch (err) {
      throw err;
    }
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
