import { RObject } from "../RObject.js";
import { RLogTransport } from "./RLogTransport.js";
import { LogLevels } from "./LogLevels.js";

export class RLogger extends RObject {
  constructor({ transports = [] } = {}) {
    super();

    if (!Array.isArray(transports)) {
      throw new Error("RLogger requires transports array");
    }

    for (const transport of transports) {
      if (!(transport instanceof RLogTransport)) {
        throw new Error("RLogger transports must extend RLogTransport");
      }
    }

    this.transports = [...transports];
  }

  log(level, message, meta = undefined) {
    const event = {
      level,
      message,
      meta,
      timeMs: Date.now(),
    };

    for (const transport of this.transports) {
      try {
        transport.handle(event);
      } catch (_err) {
        // keep logging non-fatal
      }
    }
  }

  debug(message, meta) {
    this.log(LogLevels.DEBUG, message, meta);
  }

  info(message, meta) {
    this.log(LogLevels.INFO, message, meta);
  }

  warn(message, meta) {
    this.log(LogLevels.WARN, message, meta);
  }

  error(message, meta) {
    this.log(LogLevels.ERROR, message, meta);
  }
}
