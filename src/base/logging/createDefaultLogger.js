import { LogLevels } from "./LogLevels.js";
import { RLogTransport } from "./RLogTransport.js";
import { RLogger } from "./RLogger.js";
import { ConsoleLogTransport } from "./transports/ConsoleLogTransport.js";

const levelOrder = {
  [LogLevels.DEBUG]: 10,
  [LogLevels.INFO]: 20,
  [LogLevels.WARN]: 30,
  [LogLevels.ERROR]: 40,
};

class FilterLogTransport extends RLogTransport {
  constructor({ transport, minLevel }) {
    super();
    this.transport = transport;
    this.minLevel = minLevel;
  }

  handle(event) {
    const levelValue = levelOrder[event.level] ?? 0;
    const minValue = levelOrder[this.minLevel] ?? 0;
    if (levelValue < minValue) return;
    this.transport.handle(event);
  }
}

export function createDefaultLogger({ minLevel = LogLevels.INFO } = {}) {
  const consoleTransport = new ConsoleLogTransport();
  const filtered = new FilterLogTransport({ transport: consoleTransport, minLevel });
  return new RLogger({ transports: [filtered] });
}
