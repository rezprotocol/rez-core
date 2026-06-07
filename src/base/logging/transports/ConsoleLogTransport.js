import { RLogTransport } from "../RLogTransport.js";

export class ConsoleLogTransport extends RLogTransport {
  constructor(consoleAdapter = console) {
    super();
    this.console = consoleAdapter;
  }

  handle(event) {
    const fn = (this.console && this.console[event.level]) || (this.console && this.console.log);
    if (typeof fn === "function") {
      fn.call(this.console, event.message, event.meta);
    }
  }
}
