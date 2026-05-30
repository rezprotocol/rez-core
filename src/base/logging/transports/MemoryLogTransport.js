import { RLogTransport } from "../RLogTransport.js";

export class MemoryLogTransport extends RLogTransport {
  constructor({ limit = Infinity } = {}) {
    super();
    this.limit = limit;
    this.events = [];
  }

  handle(event) {
    this.events.push(event);
    if (Number.isFinite(this.limit) && this.limit > 0 && this.events.length > this.limit) {
      this.events.splice(0, this.events.length - this.limit);
    }
  }

  getEvents() {
    return this.events.map((evt) => ({ ...evt }));
  }
}
