import { RAbstract } from "./RAbstract.js";
import RDisposable from "./RDisposable.js";
import { RLogger } from "./logging/RLogger.js";
import { NullLogTransport } from "./logging/transports/NullLogTransport.js";

export class RService extends RAbstract {
  constructor({ log, logger } = {}) {
    super();
    const l = log ?? logger ?? new RLogger({ transports: [new NullLogTransport()] });
    this.log = l;
    this.logger = l;
    this._started = false;
    this._owned = [];
  }

  get started() {
    return this._started;
  }

  async start() {
    this._started = true;
  }

  async stop() {
    this._disposeOwned();
    this._started = false;
  }

  own(disposable) {
    if (!disposable) return disposable;
    let entry = disposable;
    if (typeof disposable === "function") {
      entry = new RDisposable(disposable);
    } else if (typeof disposable.dispose !== "function") {
      throw new Error("RService.own requires a disposable or function");
    }
    this._owned.push(entry);
    return disposable;
  }

  _disposeOwned() {
    for (let i = this._owned.length - 1; i >= 0; i -= 1) {
      const item = this._owned[i];
      try {
        item.dispose();
      } catch (err) {
        if (this.log && this.log.error) this.log.error("RService failed to dispose owned item", { err });
      }
    }
    this._owned = [];
  }
}
