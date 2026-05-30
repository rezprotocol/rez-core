export class RObject {
  static type = "RObject";

  constructor() {
    this.type = this.constructor.type || this.constructor.name;
  }

  toString() {
    return `${this.type}`;
  }

  assert(condition, message, details) {
    if (condition) return;
    const err = new Error(message || "Assertion failed");
    err.name = "RezInvariantError";
    if (details) err.details = details;
    throw err;
  }

  dispose() {
    // optional cleanup
  }
}
