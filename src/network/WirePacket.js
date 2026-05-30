import { isNonEmptyString } from "../util/strings.js";

export class WirePacket {
  constructor({ bytes, to, from = undefined, meta = undefined, id = undefined } = {}) {
    if (!(bytes instanceof Uint8Array)) {
      throw new Error("WirePacket.bytes must be a Uint8Array");
    }
    if (!isNonEmptyString(to)) {
      throw new Error("WirePacket.to must be a non-empty string");
    }

    this.bytes = bytes;
    this.to = to;
    this.from = from;
    this.meta = meta;
    this.id = id;
  }
}
