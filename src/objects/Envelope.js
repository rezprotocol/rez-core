import { RSerializable } from "../base/index.js";
import { Header } from "./Header.js";

export class Envelope extends RSerializable {
  static type = "Envelope";
  static schemaVersion = 1;

  constructor({ header, body, meta = undefined } = {}) {
    super();

    this.assert(header instanceof Header, "Envelope.header must be a Header", { headerType: header?.type });
    this.assert(body !== undefined, "Envelope.body is required", { body });

    if (meta !== undefined) {
      this.assert(meta && typeof meta === "object" && !Array.isArray(meta), "Envelope.meta must be a plain object", { meta });
    }

    this.header = header;
    this.body = body;
    this.meta = meta;
  }

  toJSON() {
    return {
      schemaVersion: Envelope.schemaVersion,
      header: this.header.toJSON(),
      body: this.body,
      meta: this.meta,
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("Envelope.fromJSON(json) requires an object");
    }
    if (!json.header) {
      throw new Error("Envelope.fromJSON(json) requires header");
    }

    return new Envelope({
      header: Header.fromJSON(json.header),
      body: json.body,
      meta: json.meta,
    });
  }
}
