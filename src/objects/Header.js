import { RSerializable } from "../base/index.js";
import { Link } from "./Link.js";
import { isNonEmptyString } from "../util/strings.js";

function assertFiniteNumber(v) {
  return typeof v === "number" && Number.isFinite(v);
}

export class Header extends RSerializable {
  static type = "Header";
  static schemaVersion = 1;

  constructor({ id, type, createdAt, links = [] } = {}) {
    super();

    this.assert(isNonEmptyString(id), "Header.id must be a non-empty string", { id });
    this.assert(isNonEmptyString(type), "Header.type must be a non-empty string", { type });
    this.assert(assertFiniteNumber(createdAt), "Header.createdAt must be a finite number", { createdAt });

    if (links == null) links = [];
    this.assert(Array.isArray(links), "Header.links must be an array", { links });

    for (let i = 0; i < links.length; i++) {
      const link = links[i];
      this.assert(link instanceof Link, "Header.links entries must be Link instances", { link, i });
    }

    this.id = id;
    this.type = type;
    this.createdAt = createdAt;
    this.links = links;
  }

  toJSON() {
    return {
      schemaVersion: Header.schemaVersion,
      id: this.id,
      type: this.type,
      createdAt: this.createdAt,
      links: this.links.map((link) => link.toJSON()),
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("Header.fromJSON(json) requires an object");
    }

    return new Header({
      id: json.id,
      type: json.type,
      createdAt: json.createdAt,
      links: (json.links ?? []).map((link) => Link.fromJSON(link)),
    });
  }
}
