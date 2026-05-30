import { RSerializable } from "../base/index.js";
import { isNonEmptyString } from "../util/strings.js";

function isPlainObject(v) {
  return v != null && typeof v === "object" && !Array.isArray(v);
}

export class Link extends RSerializable {
  static type = "Link";
  static schemaVersion = 1;

  constructor({ rel, target, meta = undefined } = {}) {
    super();

    this.assert(isNonEmptyString(rel), "Link.rel must be a non-empty string", { rel });
    this.assert(isNonEmptyString(target), "Link.target must be a non-empty string", { target });

    if (meta !== undefined) {
      this.assert(isPlainObject(meta), "Link.meta must be a plain object", { meta });
    }

    this.rel = rel;
    this.target = target;
    this.meta = meta;
  }

  toJSON() {
    return {
      schemaVersion: Link.schemaVersion,
      rel: this.rel,
      target: this.target,
      meta: this.meta,
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("Link.fromJSON(json) requires an object");
    }

    return new Link({
      rel: json.rel,
      target: json.target,
      meta: json.meta,
    });
  }
}
