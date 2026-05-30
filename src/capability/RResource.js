import { RRecord } from "../base/index.js";

// `inbox` is the resource kind for capabilities scoped to a single inbox (see
// docs/CAPABILITY_MODEL.md). `mailbox` is the legacy / wire-family name and
// remains valid; new caps should prefer `inbox`.
// `channel` is reserved for channel.* protocol contracts.
// `object` is retained pending the rebuild of public-object posting under the
// new cap model (see memory project_object_namespace_removed.md).
const VALID_KINDS = Object.freeze(["channel", "inbox", "mailbox", "object"]);

export class RResource extends RRecord {
  static type = "RResource";
  static KINDS = Object.freeze({ INBOX: "inbox", MAILBOX: "mailbox", CHANNEL: "channel", OBJECT: "object" });

  constructor({ kind, id }) {
    super();
    this.kind = kind;
    this.id = id;
    this._seal();
  }

  validate() {
    this.assert(typeof this.kind === "string" && VALID_KINDS.includes(this.kind),
      `RResource.kind must be one of: ${VALID_KINDS.join(", ")}`);
    this.assert(typeof this.id === "string" && this.id.length > 0,
      "RResource.id must be a non-empty string");
    this.assert(this.id.length <= 512,
      "RResource.id must be at most 512 characters");
  }

  toString() {
    this._assertSealed();
    return `${this.kind}:${this.id}`;
  }

  static parse(str) {
    if (typeof str !== "string") {
      throw new Error("RResource.parse requires a string");
    }
    const idx = str.indexOf(":");
    if (idx < 0) {
      throw new Error(`RResource.parse: invalid format, expected "kind:id", got "${str}"`);
    }
    return new RResource({ kind: str.slice(0, idx), id: str.slice(idx + 1) });
  }

  static inbox(id) {
    return new RResource({ kind: "inbox", id });
  }

  static mailbox(id) {
    return new RResource({ kind: "mailbox", id });
  }

  static channel(id) {
    return new RResource({ kind: "channel", id });
  }

  static object(id) {
    return new RResource({ kind: "object", id });
  }
}
