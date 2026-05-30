import { RSerializable } from "../../base/index.js";
import { isBytes } from "../../util/bytes.js";

function toBytes(value, label) {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return new Uint8Array(value);
  throw new Error(`RatchetHeaderV1.${label} must be Uint8Array`);
}

export class RatchetHeaderV1 extends RSerializable {
  static type = "RatchetHeaderV1";

  constructor({ v, sid, dh = null, dhAlg, dhFmt, pn, n } = {}) {
    super();

    this.assert(v === 1, "RatchetHeaderV1.v must be 1", { v });
    this.assert(isBytes(sid), "RatchetHeaderV1.sid must be Uint8Array", { sid });
    if (dh != null) {
      this.assert(isBytes(dh), "RatchetHeaderV1.dh must be Uint8Array or null", { dh });
    }
    this.assert(typeof dhAlg === "string" && dhAlg.length > 0, "RatchetHeaderV1.dhAlg must be non-empty string", { dhAlg });
    this.assert(dhFmt === "raw" || dhFmt === "spki", "RatchetHeaderV1.dhFmt must be raw or spki", { dhFmt });
    this.assert(Number.isInteger(pn) && pn >= 0, "RatchetHeaderV1.pn must be >= 0", { pn });
    this.assert(Number.isInteger(n) && n >= 0, "RatchetHeaderV1.n must be >= 0", { n });

    this.v = v;
    this.sid = sid;
    this.dh = dh ?? null;
    this.dhAlg = dhAlg;
    this.dhFmt = dhFmt;
    this.pn = pn;
    this.n = n;
  }

  toJSON() {
    return {
      v: this.v,
      sid: Array.from(this.sid),
      dh: this.dh ? Array.from(this.dh) : null,
      dhAlg: this.dhAlg,
      dhFmt: this.dhFmt,
      pn: this.pn,
      n: this.n,
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("RatchetHeaderV1.fromJSON(json) requires object");
    }

    return new RatchetHeaderV1({
      v: json.v,
      sid: toBytes(json.sid, "sid"),
      dh: json.dh == null ? null : toBytes(json.dh, "dh"),
      dhAlg: json.dhAlg,
      dhFmt: json.dhFmt,
      pn: json.pn,
      n: json.n,
    });
  }
}
