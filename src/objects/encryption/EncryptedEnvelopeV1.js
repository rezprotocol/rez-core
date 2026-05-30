import { RSerializable } from "../../base/index.js";
import { RatchetHeaderV1 } from "./RatchetHeaderV1.js";
import { isBytes } from "../../util/bytes.js";

function toBytes(value, label) {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return new Uint8Array(value);
  throw new Error(`EncryptedEnvelopeV1.${label} must be Uint8Array`);
}

const SUITE_V1 = "HKDF-SHA256/AES-256-GCM";

export class EncryptedEnvelopeV1 extends RSerializable {
  static type = "EncryptedEnvelopeV1";

  constructor({ v, suite, header, nonce, ct } = {}) {
    super();

    this.assert(v === 1, "EncryptedEnvelopeV1.v must be 1", { v });
    this.assert(suite === SUITE_V1, "EncryptedEnvelopeV1.suite must be HKDF-SHA256/AES-256-GCM", { suite });
    this.assert(header instanceof RatchetHeaderV1, "EncryptedEnvelopeV1.header must be RatchetHeaderV1", { header });
    this.assert(isBytes(nonce) && nonce.length === 12, "EncryptedEnvelopeV1.nonce must be 12 bytes", { nonce });
    this.assert(isBytes(ct) && ct.length > 0, "EncryptedEnvelopeV1.ct must be non-empty bytes", { ct });

    this.v = v;
    this.suite = suite;
    this.header = header;
    this.nonce = nonce;
    this.ct = ct;
  }

  toJSON() {
    return {
      v: this.v,
      suite: this.suite,
      header: this.header.toJSON(),
      nonce: Array.from(this.nonce),
      ct: Array.from(this.ct),
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("EncryptedEnvelopeV1.fromJSON(json) requires object");
    }

    return new EncryptedEnvelopeV1({
      v: json.v,
      suite: json.suite,
      header: RatchetHeaderV1.fromJSON(json.header),
      nonce: toBytes(json.nonce, "nonce"),
      ct: toBytes(json.ct, "ct"),
    });
  }
}

export { SUITE_V1 };
