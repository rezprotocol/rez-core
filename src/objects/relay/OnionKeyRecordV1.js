import { RSerializable } from "../../base/index.js";
import { isNonEmptyString } from "../../util/strings.js";
import { isFiniteNumber } from "../../util/settlement.js";
import { isBytes } from "../../util/bytes.js";

const STATUS = new Set(["active", "draining", "revoked"]);
const FORMAT = new Set(["raw", "spki"]);

function toBytes(value, label) {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return new Uint8Array(value);
  throw new Error(`OnionKeyRecordV1.${label} must be Uint8Array`);
}

export class OnionKeyRecordV1 extends RSerializable {
  static type = "OnionKeyRecordV1";

  constructor({
    v = 1,
    onionKeyId,
    publicKeyBytes,
    format = "raw",
    createdAt,
    notBefore,
    notAfter,
    status,
  } = {}) {
    super();

    this.assert(v === 1, "OnionKeyRecordV1.v must be 1", { v });
    this.assert(isNonEmptyString(onionKeyId), "OnionKeyRecordV1.onionKeyId must be non-empty string", { onionKeyId });
    this.assert(isBytes(publicKeyBytes), "OnionKeyRecordV1.publicKeyBytes must be Uint8Array", { publicKeyBytes });
    this.assert(FORMAT.has(format), "OnionKeyRecordV1.format must be raw|spki", { format });
    this.assert(isFiniteNumber(createdAt), "OnionKeyRecordV1.createdAt must be number", { createdAt });
    this.assert(isFiniteNumber(notBefore), "OnionKeyRecordV1.notBefore must be number", { notBefore });
    this.assert(isFiniteNumber(notAfter), "OnionKeyRecordV1.notAfter must be number", { notAfter });
    this.assert(notBefore <= notAfter, "OnionKeyRecordV1.notBefore must be <= notAfter", { notBefore, notAfter });
    this.assert(STATUS.has(status), "OnionKeyRecordV1.status must be active|draining|revoked", { status });

    this.v = 1;
    this.onionKeyId = onionKeyId;
    this.publicKeyBytes = publicKeyBytes;
    this.format = format;
    this.createdAt = createdAt;
    this.notBefore = notBefore;
    this.notAfter = notAfter;
    this.status = status;
  }

  toJSON() {
    return {
      v: 1,
      onionKeyId: this.onionKeyId,
      publicKeyBytes: Array.from(this.publicKeyBytes),
      format: this.format,
      createdAt: this.createdAt,
      notBefore: this.notBefore,
      notAfter: this.notAfter,
      status: this.status,
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("OnionKeyRecordV1.fromJSON(json) requires object");
    }

    return new OnionKeyRecordV1({
      v: json.v ?? 1,
      onionKeyId: json.onionKeyId,
      publicKeyBytes: toBytes(json.publicKeyBytes, "publicKeyBytes"),
      format: json.format ?? "raw",
      createdAt: json.createdAt,
      notBefore: json.notBefore,
      notAfter: json.notAfter,
      status: json.status,
    });
  }
}
