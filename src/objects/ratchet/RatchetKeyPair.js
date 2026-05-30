import { RSerializable } from "../../base/index.js";
import { isBytes } from "../../util/bytes.js";

function toBytes(value, label) {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return new Uint8Array(value);
  throw new Error(`RatchetKeyPair.${label} must be Uint8Array`);
}

export class RatchetKeyPair extends RSerializable {
  static type = "RatchetKeyPair";

  constructor({ publicKey, privateKey } = {}) {
    super();

    this.assert(isBytes(publicKey), "RatchetKeyPair.publicKey must be Uint8Array", { publicKey });
    this.assert(isBytes(privateKey), "RatchetKeyPair.privateKey must be Uint8Array", { privateKey });

    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  toJSON() {
    return {
      publicKey: Array.from(this.publicKey),
      privateKey: Array.from(this.privateKey),
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("RatchetKeyPair.fromJSON(json) requires object");
    }

    return new RatchetKeyPair({
      publicKey: toBytes(json.publicKey, "publicKey"),
      privateKey: toBytes(json.privateKey, "privateKey"),
    });
  }
}
