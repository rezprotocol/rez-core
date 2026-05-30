import { RSerializable } from "../../base/index.js";

const MAX_ONION_SIZE = 1024 * 1024;
const SIZE_CLASSES = [4096, 8192, 16384, 32768, 65536, 131072, 262144];

function isBytes(value) {
  return value instanceof Uint8Array;
}

function toBytes(value, label) {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return new Uint8Array(value);
  throw new Error(`OnionPacketV2.${label} must be Uint8Array`);
}

export class OnionPacketV2 extends RSerializable {
  static type = "OnionPacketV2";

  constructor({ v, sizeClass, payload } = {}) {
    super();

    this.assert(v === 2, "OnionPacketV2.v must be 2", { v });
    this.assert(SIZE_CLASSES.includes(sizeClass), "OnionPacketV2.sizeClass must be valid", { sizeClass });
    this.assert(sizeClass <= MAX_ONION_SIZE, "OnionPacketV2.sizeClass exceeds max", { sizeClass });
    this.assert(isBytes(payload), "OnionPacketV2.payload must be Uint8Array", { payload });
    this.assert(payload.length === sizeClass, "OnionPacketV2.payload length must equal sizeClass", { sizeClass, payloadLength: payload.length });

    this.v = v;
    this.sizeClass = sizeClass;
    this.payload = payload;
  }

  toJSON() {
    return {
      v: this.v,
      sizeClass: this.sizeClass,
      payload: Array.from(this.payload),
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("OnionPacketV2.fromJSON(json) requires object");
    }

    return new OnionPacketV2({
      v: json.v,
      sizeClass: json.sizeClass,
      payload: toBytes(json.payload, "payload"),
    });
  }
}

export { MAX_ONION_SIZE as MAX_ONION_V2_SIZE, SIZE_CLASSES as ONION_V2_SIZE_CLASSES };
