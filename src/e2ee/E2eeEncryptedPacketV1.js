import { RSerializable } from "../base/RSerializable.js";
import { bytesToBase64, base64ToBytes } from "../util/bytes.js";

/**
 * Validated record for an E2EE encrypted packet on the wire.
 *
 * Wire JSON shape: { "e2ee": 1, "v": 1, "payload": "<base64 encrypted envelope>" }
 *
 * Constructor validates all fields — if you can construct it, it's valid.
 */
export class E2eeEncryptedPacketV1 extends RSerializable {
  static type = "E2eeEncryptedPacketV1";

  constructor({ v = 1, payloadBytes } = {}) {
    super();
    this.assert(v === 1, "E2eeEncryptedPacketV1.v must be 1", { v });
    this.assert(
      payloadBytes instanceof Uint8Array && payloadBytes.length > 0,
      "E2eeEncryptedPacketV1.payloadBytes must be non-empty Uint8Array",
      { payloadBytes },
    );
    this.v = 1;
    this.e2ee = 1;
    this.payloadBytes = payloadBytes;
  }

  toJSON() {
    return { e2ee: 1, v: 1, payload: bytesToBase64(this.payloadBytes) };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("E2eeEncryptedPacketV1.fromJSON requires object");
    }
    if (json.e2ee !== 1) {
      throw new Error("E2eeEncryptedPacketV1.fromJSON: e2ee must be 1");
    }
    if (json.v !== 1) {
      throw new Error("E2eeEncryptedPacketV1.fromJSON: v must be 1");
    }
    if (typeof json.payload !== "string" || json.payload.length === 0) {
      throw new Error("E2eeEncryptedPacketV1.fromJSON: payload must be non-empty string");
    }
    return new E2eeEncryptedPacketV1({ v: 1, payloadBytes: base64ToBytes(json.payload) });
  }

  /** Serialize to wire bytes (UTF-8 JSON). */
  toBytes() {
    return new TextEncoder().encode(JSON.stringify(this.toJSON()));
  }

  /** Deserialize from wire bytes (UTF-8 JSON). */
  static fromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
      throw new Error("E2eeEncryptedPacketV1.fromBytes requires non-empty Uint8Array");
    }
    const json = JSON.parse(new TextDecoder().decode(bytes));
    return E2eeEncryptedPacketV1.fromJSON(json);
  }
}
