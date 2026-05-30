import { RSerializable } from "../base/RSerializable.js";
import { decodeOuterPacket } from "./OuterPacket.js";

/**
 * Validated record for an outer network packet.
 *
 * The packet header intentionally carries no app correlation data. Network
 * delivery is inbox-to-inbox; app state belongs inside the encrypted body.
 */
export class OuterPacketRecord extends RSerializable {
  static type = "OuterPacketRecord";

  static CONTENT_TYPE = "rez.outer";

  #wireBytes;

  constructor({ wireBytes } = {}) {
    super();
    this.assert(
      wireBytes instanceof Uint8Array && wireBytes.length > 0,
      "OuterPacketRecord requires non-empty Uint8Array wireBytes",
    );
    const decoded = decodeOuterPacket(wireBytes);
    this.bodyBytesView = decoded.bodyBytesView;
    this.version = decoded.version;
    this.#wireBytes = wireBytes;
  }

  get contentType() {
    return OuterPacketRecord.CONTENT_TYPE;
  }

  toBytes() {
    return this.#wireBytes;
  }

  toJSON() {
    return {
      type: OuterPacketRecord.type,
      version: this.version,
      bodyLength: this.bodyBytesView.length,
    };
  }

  static probe(wireBytes) {
    return wireBytes instanceof Uint8Array
      && wireBytes.length >= 1
      && wireBytes[0] === 0x02;
  }

  static fromBytes(wireBytes) {
    return new OuterPacketRecord({ wireBytes });
  }
}
