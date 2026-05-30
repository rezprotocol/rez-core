import { RSerializable } from "../base/RSerializable.js";

/**
 * Validated record for an application-layer mailbox deposit.
 *
 * Wraps app-level payloads (SDK deposits, local messages, file uploads).
 * This is the only type (along with OuterPacketRecord) that RMailbox.deposit() accepts.
 */
export class AppDepositRecord extends RSerializable {
  static type = "AppDepositRecord";

  static CONTENT_TYPE = "rez.app.deposit";

  /**
   * @param {{ objectId: string, payloadBytes: Uint8Array, metadata?: object }} opts
   */
  constructor({ objectId, payloadBytes, metadata } = {}) {
    super();
    this.assert(
      typeof objectId === "string" && objectId.length > 0,
      "AppDepositRecord requires non-empty string objectId",
    );
    this.assert(
      payloadBytes instanceof Uint8Array,
      "AppDepositRecord requires Uint8Array payloadBytes",
    );
    this.objectId = objectId;
    this.payloadBytes = payloadBytes;
    this.metadata = metadata && typeof metadata === "object" ? metadata : {};
  }

  get contentType() {
    return AppDepositRecord.CONTENT_TYPE;
  }

  toBytes() {
    return this.payloadBytes;
  }

  toJSON() {
    return {
      type: AppDepositRecord.type,
      objectId: this.objectId,
      payloadLength: this.payloadBytes.length,
      metadata: this.metadata,
    };
  }
}
