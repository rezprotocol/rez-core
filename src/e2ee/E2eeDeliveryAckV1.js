import { RSerializable } from "../base/RSerializable.js";

/**
 * Validated record for a delivery acknowledgement.
 *
 * Sent by the recipient after successfully decrypting and storing messages.
 * Allows the sender to update message status from "sent" → "delivered".
 *
 * Batch acks: multiple messageIds in one packet to reduce chattiness.
 * Fire-and-forget — acks are not themselves acknowledged.
 *
 * Wire JSON shape: { "kind": "rez.delivery.ack", ... }
 */
export class E2eeDeliveryAckV1 extends RSerializable {
  static type = "E2eeDeliveryAckV1";

  /**
   * @param {object} opts
   * @param {string} opts.senderAccountId — the account sending the ack (i.e. the message recipient)
   * @param {string[]} opts.messageIds — IDs of messages being acknowledged
   */
  constructor({ senderAccountId, messageIds } = {}) {
    super();
    this.assert(
      typeof senderAccountId === "string" && senderAccountId.length > 0,
      "E2eeDeliveryAckV1 requires non-empty string senderAccountId",
    );
    this.assert(
      Array.isArray(messageIds) && messageIds.length > 0,
      "E2eeDeliveryAckV1 requires non-empty messageIds array",
    );
    for (let i = 0; i < messageIds.length; i++) {
      this.assert(
        typeof messageIds[i] === "string" && messageIds[i].length > 0,
        "E2eeDeliveryAckV1 messageIds[" + i + "] must be non-empty string",
      );
    }

    this.kind = "rez.delivery.ack";
    this.senderAccountId = senderAccountId;
    this.messageIds = messageIds.slice(); // defensive copy
  }

  toJSON() {
    return {
      kind: this.kind,
      senderAccountId: this.senderAccountId,
      messageIds: this.messageIds.slice(),
    };
  }

  toBytes() {
    return new TextEncoder().encode(JSON.stringify(this.toJSON()));
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("E2eeDeliveryAckV1.fromJSON requires object");
    }
    if (json.kind !== "rez.delivery.ack") {
      throw new Error("E2eeDeliveryAckV1.fromJSON: kind must be rez.delivery.ack");
    }
    return new E2eeDeliveryAckV1({
      senderAccountId: json.senderAccountId,
      messageIds: json.messageIds,
    });
  }

  static fromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
      throw new Error("E2eeDeliveryAckV1.fromBytes requires non-empty Uint8Array");
    }
    const json = JSON.parse(new TextDecoder().decode(bytes));
    return E2eeDeliveryAckV1.fromJSON(json);
  }
}
