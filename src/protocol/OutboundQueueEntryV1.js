import { RSerializable } from "../base/RSerializable.js";
import { bytesToBase64, base64ToBytes, isBytes } from "../util/bytes.js";

/**
 * Validated record for a queued outbound message awaiting delivery.
 *
 * Stored encrypted at rest in the persistent outbound queue.
 * Carries all state needed to retry delivery: the raw packet bytes,
 * destination inbox, retry timing, and attempt count.
 *
 * Constructor validates all fields — if you can construct it, it's valid.
 */
export class OutboundQueueEntryV1 extends RSerializable {
  static type = "OutboundQueueEntryV1";

  /**
   * @param {object} opts
   * @param {string} opts.queueId — unique ID for this queue entry
   * @param {string} opts.deliverInboxId — target inbox for delivery
   * @param {Uint8Array} opts.innerBytes — encrypted packet bytes to deliver
   * @param {number} opts.createdAtMs — timestamp of initial enqueue
   * @param {number} opts.attempts — number of delivery attempts so far
   * @param {number} opts.lastAttemptMs — timestamp of last attempt (0 if never attempted)
   * @param {number} opts.nextRetryMs — timestamp of next retry (0 for immediate)
   * @param {string} [opts.receiptInboxId] — optional inbox for delivery receipts
   * @param {string} [opts.ownerPublicKeyB64] — pubkey of the WS session that
   *   originated this enqueue. Used to route delivery/expiry notifications
   *   back to the originating client's sessions via
   *   `sessionRegistry.broadcastToOwner`. Nullable for entries persisted
   *   before this field was introduced; missing owner just means the
   *   eventual status transition delivers silently (the retry still works).
   */
  constructor({ queueId, deliverInboxId, innerBytes, createdAtMs, attempts, lastAttemptMs, nextRetryMs, receiptInboxId, ownerPublicKeyB64 } = {}) {
    super();

    this.assert(
      typeof queueId === "string" && queueId.length > 0,
      "OutboundQueueEntryV1 requires non-empty string queueId",
    );
    this.assert(
      typeof deliverInboxId === "string" && deliverInboxId.length > 0,
      "OutboundQueueEntryV1 requires non-empty string deliverInboxId",
    );
    this.assert(
      isBytes(innerBytes) && innerBytes.length > 0,
      "OutboundQueueEntryV1 requires non-empty Uint8Array innerBytes",
    );
    this.assert(
      typeof createdAtMs === "number" && createdAtMs > 0,
      "OutboundQueueEntryV1 requires positive number createdAtMs",
    );
    this.assert(
      typeof attempts === "number" && attempts >= 0,
      "OutboundQueueEntryV1 requires non-negative number attempts",
    );
    this.assert(
      typeof lastAttemptMs === "number" && lastAttemptMs >= 0,
      "OutboundQueueEntryV1 requires non-negative number lastAttemptMs",
    );
    this.assert(
      typeof nextRetryMs === "number" && nextRetryMs >= 0,
      "OutboundQueueEntryV1 requires non-negative number nextRetryMs",
    );

    this.queueId = queueId;
    this.deliverInboxId = deliverInboxId;
    this.innerBytes = innerBytes;
    this.createdAtMs = createdAtMs;
    this.attempts = attempts;
    this.lastAttemptMs = lastAttemptMs;
    this.nextRetryMs = nextRetryMs;
    this.receiptInboxId = typeof receiptInboxId === "string" && receiptInboxId.length > 0 ? receiptInboxId : null;
    this.ownerPublicKeyB64 = typeof ownerPublicKeyB64 === "string" && ownerPublicKeyB64.length > 0 ? ownerPublicKeyB64 : null;
  }

  toJSON() {
    return {
      queueId: this.queueId,
      deliverInboxId: this.deliverInboxId,
      innerBytesB64: bytesToBase64(this.innerBytes),
      createdAtMs: this.createdAtMs,
      attempts: this.attempts,
      lastAttemptMs: this.lastAttemptMs,
      nextRetryMs: this.nextRetryMs,
      receiptInboxId: this.receiptInboxId,
      ownerPublicKeyB64: this.ownerPublicKeyB64,
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("OutboundQueueEntryV1.fromJSON requires object");
    }
    return new OutboundQueueEntryV1({
      queueId: json.queueId,
      deliverInboxId: json.deliverInboxId,
      innerBytes: base64ToBytes(json.innerBytesB64),
      createdAtMs: json.createdAtMs,
      attempts: json.attempts,
      lastAttemptMs: json.lastAttemptMs,
      nextRetryMs: json.nextRetryMs,
      receiptInboxId: json.receiptInboxId,
      ownerPublicKeyB64: json.ownerPublicKeyB64,
    });
  }
}
