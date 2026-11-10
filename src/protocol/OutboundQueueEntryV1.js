import { RRecord } from "../base/RRecord.js";
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
export class OutboundQueueEntryV1 extends RRecord {
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
      isBytes(innerBytes) && innerBytes.length > 0,
      "OutboundQueueEntryV1 requires non-empty Uint8Array innerBytes",
    );
    this.queueId = queueId;
    this.deliverInboxId = deliverInboxId;
    this.innerBytesB64 = bytesToBase64(innerBytes);
    this.createdAtMs = createdAtMs;
    this.attempts = attempts;
    this.lastAttemptMs = lastAttemptMs;
    this.nextRetryMs = nextRetryMs;
    this.receiptInboxId = typeof receiptInboxId === "string" && receiptInboxId.length > 0 ? receiptInboxId : null;
    this.ownerPublicKeyB64 = typeof ownerPublicKeyB64 === "string" && ownerPublicKeyB64.length > 0 ? ownerPublicKeyB64 : null;
    this._seal();
  }

  get innerBytes() {
    return base64ToBytes(this.innerBytesB64);
  }

  validate() {
    this.assert(typeof this.queueId === "string" && this.queueId.length > 0, "OutboundQueueEntryV1 requires queueId");
    this.assert(typeof this.deliverInboxId === "string" && this.deliverInboxId.length > 0, "OutboundQueueEntryV1 requires deliverInboxId");
    this.assert(typeof this.innerBytesB64 === "string" && this.innerBytesB64.length > 0, "OutboundQueueEntryV1 requires ciphertext");
    this.assert(Number.isSafeInteger(this.createdAtMs) && this.createdAtMs > 0, "OutboundQueueEntryV1 requires positive integer createdAtMs");
    for (const field of ["attempts", "lastAttemptMs", "nextRetryMs"]) {
      this.assert(Number.isSafeInteger(this[field]) && this[field] >= 0, "OutboundQueueEntryV1 requires non-negative integer " + field);
    }
  }

  toJSON() {
    this._assertSealed();
    return {
      queueId: this.queueId,
      deliverInboxId: this.deliverInboxId,
      innerBytesB64: this.innerBytesB64,
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
