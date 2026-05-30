import { RSerializable } from "../../base/index.js";
import { isNonEmptyString } from "../../util/strings.js";
import { isFinitePositive, isFiniteNumber, validateSig, cloneSig, sigToJSON, sigFromJSON } from "../../util/settlement.js";

export class ReleaseReceiptV1 extends RSerializable {
  static type = "ReleaseReceiptV1";

  constructor({
    v = 1,
    receiptId,
    escrowId,
    recipientId,
    amount,
    relayKeyId,
    createdAtMs,
    sig,
  } = {}) {
    super();

    this.assert(v === 1, "ReleaseReceiptV1.v must be 1", { v });
    this.assert(isNonEmptyString(receiptId), "ReleaseReceiptV1.receiptId must be non-empty string", { receiptId });
    this.assert(isNonEmptyString(escrowId), "ReleaseReceiptV1.escrowId must be non-empty string", { escrowId });
    this.assert(isNonEmptyString(recipientId), "ReleaseReceiptV1.recipientId must be non-empty string", { recipientId });
    this.assert(isFinitePositive(amount), "ReleaseReceiptV1.amount must be positive number", { amount });
    this.assert(isNonEmptyString(relayKeyId), "ReleaseReceiptV1.relayKeyId must be non-empty string", { relayKeyId });
    this.assert(isFiniteNumber(createdAtMs), "ReleaseReceiptV1.createdAtMs must be number", { createdAtMs });
    validateSig(sig, "ReleaseReceiptV1");

    this.v = 1;
    this.receiptId = receiptId;
    this.escrowId = escrowId;
    this.recipientId = recipientId;
    this.amount = amount;
    this.relayKeyId = relayKeyId;
    this.createdAtMs = createdAtMs;
    this.sig = cloneSig(sig);
  }

  toJSON() {
    return {
      v: this.v,
      receiptId: this.receiptId,
      escrowId: this.escrowId,
      recipientId: this.recipientId,
      amount: this.amount,
      relayKeyId: this.relayKeyId,
      createdAtMs: this.createdAtMs,
      sig: sigToJSON(this.sig),
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("ReleaseReceiptV1.fromJSON(json) requires object");
    }
    return new ReleaseReceiptV1({
      v: json.v,
      receiptId: json.receiptId,
      escrowId: json.escrowId,
      recipientId: json.recipientId,
      amount: json.amount,
      relayKeyId: json.relayKeyId,
      createdAtMs: json.createdAtMs,
      sig: sigFromJSON(json.sig, "ReleaseReceiptV1"),
    });
  }
}
