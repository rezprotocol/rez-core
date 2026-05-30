import { RSerializable } from "../../base/index.js";
import { isNonEmptyString } from "../../util/strings.js";
import { isFinitePositive, isFiniteNumber, validateSig, cloneSig, sigToJSON, sigFromJSON } from "../../util/settlement.js";

export class SlashReceiptV1 extends RSerializable {
  static type = "SlashReceiptV1";

  constructor({
    v = 1,
    receiptId,
    escrowId,
    amount,
    reason,
    relayKeyId,
    createdAtMs,
    sig,
  } = {}) {
    super();

    this.assert(v === 1, "SlashReceiptV1.v must be 1", { v });
    this.assert(isNonEmptyString(receiptId), "SlashReceiptV1.receiptId must be non-empty string", { receiptId });
    this.assert(isNonEmptyString(escrowId), "SlashReceiptV1.escrowId must be non-empty string", { escrowId });
    this.assert(isFinitePositive(amount), "SlashReceiptV1.amount must be positive number", { amount });
    this.assert(isNonEmptyString(reason), "SlashReceiptV1.reason must be non-empty string", { reason });
    this.assert(isNonEmptyString(relayKeyId), "SlashReceiptV1.relayKeyId must be non-empty string", { relayKeyId });
    this.assert(isFiniteNumber(createdAtMs), "SlashReceiptV1.createdAtMs must be number", { createdAtMs });
    validateSig(sig, "SlashReceiptV1");

    this.v = 1;
    this.receiptId = receiptId;
    this.escrowId = escrowId;
    this.amount = amount;
    this.reason = reason;
    this.relayKeyId = relayKeyId;
    this.createdAtMs = createdAtMs;
    this.sig = cloneSig(sig);
  }

  toJSON() {
    return {
      v: this.v,
      receiptId: this.receiptId,
      escrowId: this.escrowId,
      amount: this.amount,
      reason: this.reason,
      relayKeyId: this.relayKeyId,
      createdAtMs: this.createdAtMs,
      sig: sigToJSON(this.sig),
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("SlashReceiptV1.fromJSON(json) requires object");
    }
    return new SlashReceiptV1({
      v: json.v,
      receiptId: json.receiptId,
      escrowId: json.escrowId,
      amount: json.amount,
      reason: json.reason,
      relayKeyId: json.relayKeyId,
      createdAtMs: json.createdAtMs,
      sig: sigFromJSON(json.sig, "SlashReceiptV1"),
    });
  }
}
