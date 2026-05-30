import { RSerializable } from "../../base/index.js";
import { isNonEmptyString } from "../../util/strings.js";
import { isFinitePositive, isFiniteNumber, validateSig, cloneSig, sigToJSON, sigFromJSON } from "../../util/settlement.js";

export class CreditReceiptV1 extends RSerializable {
  static type = "CreditReceiptV1";

  constructor({
    v = 1,
    receiptId,
    accountId,
    amount,
    reason,
    relayKeyId,
    createdAtMs,
    sig,
  } = {}) {
    super();

    this.assert(v === 1, "CreditReceiptV1.v must be 1", { v });
    this.assert(isNonEmptyString(receiptId), "CreditReceiptV1.receiptId must be non-empty string", { receiptId });
    this.assert(isNonEmptyString(accountId), "CreditReceiptV1.accountId must be non-empty string", { accountId });
    this.assert(isFinitePositive(amount), "CreditReceiptV1.amount must be positive number", { amount });
    this.assert(isNonEmptyString(reason), "CreditReceiptV1.reason must be non-empty string", { reason });
    this.assert(isNonEmptyString(relayKeyId), "CreditReceiptV1.relayKeyId must be non-empty string", { relayKeyId });
    this.assert(isFiniteNumber(createdAtMs), "CreditReceiptV1.createdAtMs must be number", { createdAtMs });
    validateSig(sig, "CreditReceiptV1");

    this.v = 1;
    this.receiptId = receiptId;
    this.accountId = accountId;
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
      accountId: this.accountId,
      amount: this.amount,
      reason: this.reason,
      relayKeyId: this.relayKeyId,
      createdAtMs: this.createdAtMs,
      sig: sigToJSON(this.sig),
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("CreditReceiptV1.fromJSON(json) requires object");
    }
    return new CreditReceiptV1({
      v: json.v,
      receiptId: json.receiptId,
      accountId: json.accountId,
      amount: json.amount,
      reason: json.reason,
      relayKeyId: json.relayKeyId,
      createdAtMs: json.createdAtMs,
      sig: sigFromJSON(json.sig, "CreditReceiptV1"),
    });
  }
}
