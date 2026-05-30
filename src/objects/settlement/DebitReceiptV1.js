import { RSerializable } from "../../base/index.js";
import { isNonEmptyString } from "../../util/strings.js";
import { isFinitePositive, isFiniteNumber, validateSig, cloneSig, sigToJSON, sigFromJSON } from "../../util/settlement.js";

export class DebitReceiptV1 extends RSerializable {
  static type = "DebitReceiptV1";

  constructor({
    v = 1,
    receiptId,
    accountId,
    amount,
    serviceId,
    serviceRef,
    relayKeyId,
    createdAtMs,
    sig,
  } = {}) {
    super();

    this.assert(v === 1, "DebitReceiptV1.v must be 1", { v });
    this.assert(isNonEmptyString(receiptId), "DebitReceiptV1.receiptId must be non-empty string", { receiptId });
    this.assert(isNonEmptyString(accountId), "DebitReceiptV1.accountId must be non-empty string", { accountId });
    this.assert(isFinitePositive(amount), "DebitReceiptV1.amount must be positive number", { amount });
    this.assert(isNonEmptyString(serviceId), "DebitReceiptV1.serviceId must be non-empty string", { serviceId });
    this.assert(isNonEmptyString(serviceRef), "DebitReceiptV1.serviceRef must be non-empty string", { serviceRef });
    this.assert(isNonEmptyString(relayKeyId), "DebitReceiptV1.relayKeyId must be non-empty string", { relayKeyId });
    this.assert(isFiniteNumber(createdAtMs), "DebitReceiptV1.createdAtMs must be number", { createdAtMs });
    validateSig(sig, "DebitReceiptV1");

    this.v = 1;
    this.receiptId = receiptId;
    this.accountId = accountId;
    this.amount = amount;
    this.serviceId = serviceId;
    this.serviceRef = serviceRef;
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
      serviceId: this.serviceId,
      serviceRef: this.serviceRef,
      relayKeyId: this.relayKeyId,
      createdAtMs: this.createdAtMs,
      sig: sigToJSON(this.sig),
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("DebitReceiptV1.fromJSON(json) requires object");
    }
    return new DebitReceiptV1({
      v: json.v,
      receiptId: json.receiptId,
      accountId: json.accountId,
      amount: json.amount,
      serviceId: json.serviceId,
      serviceRef: json.serviceRef,
      relayKeyId: json.relayKeyId,
      createdAtMs: json.createdAtMs,
      sig: sigFromJSON(json.sig, "DebitReceiptV1"),
    });
  }
}
