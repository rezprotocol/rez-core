import { RSerializable } from "../../base/index.js";
import { isNonEmptyString } from "../../util/strings.js";
import { isFinitePositive, isFiniteNumber, validateSig, cloneSig, sigToJSON, sigFromJSON } from "../../util/settlement.js";

export class EscrowReceiptV1 extends RSerializable {
  static type = "EscrowReceiptV1";

  constructor({
    v = 1,
    escrowId,
    accountId,
    amount,
    commitment,
    expiresAtMs,
    relayKeyId,
    createdAtMs,
    sig,
  } = {}) {
    super();

    this.assert(v === 1, "EscrowReceiptV1.v must be 1", { v });
    this.assert(isNonEmptyString(escrowId), "EscrowReceiptV1.escrowId must be non-empty string", { escrowId });
    this.assert(isNonEmptyString(accountId), "EscrowReceiptV1.accountId must be non-empty string", { accountId });
    this.assert(isFinitePositive(amount), "EscrowReceiptV1.amount must be positive number", { amount });
    this.assert(isNonEmptyString(commitment), "EscrowReceiptV1.commitment must be non-empty string", { commitment });
    this.assert(isFiniteNumber(expiresAtMs), "EscrowReceiptV1.expiresAtMs must be number", { expiresAtMs });
    this.assert(expiresAtMs > createdAtMs, "EscrowReceiptV1.expiresAtMs must be after createdAtMs", { expiresAtMs, createdAtMs });
    this.assert(isNonEmptyString(relayKeyId), "EscrowReceiptV1.relayKeyId must be non-empty string", { relayKeyId });
    this.assert(isFiniteNumber(createdAtMs), "EscrowReceiptV1.createdAtMs must be number", { createdAtMs });
    validateSig(sig, "EscrowReceiptV1");

    this.v = 1;
    this.escrowId = escrowId;
    this.accountId = accountId;
    this.amount = amount;
    this.commitment = commitment;
    this.expiresAtMs = expiresAtMs;
    this.relayKeyId = relayKeyId;
    this.createdAtMs = createdAtMs;
    this.sig = cloneSig(sig);
  }

  toJSON() {
    return {
      v: this.v,
      escrowId: this.escrowId,
      accountId: this.accountId,
      amount: this.amount,
      commitment: this.commitment,
      expiresAtMs: this.expiresAtMs,
      relayKeyId: this.relayKeyId,
      createdAtMs: this.createdAtMs,
      sig: sigToJSON(this.sig),
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("EscrowReceiptV1.fromJSON(json) requires object");
    }
    return new EscrowReceiptV1({
      v: json.v,
      escrowId: json.escrowId,
      accountId: json.accountId,
      amount: json.amount,
      commitment: json.commitment,
      expiresAtMs: json.expiresAtMs,
      relayKeyId: json.relayKeyId,
      createdAtMs: json.createdAtMs,
      sig: sigFromJSON(json.sig, "EscrowReceiptV1"),
    });
  }
}
