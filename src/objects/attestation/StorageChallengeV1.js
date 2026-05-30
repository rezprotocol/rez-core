import { RSerializable } from "../../base/index.js";
import { isNonEmptyString } from "../../util/strings.js";
import { isFiniteNumber, isFinitePositive, validateSig, cloneSig, sigToJSON, sigFromJSON } from "../../util/settlement.js";

export class StorageChallengeV1 extends RSerializable {
  static type = "StorageChallengeV1";

  constructor({
    v = 1,
    challengeId,
    challengerRelayKeyId,
    targetRelayKeyId,
    objectId,
    byteOffset,
    byteLength,
    createdAtMs,
    expiresAtMs,
    sig,
  } = {}) {
    super();

    this.assert(v === 1, "StorageChallengeV1.v must be 1", { v });
    this.assert(isNonEmptyString(challengeId), "StorageChallengeV1.challengeId must be non-empty string", { challengeId });
    this.assert(isNonEmptyString(challengerRelayKeyId), "StorageChallengeV1.challengerRelayKeyId must be non-empty string", { challengerRelayKeyId });
    this.assert(isNonEmptyString(targetRelayKeyId), "StorageChallengeV1.targetRelayKeyId must be non-empty string", { targetRelayKeyId });
    this.assert(isNonEmptyString(objectId), "StorageChallengeV1.objectId must be non-empty string", { objectId });
    this.assert(isFiniteNumber(byteOffset) && byteOffset >= 0, "StorageChallengeV1.byteOffset must be non-negative number", { byteOffset });
    this.assert(isFinitePositive(byteLength), "StorageChallengeV1.byteLength must be positive number", { byteLength });
    this.assert(isFiniteNumber(createdAtMs), "StorageChallengeV1.createdAtMs must be number", { createdAtMs });
    this.assert(isFiniteNumber(expiresAtMs), "StorageChallengeV1.expiresAtMs must be number", { expiresAtMs });
    this.assert(expiresAtMs > createdAtMs, "StorageChallengeV1.expiresAtMs must be after createdAtMs", { expiresAtMs, createdAtMs });
    validateSig(sig, "StorageChallengeV1");

    this.v = 1;
    this.challengeId = challengeId;
    this.challengerRelayKeyId = challengerRelayKeyId;
    this.targetRelayKeyId = targetRelayKeyId;
    this.objectId = objectId;
    this.byteOffset = byteOffset;
    this.byteLength = byteLength;
    this.createdAtMs = createdAtMs;
    this.expiresAtMs = expiresAtMs;
    this.sig = cloneSig(sig);
  }

  toJSON() {
    return {
      v: this.v,
      challengeId: this.challengeId,
      challengerRelayKeyId: this.challengerRelayKeyId,
      targetRelayKeyId: this.targetRelayKeyId,
      objectId: this.objectId,
      byteOffset: this.byteOffset,
      byteLength: this.byteLength,
      createdAtMs: this.createdAtMs,
      expiresAtMs: this.expiresAtMs,
      sig: sigToJSON(this.sig),
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("StorageChallengeV1.fromJSON(json) requires object");
    }
    return new StorageChallengeV1({
      v: json.v,
      challengeId: json.challengeId,
      challengerRelayKeyId: json.challengerRelayKeyId,
      targetRelayKeyId: json.targetRelayKeyId,
      objectId: json.objectId,
      byteOffset: json.byteOffset,
      byteLength: json.byteLength,
      createdAtMs: json.createdAtMs,
      expiresAtMs: json.expiresAtMs,
      sig: sigFromJSON(json.sig, "StorageChallengeV1"),
    });
  }
}
