import { RSerializable } from "../../base/index.js";
import { isNonEmptyString } from "../../util/strings.js";
import { isFiniteNumber, validateSig, cloneSig, sigToJSON, sigFromJSON, toSigBytes } from "../../util/settlement.js";

const HASH_ALGS = new Set(["sha256"]);

export class StorageChallengeResponseV1 extends RSerializable {
  static type = "StorageChallengeResponseV1";

  constructor({
    v = 1,
    challengeId,
    targetRelayKeyId,
    hashAlg = "sha256",
    hashBytes,
    createdAtMs,
    sig,
  } = {}) {
    super();

    this.assert(v === 1, "StorageChallengeResponseV1.v must be 1", { v });
    this.assert(isNonEmptyString(challengeId), "StorageChallengeResponseV1.challengeId must be non-empty string", { challengeId });
    this.assert(isNonEmptyString(targetRelayKeyId), "StorageChallengeResponseV1.targetRelayKeyId must be non-empty string", { targetRelayKeyId });
    this.assert(HASH_ALGS.has(hashAlg), "StorageChallengeResponseV1.hashAlg must be sha256", { hashAlg });
    this.assert(hashBytes instanceof Uint8Array && hashBytes.length === 32, "StorageChallengeResponseV1.hashBytes must be 32-byte Uint8Array", { hashBytes });
    this.assert(isFiniteNumber(createdAtMs), "StorageChallengeResponseV1.createdAtMs must be number", { createdAtMs });
    validateSig(sig, "StorageChallengeResponseV1");

    this.v = 1;
    this.challengeId = challengeId;
    this.targetRelayKeyId = targetRelayKeyId;
    this.hashAlg = hashAlg;
    this.hashBytes = hashBytes;
    this.createdAtMs = createdAtMs;
    this.sig = cloneSig(sig);
  }

  toJSON() {
    return {
      v: this.v,
      challengeId: this.challengeId,
      targetRelayKeyId: this.targetRelayKeyId,
      hashAlg: this.hashAlg,
      hashBytes: Array.from(this.hashBytes),
      createdAtMs: this.createdAtMs,
      sig: sigToJSON(this.sig),
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("StorageChallengeResponseV1.fromJSON(json) requires object");
    }
    return new StorageChallengeResponseV1({
      v: json.v,
      challengeId: json.challengeId,
      targetRelayKeyId: json.targetRelayKeyId,
      hashAlg: json.hashAlg,
      hashBytes: toSigBytes(json.hashBytes, "StorageChallengeResponseV1.hashBytes"),
      createdAtMs: json.createdAtMs,
      sig: sigFromJSON(json.sig, "StorageChallengeResponseV1"),
    });
  }
}
