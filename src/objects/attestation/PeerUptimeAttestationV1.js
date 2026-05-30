import { RSerializable } from "../../base/index.js";
import { isNonEmptyString } from "../../util/strings.js";
import { isFiniteNumber, validateSig, cloneSig, sigToJSON, sigFromJSON } from "../../util/settlement.js";

export class PeerUptimeAttestationV1 extends RSerializable {
  static type = "PeerUptimeAttestationV1";

  constructor({
    v = 1,
    attesterId,
    targetRelayKeyId,
    reachable,
    latencyMs = null,
    createdAtMs,
    sig,
  } = {}) {
    super();

    this.assert(v === 1, "PeerUptimeAttestationV1.v must be 1", { v });
    this.assert(isNonEmptyString(attesterId), "PeerUptimeAttestationV1.attesterId must be non-empty string", { attesterId });
    this.assert(isNonEmptyString(targetRelayKeyId), "PeerUptimeAttestationV1.targetRelayKeyId must be non-empty string", { targetRelayKeyId });
    this.assert(typeof reachable === "boolean", "PeerUptimeAttestationV1.reachable must be boolean", { reachable });
    this.assert(latencyMs === null || (isFiniteNumber(latencyMs) && latencyMs >= 0), "PeerUptimeAttestationV1.latencyMs must be null or non-negative number", { latencyMs });
    this.assert(isFiniteNumber(createdAtMs), "PeerUptimeAttestationV1.createdAtMs must be number", { createdAtMs });
    validateSig(sig, "PeerUptimeAttestationV1");

    this.v = 1;
    this.attesterId = attesterId;
    this.targetRelayKeyId = targetRelayKeyId;
    this.reachable = reachable;
    this.latencyMs = latencyMs;
    this.createdAtMs = createdAtMs;
    this.sig = cloneSig(sig);
  }

  toJSON() {
    return {
      v: this.v,
      attesterId: this.attesterId,
      targetRelayKeyId: this.targetRelayKeyId,
      reachable: this.reachable,
      latencyMs: this.latencyMs,
      createdAtMs: this.createdAtMs,
      sig: sigToJSON(this.sig),
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("PeerUptimeAttestationV1.fromJSON(json) requires object");
    }
    return new PeerUptimeAttestationV1({
      v: json.v,
      attesterId: json.attesterId,
      targetRelayKeyId: json.targetRelayKeyId,
      reachable: json.reachable,
      latencyMs: json.latencyMs,
      createdAtMs: json.createdAtMs,
      sig: sigFromJSON(json.sig, "PeerUptimeAttestationV1"),
    });
  }
}
