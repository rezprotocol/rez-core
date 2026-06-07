import { OnionKeyRecordV1 } from "../../objects/relay/OnionKeyRecordV1.js";
import { isFiniteNumber } from "../../util/settlement.js";

export class NoUsableOnionKeyError extends Error {
  constructor(message = "No usable onion key") {
    super(message);
    this.name = "NoUsableOnionKeyError";
  }
}

function isUsable(record, nowMs) {
  if (!(record instanceof OnionKeyRecordV1)) return false;
  if (record.status === "revoked") return false;
  if (!isFiniteNumber(nowMs)) return false;
  return record.notBefore <= nowMs && nowMs < record.notAfter;
}

/**
 * Returns true if descriptor has at least one onion key valid at nowMs (time window + active or draining).
 * Works with OnionKeyRecordV1 instances or plain objects (duck typing for notBefore, notAfter, status).
 */
export function descriptorHasUsableOnionKey(descriptor, nowMs) {
  if (!descriptor || !Array.isArray(descriptor.onionKeys) || descriptor.onionKeys.length === 0) {
    return false;
  }
  if (!isFiniteNumber(nowMs)) return false;
  const keys = descriptor.onionKeys;
  let hasUsable = false;
  let hasActiveOrDraining = false;
  for (const key of keys) {
    const notBefore = Number(key ? key.notBefore : undefined);
    const notAfter = Number(key ? key.notAfter : undefined);
    const status = key ? key.status : undefined;
    if (!Number.isFinite(notBefore) || !Number.isFinite(notAfter)) continue;
    if (status === "revoked") continue;
    if (notBefore <= nowMs && nowMs < notAfter) {
      hasUsable = true;
      if (status === "active" || status === "draining") {
        hasActiveOrDraining = true;
        break;
      }
    }
  }
  return hasUsable && hasActiveOrDraining;
}

export function selectOnionKeyForSendV1(onionKeys, nowMs) {
  if (!Array.isArray(onionKeys) || onionKeys.length === 0) {
    throw new NoUsableOnionKeyError("No onion keys provided");
  }
  if (!isFiniteNumber(nowMs)) {
    throw new NoUsableOnionKeyError("nowMs must be provided");
  }

  const usable = onionKeys.filter((key) => isUsable(key, nowMs));
  if (usable.length === 0) {
    throw new NoUsableOnionKeyError("No usable onion keys at this time");
  }

  const active = usable.filter((key) => key.status === "active");
  const candidates = active.length > 0 ? active : usable.filter((key) => key.status === "draining");
  if (candidates.length === 0) {
    throw new NoUsableOnionKeyError("No usable onion keys in active or draining state");
  }

  candidates.sort((a, b) => b.createdAt - a.createdAt);
  const selected = candidates[0];
  return {
    onionKeyId: selected.onionKeyId,
    publicKeyBytes: selected.publicKeyBytes,
    format: selected.format,
  };
}
