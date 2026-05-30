export class ReplayDetectedError extends Error {
  constructor() {
    super("ReplayDetected");
    this.name = "ReplayDetectedError";
  }
}

export class OnionReplayCacheV2 {
  constructor({ maxEntries = 50000 } = {}) {
    if (!Number.isInteger(maxEntries) || maxEntries <= 0) {
      throw new Error("OnionReplayCacheV2 requires maxEntries > 0");
    }
    this.maxEntries = maxEntries;
    this.map = new Map();
  }

  checkAndMark(packetIdHex, hopIndex, onionKeyId) {
    if (typeof packetIdHex !== "string" || packetIdHex.length === 0) {
      throw new Error("OnionReplayCacheV2.checkAndMark requires packetIdHex");
    }
    if (!Number.isInteger(hopIndex) || hopIndex < 0) {
      throw new Error("OnionReplayCacheV2.checkAndMark requires hopIndex >= 0");
    }
    if (typeof onionKeyId !== "string" || onionKeyId.length === 0) {
      throw new Error("OnionReplayCacheV2.checkAndMark requires onionKeyId");
    }

    const key = `${packetIdHex}:${hopIndex}:${onionKeyId}`;
    if (this.map.has(key)) {
      throw new ReplayDetectedError();
    }
    this.map.set(key, true);
    if (this.map.size > this.maxEntries) {
      const oldest = this.map.keys().next().value;
      this.map.delete(oldest);
    }
  }
}
