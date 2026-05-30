export class OnionPathBuilder {
  constructor({ deterministic = true } = {}) {
    this.deterministic = deterministic;
  }

  build({ relays, hopCount = 3 } = {}) {
    if (!Array.isArray(relays) || relays.length === 0) {
      throw new Error("OnionPathBuilder.build requires relays[]");
    }
    if (!Number.isInteger(hopCount) || hopCount <= 0) {
      throw new Error("OnionPathBuilder.build requires hopCount > 0");
    }

    const unique = [];
    const seen = new Set();
    for (const relay of relays) {
      const key = JSON.stringify(relay.endpoint);
      if (seen.has(key)) continue;
      seen.add(key);
      unique.push(relay);
    }

    if (unique.length < hopCount) {
      throw new Error("OnionPathBuilder.build requires enough unique relays");
    }

    return unique.slice(0, hopCount);
  }
}
