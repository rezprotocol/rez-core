const PRUNE_INTERVAL_MS = 60_000;

/**
 * LRU deduplication cache for message/frame deduplication.
 */
export class DeduperLRU {
  #capacity;
  #ttlMs;
  #map = new Map();
  #lastPruneAtMs = 0;

  constructor({ capacity = 50000, ttlMs = 24 * 60 * 60 * 1000 } = {}) {
    this.#capacity = Math.max(100, Number(capacity) || 50000);
    this.#ttlMs = Math.max(1000, Number(ttlMs) || 24 * 60 * 60 * 1000);
  }

  seen(key, nowMs = Date.now()) {
    if (nowMs - this.#lastPruneAtMs >= PRUNE_INTERVAL_MS) {
      this.#prune(nowMs);
      this.#lastPruneAtMs = nowMs;
    }
    if (!validKey(key)) return false;
    const ts = this.#map.get(key);
    if (!Number.isFinite(ts)) return false;
    if (nowMs - ts > this.#ttlMs) {
      this.#map.delete(key);
      return false;
    }
    return true;
  }

  mark(key, nowMs = Date.now()) {
    if (nowMs - this.#lastPruneAtMs >= PRUNE_INTERVAL_MS) {
      this.#prune(nowMs);
      this.#lastPruneAtMs = nowMs;
    }
    if (!validKey(key)) return;
    if (this.#map.has(key)) this.#map.delete(key);
    this.#map.set(key, nowMs);
    while (this.#map.size > this.#capacity) {
      const oldest = this.#map.keys().next();
      if (oldest.done) break;
      this.#map.delete(oldest.value);
    }
  }

  clear() {
    this.#map.clear();
    this.#lastPruneAtMs = 0;
  }

  #prune(nowMs) {
    for (const [key, ts] of this.#map.entries()) {
      if (!Number.isFinite(ts) || nowMs - ts > this.#ttlMs) {
        this.#map.delete(key);
      }
    }
  }
}

function validKey(value) {
  return typeof value === "string" && value.trim().length > 0;
}
