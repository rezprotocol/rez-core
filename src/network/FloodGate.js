import { WARN_CODES } from "./WarnCodes.js";

class TokenBucket {
  constructor({ rate, burst }) {
    this.rate = Math.max(1, Number(rate) || 1);
    this.burst = Math.max(1, Number(burst) || this.rate);
    this.tokens = this.burst;
    this.lastTs = Date.now();
  }

  allow(nowMs = Date.now()) {
    const elapsedSec = Math.max(0, nowMs - this.lastTs) / 1000;
    this.lastTs = nowMs;
    this.tokens = Math.min(this.burst, this.tokens + elapsedSec * this.rate);
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return true;
    }
    return false;
  }
}

/**
 * Flood gate — token-bucket rate limiter for inbound frames.
 */
export class FloodGate {
  #perConnRate;
  #perConnBurst;
  #global;
  #warnIntervalMs;
  #pool = new Map();
  #dropped = 0;
  #lastWarn = 0;

  constructor({
    perConnRate = 200,
    perConnBurst = 400,
    globalRate = 500,
    globalBurst = 1000,
    warnIntervalMs = 1000,
  } = {}) {
    this.#perConnRate = Math.max(1, Number(perConnRate) || 200);
    this.#perConnBurst = Math.max(1, Number(perConnBurst) || 400);
    this.#global = new TokenBucket({ rate: globalRate, burst: globalBurst });
    this.#warnIntervalMs = Math.max(100, Number(warnIntervalMs) || 1000);
  }

  allow(connKey, nowMs = Date.now()) {
    const bucket = this.#bucket(connKey);
    const ok = bucket.allow(nowMs) && this.#global.allow(nowMs);
    if (!ok) this.#dropped += 1;
    return ok;
  }

  consumeWarn(nowMs = Date.now()) {
    if (this.#dropped <= 0) return null;
    if (nowMs - this.#lastWarn < this.#warnIntervalMs) return null;
    const out = { code: WARN_CODES.INBOUND_FLOOD, droppedCount: this.#dropped };
    this.#dropped = 0;
    this.#lastWarn = nowMs;
    return out;
  }

  clear() {
    this.#pool.clear();
    this.#dropped = 0;
    this.#lastWarn = 0;
  }

  #bucket(connKey) {
    const key = String(connKey || "uplink:unknown");
    let bucket = this.#pool.get(key);
    if (!bucket) {
      bucket = new TokenBucket({ rate: this.#perConnRate, burst: this.#perConnBurst });
      this.#pool.set(key, bucket);
    }
    return bucket;
  }
}
