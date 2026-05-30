import { RSerializable } from "../../base/index.js";
import { isBytes } from "../../util/bytes.js";

function toBytes(value, label) {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return new Uint8Array(value);
  throw new Error(`SkippedKeyStore.${label} must be Uint8Array`);
}

function computeTotalBytes(entries) {
  let total = 0;
  for (const entry of entries) {
    total += entry.mk.length;
  }
  return total;
}

export class SkippedKeyStore extends RSerializable {
  static type = "SkippedKeyStore";

  constructor({ entries = [] } = {}) {
    super();

    if (!Array.isArray(entries)) {
      throw new Error("SkippedKeyStore.entries must be an array");
    }

    for (const entry of entries) {
      if (!entry || typeof entry !== "object") {
        throw new Error("SkippedKeyStore.entries must contain objects");
      }
      if (typeof entry.k !== "string" || entry.k.length === 0) {
        throw new Error("SkippedKeyStore.entries.k must be a non-empty string");
      }
      if (!isBytes(entry.mk)) {
        throw new Error("SkippedKeyStore.entries.mk must be Uint8Array");
      }
    }

    this.entries = entries.slice();
    this.totalBytes = computeTotalBytes(this.entries);
  }

  get(key) {
    const found = this.entries.find((entry) => entry.k === key);
    return found ? found.mk : null;
  }

  set(key, mk) {
    if (typeof key !== "string" || key.length === 0) {
      throw new Error("SkippedKeyStore.set requires non-empty key");
    }
    if (!isBytes(mk)) {
      throw new Error("SkippedKeyStore.set requires mk Uint8Array");
    }

    const idx = this.entries.findIndex((entry) => entry.k === key);
    if (idx >= 0) {
      const prev = this.entries[idx].mk;
      this.entries[idx] = { k: key, mk };
      this.totalBytes += mk.length - prev.length;
      return;
    }

    this.entries.push({ k: key, mk });
    this.totalBytes += mk.length;
  }

  delete(key) {
    const idx = this.entries.findIndex((entry) => entry.k === key);
    if (idx < 0) return false;
    const [removed] = this.entries.splice(idx, 1);
    this.totalBytes -= removed.mk.length;
    return true;
  }

  size() {
    return this.entries.length;
  }

  toJSON() {
    return {
      entries: this.entries.map((entry) => ({ k: entry.k, mk: Array.from(entry.mk) })),
      totalBytes: this.totalBytes,
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("SkippedKeyStore.fromJSON(json) requires object");
    }
    const entries = Array.isArray(json.entries) ? json.entries : [];
    return new SkippedKeyStore({
      entries: entries.map((entry) => ({ k: entry.k, mk: toBytes(entry.mk, "entries.mk") })),
    });
  }
}
