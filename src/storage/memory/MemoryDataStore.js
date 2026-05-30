import { RDataStore } from "../RDataStore.js";

export class MemoryDataStore extends RDataStore {
  static type = "MemoryDataStore";

  #data = new Map();

  async put(key, value) {
    this.assert(typeof key === "string" && key.length > 0, "put() requires non-empty string key");
    this.#data.set(key, structuredClone(value));
  }

  async get(key) {
    this.assert(typeof key === "string", "get() requires string key");
    const v = this.#data.get(key);
    return v === undefined ? null : structuredClone(v);
  }

  async list(prefix = "", { cursor, limit, reverse } = {}) {
    let keys = [];
    for (const k of this.#data.keys()) {
      if (k.startsWith(prefix)) keys.push(k);
    }
    keys.sort();
    if (reverse) keys.reverse();

    if (cursor) {
      const idx = keys.indexOf(cursor);
      if (idx >= 0) {
        keys = keys.slice(idx + 1);
      }
    }

    let nextCursor = null;
    if (limit != null && limit > 0 && keys.length > limit) {
      nextCursor = keys[limit - 1];
      keys = keys.slice(0, limit);
    }

    const items = keys.map((k) => ({ key: k, value: structuredClone(this.#data.get(k)) }));
    return { items, nextCursor };
  }

  async remove(key) {
    this.assert(typeof key === "string", "remove() requires string key");
    return this.#data.delete(key);
  }

  async has(key) {
    this.assert(typeof key === "string", "has() requires string key");
    return this.#data.has(key);
  }

  async clear() {
    this.#data.clear();
  }
}
