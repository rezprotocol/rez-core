import { KeyValueStore } from "../KeyValueStore.js";

export class MemoryKeyValueStore extends KeyValueStore {
  constructor() {
    super();
    this.store = new Map();
  }

  set(key, value) {
    this.store.set(key, value);
  }

  get(key) {
    return this.store.get(key);
  }

  delete(key) {
    return this.store.delete(key);
  }

  keys(prefix = "") {
    const out = [];
    for (const key of this.store.keys()) {
      if (key.startsWith(prefix)) out.push(key);
    }
    return out;
  }
}
