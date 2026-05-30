import { Envelope } from "../../objects/Envelope.js";
import { ObjectStore } from "../ObjectStore.js";

export class MemoryObjectStore extends ObjectStore {
  constructor() {
    super();
    this.store = new Map();
  }

  put(envelope) {
    super.put(envelope);
    this.store.set(envelope.header.id, envelope.toJSON());
  }

  get(id) {
    const json = this.store.get(id);
    if (!json) return null;
    return Envelope.fromJSON(json);
  }

  has(id) {
    return this.store.has(id);
  }

  delete(id) {
    return this.store.delete(id);
  }

  listIds() {
    return Array.from(this.store.keys());
  }
}
