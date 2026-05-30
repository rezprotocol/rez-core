import { assertKeystoreEnvelope } from "./KeystoreEnvelope.js";

const DEFAULT_KEY = "default";

/**
 * Persistence for a single keystore envelope.
 * Storage adapter must provide get(key), put(key, value), del(key).
 * Value is a plain object (keystore envelope shape).
 */
export class KeystoreStore {
  constructor({ storageProvider, storage = null, key = DEFAULT_KEY } = {}) {
    const provider = storageProvider || storage;
    if (!provider || typeof provider.get !== "function" || typeof provider.put !== "function" || typeof provider.del !== "function") {
      throw new Error("KeystoreStore requires storageProvider with get(key), put(key, value), del(key)");
    }
    this._storage = provider;
    this._key = String(key || DEFAULT_KEY);
  }

  async hasKeystore() {
    const value = await Promise.resolve(this._storage.get(this._key));
    if (!value) return false;
    try {
      assertKeystoreEnvelope(value);
      return true;
    } catch {
      return false;
    }
  }

  async getKeystoreEnvelope() {
    const value = await Promise.resolve(this._storage.get(this._key));
    if (!value) return null;
    return assertKeystoreEnvelope(value);
  }

  async putKeystoreEnvelope(envelope) {
    const normalized = assertKeystoreEnvelope(envelope);
    await Promise.resolve(this._storage.put(this._key, normalized));
    return normalized;
  }

  async clearKeystore() {
    await Promise.resolve(this._storage.del(this._key));
  }
}
