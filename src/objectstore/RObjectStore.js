import { RDataStore } from "../storage/RDataStore.js";

/**
 * DEAD SURFACE — pending deletion (CORE-3).
 *
 * `CAPABILITY_MODEL.md` §9 says the `object:` namespace "is removed wholesale",
 * and it is: nothing authorizes against it. This class is the leftover storage
 * half, and it had exactly one importer in the whole polyrepo — the `rez-core`
 * package barrel, which re-exported it to every consumer. So the surface the
 * canonical spec called removed was, in fact, the package's public API.
 *
 * The barrel export is gone as of 2026-08-17; this file and its tests remain
 * only because removing them needs a separate approval. Do NOT bind
 * authorization, capabilities, or new callers to this class — it is scheduled
 * to go, and the capability model it would imply no longer exists.
 */
export class RObjectStore {
  #store;
  #counter = 0;

  constructor({ store }) {
    if (!(store instanceof RDataStore)) {
      throw new Error("RObjectStore requires store (RDataStore)");
    }
    this.#store = store;
  }

  async publish(resourceId, objectId, ciphertextB64, metadata = {}) {
    _assertNonEmpty(resourceId, "resourceId");
    _assertNonEmpty(objectId, "objectId");
    if (typeof ciphertextB64 !== "string" || ciphertextB64.length === 0) {
      throw new Error("RObjectStore requires non-empty string ciphertextB64");
    }
    const createdAtMs = Date.now();
    const key = `obj/${resourceId}/${objectId}`;
    const value = { objectId, ciphertextB64, metadata, createdAtMs };
    await this.#store.put(key, value);
    return { objectId, createdAtMs };
  }

  async get(resourceId, objectId) {
    _assertNonEmpty(resourceId, "resourceId");
    _assertNonEmpty(objectId, "objectId");
    return this.#store.get(`obj/${resourceId}/${objectId}`);
  }

  async list(resourceId, { cursor, limit = 50 } = {}) {
    _assertNonEmpty(resourceId, "resourceId");
    const prefix = `obj/${resourceId}/`;
    const result = await this.#store.list(prefix, {
      cursor: cursor ? `${prefix}${cursor}` : undefined,
      limit,
    });

    const items = result.items.map((entry) => ({
      objectId: entry.key.slice(prefix.length),
      ciphertextB64: entry.value.ciphertextB64,
      metadata: entry.value.metadata,
      createdAtMs: entry.value.createdAtMs,
    }));

    const nextCursor = result.nextCursor ? result.nextCursor.slice(prefix.length) : null;
    return { items, nextCursor };
  }

  async delete(resourceId, objectId) {
    _assertNonEmpty(resourceId, "resourceId");
    _assertNonEmpty(objectId, "objectId");
    return this.#store.remove(`obj/${resourceId}/${objectId}`);
  }

  async has(resourceId, objectId) {
    _assertNonEmpty(resourceId, "resourceId");
    _assertNonEmpty(objectId, "objectId");
    return this.#store.has(`obj/${resourceId}/${objectId}`);
  }
}

function _assertNonEmpty(value, name) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`RObjectStore requires non-empty string ${name}`);
  }
}
