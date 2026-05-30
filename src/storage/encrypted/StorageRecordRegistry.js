import { RSerializable } from "../../base/index.js";

/**
 * Allowlist of record types that can be deserialized from encrypted storage.
 *
 * When an EncryptedStoreEnvelopeV1 is opened, the inner contentType is
 * looked up in this registry. If the type is not registered, deserialization
 * is rejected — preventing injection of unexpected record types.
 *
 * Each registered class must:
 *   - extend RSerializable
 *   - have a static `type` string
 *   - have a static `fromJSON(json)` method
 */
export class StorageRecordRegistry {
  #types = new Map();

  /**
   * Register a record class for storage deserialization.
   * @param {typeof RSerializable} recordClass
   */
  register(recordClass) {
    if (!recordClass || typeof recordClass !== "function") {
      throw new Error("StorageRecordRegistry.register requires a class");
    }
    const typeName = recordClass.type;
    if (typeof typeName !== "string" || typeName.length === 0) {
      throw new Error("StorageRecordRegistry.register requires class with static type string");
    }
    if (typeof recordClass.fromJSON !== "function") {
      throw new Error("StorageRecordRegistry.register requires class with static fromJSON()");
    }
    if (this.#types.has(typeName)) {
      throw new Error("StorageRecordRegistry: duplicate type \"" + typeName + "\"");
    }
    this.#types.set(typeName, recordClass);
  }

  /**
   * Look up a registered record class by type name.
   * @param {string} contentType
   * @returns {typeof RSerializable}
   * @throws if not registered
   */
  get(contentType) {
    const cls = this.#types.get(contentType);
    if (!cls) {
      throw new Error("StorageRecordRegistry: unknown type \"" + contentType + "\" — not registered for deserialization");
    }
    return cls;
  }

  /**
   * Check if a type is registered.
   * @param {string} contentType
   * @returns {boolean}
   */
  isRegistered(contentType) {
    return this.#types.has(contentType);
  }

  /**
   * Rehydrate a plain JSON object into a validated record instance.
   * @param {string} contentType
   * @param {object} json
   * @returns {RSerializable}
   */
  rehydrate(contentType, json) {
    const cls = this.get(contentType);
    return cls.fromJSON(json);
  }
}
