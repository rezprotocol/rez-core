/**
 * Central registry of record types that can be deposited into a mailbox.
 *
 * Two kinds of registration:
 *
 * 1. Wire record types (network ingress) — registered with register().
 *    Must implement:
 *      - static CONTENT_TYPE: string
 *      - static probe(wireBytes: Uint8Array): boolean — fast check
 *      - static fromBytes(wireBytes: Uint8Array): record — hydrate + validate
 *      - instance contentType (getter): string
 *      - instance toBytes(): Uint8Array
 *
 * 2. App record types (SDK/app layer) — registered with registerAppType().
 *    Must implement:
 *      - static CONTENT_TYPE: string
 *      - instance contentType (getter): string
 *      - instance toBytes(): Uint8Array
 *    These are constructed in code, never hydrated from wire bytes.
 *
 * hydrateFromWire() only probes wire types.
 * isAllowedContentType() checks both wire and app types.
 */
export class MailboxRecordRegistry {
  #wireTypes = new Map();
  #probeOrder = [];
  #allContentTypes = new Set();

  /**
   * Register a wire record type (can be hydrated from network bytes).
   * @param {Function} recordClass
   */
  register(recordClass) {
    if (!recordClass || typeof recordClass !== "function") {
      throw new Error("MailboxRecordRegistry.register requires a class");
    }
    const ct = recordClass.CONTENT_TYPE;
    if (typeof ct !== "string" || ct.length === 0) {
      throw new Error("MailboxRecordRegistry.register: class must have static CONTENT_TYPE string");
    }
    if (typeof recordClass.probe !== "function") {
      throw new Error("MailboxRecordRegistry.register: class must have static probe(wireBytes) method");
    }
    if (typeof recordClass.fromBytes !== "function") {
      throw new Error("MailboxRecordRegistry.register: class must have static fromBytes(wireBytes) method");
    }
    if (this.#allContentTypes.has(ct)) {
      throw new Error("MailboxRecordRegistry: content type already registered: " + ct);
    }
    this.#wireTypes.set(ct, recordClass);
    this.#probeOrder.push(recordClass);
    this.#allContentTypes.add(ct);
  }

  /**
   * Register an app-layer record type (constructed in code, not from wire).
   * @param {Function} recordClass — must have static CONTENT_TYPE string
   */
  registerAppType(recordClass) {
    if (!recordClass || typeof recordClass !== "function") {
      throw new Error("MailboxRecordRegistry.registerAppType requires a class");
    }
    const ct = recordClass.CONTENT_TYPE;
    if (typeof ct !== "string" || ct.length === 0) {
      throw new Error("MailboxRecordRegistry.registerAppType: class must have static CONTENT_TYPE string");
    }
    if (this.#allContentTypes.has(ct)) {
      throw new Error("MailboxRecordRegistry: content type already registered: " + ct);
    }
    this.#allContentTypes.add(ct);
  }

  /**
   * Hydrate wire bytes into a typed record by probing registered wire types.
   * Throws if no registered type matches or if validation fails.
   * This is the ONLY way network bytes should enter the system.
   * @param {Uint8Array} wireBytes
   * @returns {object} validated record instance
   */
  hydrateFromWire(wireBytes) {
    if (!(wireBytes instanceof Uint8Array) || wireBytes.length === 0) {
      throw new Error("MailboxRecordRegistry.hydrateFromWire requires non-empty Uint8Array");
    }
    for (const cls of this.#probeOrder) {
      if (cls.probe(wireBytes)) {
        return cls.fromBytes(wireBytes);
      }
    }
    throw new Error(
      "MailboxRecordRegistry.hydrateFromWire: no registered record type matched the wire bytes"
      + " (registered wire types: " + Array.from(this.#wireTypes.keys()).join(", ") + ")"
    );
  }

  /**
   * Check if a content type is allowed for deposit.
   * @param {string} contentType
   * @returns {boolean}
   */
  isAllowedContentType(contentType) {
    return this.#allContentTypes.has(contentType);
  }

  /**
   * List all registered content types.
   * @returns {string[]}
   */
  listContentTypes() {
    return Array.from(this.#allContentTypes);
  }
}
