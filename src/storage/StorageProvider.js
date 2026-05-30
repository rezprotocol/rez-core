import { RAbstract } from "../base/index.js";

export class StorageProvider extends RAbstract {
  /**
   * Returns the root object store adapter.
   * Callers must treat account ownership as an explicit partition key rather
   * than assuming the provider is single-tenant.
   */
  getObjectStore() {
    return this.abstract("getObjectStore");
  }

  /**
   * Returns the root mailbox store adapter.
   * Mailbox state may be node-global, but account-owned data must still be
   * segregated by explicit owner identifiers in the consuming layer.
   */
  getMailboxStore() {
    return this.abstract("getMailboxStore");
  }

  /**
   * Returns the root key-value adapter.
   * Implementations must support consumer-defined owner partitioning; account
   * data must never rely on an implicit single-user node assumption. Passing
   * null requests the root adapter for cross-owner orchestration services.
   */
  getKeyValueStore(ownerAccountId = null) {
    void ownerAccountId;
    return this.abstract("getKeyValueStore");
  }

  /**
   * Returns the peer-link storage bundle.
   * All peer-link records, sessions, attempts, events, and invite prekeys must
   * be resolved through explicit owner-scoped operations. Passing null requests
   * the root bundle for services that intentionally coordinate across owners.
   */
  getPeerLinkStorage(ownerAccountId = null) {
    void ownerAccountId;
    return this.abstract("getPeerLinkStorage");
  }
}
