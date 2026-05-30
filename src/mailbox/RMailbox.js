import { RDataStore } from "../storage/RDataStore.js";
import { MailboxRecordRegistry } from "./MailboxRecordRegistry.js";

export class RMailbox {
  static VISIBILITY = Object.freeze({ PRIVATE: "private", PUBLIC_READ: "public-read" });

  static CONTENT_TYPES = Object.freeze({
    OUTER: "rez.outer",
    APP_DEPOSIT: "rez.app.deposit",
  });

  #store;
  #registry;
  #waiters = new Map();
  #counter = 0;
  #onDeposit = null;

  /**
   * @param {{ store: RDataStore, registry: MailboxRecordRegistry }} opts
   */
  constructor({ store, registry }) {
    if (!(store instanceof RDataStore)) {
      throw new Error("RMailbox requires store (RDataStore)");
    }
    if (!(registry instanceof MailboxRecordRegistry)) {
      throw new Error("RMailbox requires registry (MailboxRecordRegistry)");
    }
    this.#store = store;
    this.#registry = registry;
  }

  setOnDeposit(fn) {
    this.#onDeposit = typeof fn === "function" ? fn : null;
  }

  async createMailbox(mailboxId, { visibility = "private", ownerAccountId = null } = {}) {
    _assertNonEmpty(mailboxId, "mailboxId");
    const key = `mbox/${mailboxId}/meta`;
    await this.#store.put(key, {
      visibility,
      ownerAccountId,
      createdAtMs: Date.now(),
    });
  }

  async getMailboxMeta(mailboxId) {
    _assertNonEmpty(mailboxId, "mailboxId");
    return this.#store.get(`mbox/${mailboxId}/meta`);
  }

  /**
   * Deposit a record into a mailbox.
   *
   * @param {string} mailboxId
   * @param {object} record — must have contentType (string) and toBytes() (returns Uint8Array).
   *                          Use OuterPacketRecord for network packets or AppDepositRecord for SDK deposits.
   * @returns {Promise<string>} eventId
   */
  async deposit(mailboxId, record) {
    _assertNonEmpty(mailboxId, "mailboxId");

    if (!record || typeof record !== "object") {
      throw new Error("RMailbox.deposit requires a record object");
    }
    if (typeof record.toBytes !== "function") {
      throw new Error("RMailbox.deposit requires record with toBytes() method");
    }

    const contentType = typeof record.contentType === "string" ? record.contentType : "";
    if (!contentType || !this.#registry.isAllowedContentType(contentType)) {
      throw new Error(
        "RMailbox.deposit requires record.contentType to be one of: "
        + this.#registry.listContentTypes().join(", ")
        + (contentType ? " (got: " + contentType + ")" : " (none on record)")
      );
    }

    const bytes = record.toBytes();
    if (!(bytes instanceof Uint8Array)) {
      throw new Error("RMailbox.deposit: record.toBytes() must return Uint8Array");
    }

    const objectId = typeof record.objectId === "string" && record.objectId.length > 0
      ? record.objectId
      : this.#nextObjectId();

    const meta = typeof record.metadata === "object" && record.metadata !== null
      ? { ...record.metadata, contentType }
      : { contentType };

    const eventId = this.#nextEventId();
    const createdAt = Date.now();
    const key = `mbox/${mailboxId}/evt/${eventId}`;
    const value = { objectId, bytes, metadata: meta, createdAt };
    await this.#store.put(key, value);

    this.#notifyWaiters(mailboxId, { eventId, ...value });

    if (this.#onDeposit) {
      const fn = this.#onDeposit;
      // Defer to macrotask so deposit processing does not interleave
      // with the depositor's await chain via microtask scheduling.
      setTimeout(() => { try { fn(mailboxId, eventId); } catch { /* ignore */ } }, 0);
    }

    return eventId;
  }

  /**
   * Deposit raw network bytes into a mailbox.
   *
   * This is the ONLY way raw wire bytes should enter the mailbox system.
   * Hydrates bytes into a validated record via the registry, then deposits.
   * Rejects bytes that don't match any registered wire record type.
   *
   * @param {string} mailboxId
   * @param {Uint8Array} wireBytes
   * @returns {Promise<string>} eventId
   */
  async depositFromWire(mailboxId, wireBytes) {
    _assertNonEmpty(mailboxId, "mailboxId");
    const record = this.#registry.hydrateFromWire(wireBytes);
    return this.deposit(mailboxId, record);
  }

  async list(mailboxId, { cursor, limit = 50, sinceMs } = {}) {
    _assertNonEmpty(mailboxId, "mailboxId");
    const prefix = `mbox/${mailboxId}/evt/`;
    const result = await this.#store.list(prefix, { cursor: cursor ? `${prefix}${cursor}` : undefined, limit });

    let items = result.items.map((entry) => ({
      eventId: entry.key.slice(prefix.length),
      objectId: entry.value.objectId,
      createdAt: entry.value.createdAt,
    }));

    if (sinceMs != null) {
      items = items.filter((i) => i.createdAt >= sinceMs);
    }

    const nextCursor = result.nextCursor ? result.nextCursor.slice(prefix.length) : null;
    return { items, nextCursor };
  }

  async fetch(mailboxId, eventId) {
    _assertNonEmpty(mailboxId, "mailboxId");
    _assertNonEmpty(eventId, "eventId");
    return this.#store.get(`mbox/${mailboxId}/evt/${eventId}`);
  }

  async ack(mailboxId, eventId) {
    _assertNonEmpty(mailboxId, "mailboxId");
    _assertNonEmpty(eventId, "eventId");
    return this.#store.remove(`mbox/${mailboxId}/evt/${eventId}`);
  }

  waitForDeposit(mailboxId, { timeoutMs = 2000, cursor, sinceMs } = {}) {
    _assertNonEmpty(mailboxId, "mailboxId");

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#removeWaiter(mailboxId, waiter);
        reject(new Error("RMailbox.waitForDeposit timeout"));
      }, timeoutMs);

      const waiter = {
        cursor,
        sinceMs,
        resolve: (item) => {
          clearTimeout(timer);
          this.#removeWaiter(mailboxId, waiter);
          resolve(item);
        },
      };

      const queue = this.#waiters.get(mailboxId) || [];
      queue.push(waiter);
      this.#waiters.set(mailboxId, queue);
    });
  }

  #nextEventId() {
    this.#counter += 1;
    return String(Date.now()) + "_" + String(this.#counter).padStart(6, "0");
  }

  #nextObjectId() {
    this.#counter += 1;
    return "obj_" + String(Date.now()) + "_" + String(this.#counter).padStart(6, "0");
  }

  #notifyWaiters(mailboxId, item) {
    const queue = this.#waiters.get(mailboxId);
    if (!queue || queue.length === 0) return;

    const remaining = [];
    for (const waiter of queue) {
      if (this.#itemMatchesWaiter(item, waiter)) {
        try {
          waiter.resolve(item);
        } catch {
          // ignore waiter failures
        }
      } else {
        remaining.push(waiter);
      }
    }

    if (remaining.length > 0) this.#waiters.set(mailboxId, remaining);
    else this.#waiters.delete(mailboxId);
  }

  #itemMatchesWaiter(item, waiter) {
    if (waiter.sinceMs != null && item.createdAt < waiter.sinceMs) return false;
    if (waiter.cursor != null && item.eventId <= waiter.cursor) return false;
    return true;
  }

  #removeWaiter(mailboxId, waiterRef) {
    const queue = this.#waiters.get(mailboxId);
    if (!queue) return;
    const next = queue.filter((w) => w !== waiterRef);
    if (next.length > 0) this.#waiters.set(mailboxId, next);
    else this.#waiters.delete(mailboxId);
  }
}

function _assertNonEmpty(value, name) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`RMailbox requires non-empty string ${name}`);
  }
}
