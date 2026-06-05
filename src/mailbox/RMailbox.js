import { RDataStore } from "../storage/RDataStore.js";
import { MailboxRecordRegistry } from "./MailboxRecordRegistry.js";

/**
 * Thrown by RMailbox.deposit when a mailbox is at its configured item cap.
 * Callers that fire-and-forget a deposit (relay ingress paths) catch + log it;
 * the deposit is dropped rather than letting one mailbox grow without bound.
 */
export class MailboxQuotaExceededError extends Error {
  constructor(mailboxId, cap, limitType = "items") {
    super("RMailbox: mailbox '" + mailboxId + "' is at its " + limitType + " cap (" + cap + ")");
    this.name = "MailboxQuotaExceededError";
    this.code = "MAILBOX_QUOTA_EXCEEDED";
    this.mailboxId = mailboxId;
    this.cap = cap;
    // "items" | "bytes" — which limit was hit (both share this error type).
    this.limitType = limitType;
  }
}

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
  // Per-mailbox item cap (DoS guard). null = unlimited (default; preserves
  // behaviour for every non-relay RMailbox). The relay inbox store opts in so a
  // sender cannot fill a victim's buffer without bound. Counts are tracked in
  // memory, lazily seeded from disk on first access per mailbox.
  #maxItems;
  #countByMailbox = new Map();
  // Per-mailbox byte cap (DoS guard), independent of the item cap. null =
  // unlimited (default). The item count is cheap to seed by listing keys, but a
  // byte total can't be summed from list() without reading every event body, so
  // the total is kept in an O(1) persisted counter per mailbox
  // (mbox/<id>/bytesz) and maintained incrementally on deposit/ack — there is
  // deliberately no O(n) read-to-seed of event bodies on startup.
  #maxBytes;
  #bytesByMailbox = new Map();

  /**
   * @param {{ store: RDataStore, registry: MailboxRecordRegistry, maxItems?: number|null, maxBytes?: number|null }} opts
   * @param {number|null} [opts.maxItems] per-mailbox item cap; omit/null for unlimited.
   * @param {number|null} [opts.maxBytes] per-mailbox total-bytes cap; omit/null for unlimited.
   */
  constructor({ store, registry, maxItems = null, maxBytes = null }) {
    if (!(store instanceof RDataStore)) {
      throw new Error("RMailbox requires store (RDataStore)");
    }
    if (!(registry instanceof MailboxRecordRegistry)) {
      throw new Error("RMailbox requires registry (MailboxRecordRegistry)");
    }
    this.#store = store;
    this.#registry = registry;
    this.#maxItems = typeof maxItems === "number" && maxItems > 0 ? maxItems : null;
    this.#maxBytes = typeof maxBytes === "number" && maxBytes > 0 ? maxBytes : null;
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

    // Per-mailbox caps (DoS guard). Enforced for every deposit path because
    // depositFromWire() and deposit() both funnel here. No-op when uncapped.
    if (this.#maxItems !== null) {
      const count = await this.#ensureCount(mailboxId);
      if (count >= this.#maxItems) {
        throw new MailboxQuotaExceededError(mailboxId, this.#maxItems, "items");
      }
    }
    const byteLen = bytes.length;
    if (this.#maxBytes !== null) {
      const used = await this.#ensureBytes(mailboxId);
      if (used + byteLen > this.#maxBytes) {
        throw new MailboxQuotaExceededError(mailboxId, this.#maxBytes, "bytes");
      }
    }

    const eventId = this.#nextEventId();
    const createdAt = Date.now();
    const key = `mbox/${mailboxId}/evt/${eventId}`;
    const value = { objectId, bytes, metadata: meta, createdAt };
    await this.#store.put(key, value);

    if (this.#maxItems !== null) {
      this.#countByMailbox.set(mailboxId, (this.#countByMailbox.get(mailboxId) || 0) + 1);
    }
    if (this.#maxBytes !== null) {
      const nextBytes = (this.#bytesByMailbox.get(mailboxId) || 0) + byteLen;
      this.#bytesByMailbox.set(mailboxId, nextBytes);
      await this.#persistBytes(mailboxId, nextBytes);
    }

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
    const key = `mbox/${mailboxId}/evt/${eventId}`;
    // When a byte cap is active we need the record's size to keep the counter
    // accurate, so read it before removal. Skipped (no extra read) when uncapped.
    let ackedBytes = 0;
    if (this.#maxBytes !== null) {
      const existing = await this.#store.get(key);
      if (existing && existing.bytes instanceof Uint8Array) {
        ackedBytes = existing.bytes.length;
      }
    }
    const removed = await this.#store.remove(key);
    if (removed && this.#maxItems !== null && this.#countByMailbox.has(mailboxId)) {
      const next = (this.#countByMailbox.get(mailboxId) || 0) - 1;
      this.#countByMailbox.set(mailboxId, next > 0 ? next : 0);
    }
    if (removed && this.#maxBytes !== null) {
      const used = await this.#ensureBytes(mailboxId);
      const next = used - ackedBytes;
      const clamped = next > 0 ? next : 0;
      this.#bytesByMailbox.set(mailboxId, clamped);
      await this.#persistBytes(mailboxId, clamped);
    }
    return removed;
  }

  /**
   * Lazily seed and return the in-memory item count for a mailbox. The first
   * deposit/ack for a mailbox after process start pays a one-time scan so a
   * count that survived a restart is not undercounted; afterwards the count is
   * maintained incrementally. Only called when a cap is configured.
   */
  async #ensureCount(mailboxId) {
    if (this.#countByMailbox.has(mailboxId)) {
      return this.#countByMailbox.get(mailboxId);
    }
    let count = 0;
    let cursor;
    // Loop the paginated list to the end so the seed reflects the full backlog.
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const page = await this.list(mailboxId, { cursor, limit: 200 });
      count += page.items.length;
      if (!page.nextCursor) break;
      cursor = page.nextCursor;
    }
    this.#countByMailbox.set(mailboxId, count);
    return count;
  }

  /**
   * Lazily seed and return the in-memory byte total for a mailbox from its O(1)
   * persisted counter (mbox/<id>/bytesz). A mailbox with no persisted counter
   * yet — created before this counter existed, or never deposited under a byte
   * cap — seeds to 0 and is maintained incrementally from here; we deliberately
   * do NOT scan and read every event body to reconstruct a historical total
   * (that would reintroduce the O(n) body-read this counter exists to avoid).
   * Only called when a byte cap is configured.
   */
  async #ensureBytes(mailboxId) {
    if (this.#bytesByMailbox.has(mailboxId)) {
      return this.#bytesByMailbox.get(mailboxId);
    }
    const rec = await this.#store.get(`mbox/${mailboxId}/bytesz`);
    const seeded = rec && typeof rec.total === "number" && rec.total > 0 ? rec.total : 0;
    this.#bytesByMailbox.set(mailboxId, seeded);
    return seeded;
  }

  async #persistBytes(mailboxId, total) {
    await this.#store.put(`mbox/${mailboxId}/bytesz`, { total });
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
