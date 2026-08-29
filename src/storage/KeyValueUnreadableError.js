/**
 * KeyValueUnreadableError distinguishes an unreadable/corrupt stored value
 * from a key that is genuinely absent. Recovery code must never collapse the
 * former into the latter.
 */
export class KeyValueUnreadableError extends Error {
  constructor({ key, cause } = {}) {
    const normalizedKey = String(key == null ? "" : key);
    const detail = cause && cause.message ? cause.message : String(cause || "unreadable value");
    super("Key-value record is unreadable for " + normalizedKey + ": " + detail, { cause });
    this.name = "KeyValueUnreadableError";
    this.code = "KEY_VALUE_UNREADABLE";
    this.key = normalizedKey;
  }
}
