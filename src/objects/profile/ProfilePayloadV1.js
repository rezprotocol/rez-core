import { RSerializable } from "../../base/index.js";

const MAX_DISPLAY_NAME_LENGTH = 64;
const HEX_HASH_RE = /^[0-9a-f]{64}$/;

export class ProfilePayloadV1 extends RSerializable {
  static type = "ProfilePayloadV1";

  constructor({ displayName, updatedAtMs, avatarFileHash, ...rest } = {}) {
    super();

    this.assert(
      typeof displayName === "string" && displayName.trim().length > 0,
      "ProfilePayloadV1 requires non-empty displayName",
      { displayName },
    );
    this.assert(
      typeof displayName === "string" && displayName.trim().length <= MAX_DISPLAY_NAME_LENGTH,
      "ProfilePayloadV1 displayName must be " + MAX_DISPLAY_NAME_LENGTH + " chars or fewer",
      { length: typeof displayName === "string" ? displayName.length : 0 },
    );
    this.assert(
      Number.isFinite(updatedAtMs) && updatedAtMs > 0,
      "ProfilePayloadV1 requires positive updatedAtMs",
      { updatedAtMs },
    );
    const rawHash = avatarFileHash != null ? avatarFileHash : "";
    this.assert(
      typeof rawHash === "string",
      "ProfilePayloadV1 avatarFileHash must be a string if provided",
      { avatarFileHash },
    );
    const trimmedHash = typeof rawHash === "string" ? rawHash.trim() : "";
    if (trimmedHash.length > 0) {
      this.assert(
        HEX_HASH_RE.test(trimmedHash),
        "ProfilePayloadV1 avatarFileHash must be a 64-char hex SHA-256 hash",
        { avatarFileHash: trimmedHash },
      );
    }

    this.kind = "rez.profile.v1";
    this.displayName = displayName.trim();
    this.updatedAtMs = updatedAtMs;
    this.avatarFileHash = trimmedHash;
    this.extras = rest && typeof rest === "object" ? Object.assign({}, rest) : {};
    delete this.extras.kind;
  }

  toJSON() {
    const base = Object.assign({}, this.extras, {
      kind: this.kind,
      displayName: this.displayName,
      updatedAtMs: this.updatedAtMs,
    });
    if (this.avatarFileHash) {
      base.avatarFileHash = this.avatarFileHash;
    }
    return base;
  }

  toBytes() {
    return new TextEncoder().encode(JSON.stringify(this.toJSON()));
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("ProfilePayloadV1.fromJSON(json) requires object");
    }
    const { kind, displayName, updatedAtMs, avatarFileHash, ...rest } = json;
    return new ProfilePayloadV1({ displayName, updatedAtMs, avatarFileHash, ...rest });
  }

  static fromBytes(bytes) {
    const text = new TextDecoder().decode(bytes);
    return ProfilePayloadV1.fromJSON(JSON.parse(text));
  }
}
