import { RDataStore } from "../RDataStore.js";
import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";

export class FileSystemDataStore extends RDataStore {
  static type = "FileSystemDataStore";

  #basePath;

  constructor({ basePath }) {
    super();
    if (!basePath || typeof basePath !== "string") {
      throw new Error("FileSystemDataStore requires basePath string");
    }
    this.#basePath = path.resolve(basePath);
  }

  #keyToPath(key) {
    this.assert(typeof key === "string" && key.length > 0, "requires non-empty string key");
    const segments = key.split("/");
    for (const seg of segments) {
      this.assert(seg.length > 0, "key must not contain empty segments");
      this.assert(seg !== "." && seg !== "..", "key must not contain . or .. segments");
    }
    return path.join(this.#basePath, ...segments) + ".json";
  }

  #pathToKey(filePath) {
    const rel = path.relative(this.#basePath, filePath);
    this.assert(!rel.startsWith(".."), "path outside basePath");
    return rel.slice(0, -".json".length).split(path.sep).join("/");
  }

  async put(key, value) {
    const filePath = this.#keyToPath(key);
    const dir = path.dirname(filePath);
    await fs.mkdir(dir, { recursive: true });

    const tmpPath = filePath + "." + crypto.randomBytes(6).toString("hex") + ".tmp";
    const json = JSON.stringify(value, _bytesReplacer);
    await fs.writeFile(tmpPath, json, "utf8");
    await fs.rename(tmpPath, filePath);
  }

  async get(key) {
    const filePath = this.#keyToPath(key);
    try {
      const raw = await fs.readFile(filePath, "utf8");
      return _reviveBytes(JSON.parse(raw));
    } catch (err) {
      if (err.code === "ENOENT") return null;
      throw err;
    }
  }

  async list(prefix = "", { cursor, limit, reverse } = {}) {
    const dirPath = prefix
      ? path.join(this.#basePath, ...prefix.split("/"))
      : this.#basePath;

    const files = await this.#collectFiles(dirPath);
    let keys = files
      .filter((f) => f.endsWith(".json"))
      .map((f) => this.#pathToKey(f))
      .filter((k) => k.startsWith(prefix));

    keys.sort();
    if (reverse) keys.reverse();

    if (cursor) {
      const idx = keys.indexOf(cursor);
      if (idx >= 0) {
        keys = keys.slice(idx + 1);
      }
    }

    let nextCursor = null;
    if (limit != null && limit > 0 && keys.length > limit) {
      nextCursor = keys[limit - 1];
      keys = keys.slice(0, limit);
    }

    const items = [];
    for (const k of keys) {
      const value = await this.get(k);
      if (value !== null) items.push({ key: k, value });
    }

    return { items, nextCursor };
  }



  async remove(key) {
    const filePath = this.#keyToPath(key);
    try {
      await fs.unlink(filePath);
    } catch (err) {
      if (err.code === "ENOENT") return false;
      throw err;
    }
    await this.#pruneEmptyDirs(path.dirname(filePath));
    return true;
  }

  async has(key) {
    const filePath = this.#keyToPath(key);
    try {
      await fs.access(filePath);
      return true;
    } catch {
      return false;
    }
  }

  async clear() {
    try {
      const entries = await fs.readdir(this.#basePath);
      for (const entry of entries) {
        const full = path.join(this.#basePath, entry);
        await fs.rm(full, { recursive: true, force: true });
      }
    } catch (err) {
      if (err.code === "ENOENT") return;
      throw err;
    }
  }

  async #collectFiles(dirPath) {
    const results = [];
    let entries;
    try {
      entries = await fs.readdir(dirPath, { withFileTypes: true });
    } catch (err) {
      if (err.code === "ENOENT") return results;
      throw err;
    }
    for (const entry of entries) {
      const full = path.join(dirPath, entry.name);
      if (entry.isDirectory()) {
        const sub = await this.#collectFiles(full);
        results.push(...sub);
      } else if (entry.isFile() && entry.name.endsWith(".json")) {
        results.push(full);
      }
    }
    return results;
  }

  async #pruneEmptyDirs(dirPath) {
    const resolved = path.resolve(dirPath);
    if (resolved === this.#basePath || !resolved.startsWith(this.#basePath)) return;
    try {
      const entries = await fs.readdir(resolved);
      if (entries.length === 0) {
        await fs.rmdir(resolved);
        await this.#pruneEmptyDirs(path.dirname(resolved));
      }
    } catch {
      // ignore — dir may already be gone or non-empty
    }
  }
}

// Binary round-trip: relay's RMailbox stores deposit bodies as Uint8Array
// inside the value record (RMailbox.js: { objectId, bytes, metadata,
// createdAt }), and plain JSON.stringify would emit a digit-keyed object
// that doesn't round-trip. A sentinel-wrapped base64 form keeps the
// FileSystemDataStore generic — any value tree containing Uint8Arrays
// round-trips byte-identical without callers needing to know.
const BYTES_SENTINEL = "__rez_bytes_b64__";

function _bytesReplacer(_key, value) {
  if (value instanceof Uint8Array) {
    return { [BYTES_SENTINEL]: Buffer.from(value).toString("base64") };
  }
  return value;
}

function _reviveBytes(value) {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      value[i] = _reviveBytes(value[i]);
    }
    return value;
  }
  if (typeof value[BYTES_SENTINEL] === "string") {
    return new Uint8Array(Buffer.from(value[BYTES_SENTINEL], "base64"));
  }
  for (const k of Object.keys(value)) {
    value[k] = _reviveBytes(value[k]);
  }
  return value;
}
