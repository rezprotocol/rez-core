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

  /**
   * Split a caller-supplied key or prefix into path segments, rejecting any
   * that could escape basePath.
   *
   * ONE rule for both (CORE-1): keys were validated here while `list(prefix)`
   * joined its segments raw, so the same string was safe as a key and a
   * traversal as a prefix. Two call sites, two behaviours, one boundary — the
   * shape of bug this repo keeps rediscovering.
   *
   * `.` and `..` are rejected for both — those are the segments that escape.
   * Empty segments differ: a key must name an exact file so `a//b` is a
   * malformed key, but `list("mbox/a/evt/")` is an established calling
   * convention and its trailing empty segment is inert (`path.join` drops it).
   * Rejecting it would break real callers for no security gain, so prefixes
   * tolerate empties while keys keep the stricter rule they already had.
   *
   * @param {string} value the raw key or prefix
   * @param {string} label what to call it in the error ("key" / "prefix")
   * @param {{ allowEmptySegments?: boolean }} [opts]
   */
  #validatedSegments(value, label, { allowEmptySegments = false } = {}) {
    this.assert(typeof value === "string" && value.length > 0, `requires non-empty string ${label}`);
    const segments = value.split("/");
    for (const seg of segments) {
      if (!allowEmptySegments) {
        this.assert(seg.length > 0, `${label} must not contain empty segments`);
      }
      this.assert(seg !== "." && seg !== "..", `${label} must not contain . or .. segments`);
    }
    return allowEmptySegments ? segments.filter((seg) => seg.length > 0) : segments;
  }

  #keyToPath(key) {
    return path.join(this.#basePath, ...this.#validatedSegments(key, "key")) + ".json";
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
    // CORE-1 (second half): `list` is public and used to join prefix segments
    // straight onto basePath with none of the `.`/`..` validation `#keyToPath`
    // applies to keys. A prefix like `../../etc` therefore built a path outside
    // the store and `#collectFiles` walked it — the containment assert in
    // `#pathToKey` only fires afterwards, once the traversal has already
    // happened. Same rule as keys, applied at the same boundary.
    const dirPath = prefix
      ? path.join(this.#basePath, ...this.#validatedSegments(prefix, "prefix", { allowEmptySegments: true }))
      : this.#basePath;
    this.assert(
      dirPath === this.#basePath || this.#isInsideBase(dirPath),
      "prefix resolves outside basePath",
    );

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

  /**
   * Is `candidate` strictly inside basePath?
   *
   * CORE-1: this used to be `resolved.startsWith(this.#basePath)`, which is a
   * PREFIX test, not a containment test — `/tmp/base2` starts with `/tmp/base`,
   * so a sibling directory read as "inside". The same file already had the
   * correct form 120 lines up in `#pathToKey`; the two just drifted.
   *
   * `path.relative` is the containment test: for a path inside the base it
   * yields a relative walk with no leading `..`, and for anything outside (or
   * on another drive, where it returns an absolute path) it does not.
   */
  #isInsideBase(candidate) {
    const rel = path.relative(this.#basePath, candidate);
    if (rel === "") return false; // the base itself is not "inside" it
    if (path.isAbsolute(rel)) return false; // different root/drive
    return rel !== ".." && !rel.startsWith(".." + path.sep);
  }

  async #pruneEmptyDirs(dirPath) {
    const resolved = path.resolve(dirPath);
    if (!this.#isInsideBase(resolved)) return;
    let entries;
    try {
      entries = await fs.readdir(resolved);
    } catch (err) {
      // ENOENT: already removed by a concurrent prune — nothing left to do.
      // Anything else (EACCES, EIO) is a real storage fault and must not be
      // swallowed silently, or a failing disk looks like a tidy one.
      if (err && err.code === "ENOENT") return;
      throw err;
    }
    if (entries.length !== 0) return;
    try {
      await fs.rmdir(resolved);
    } catch (err) {
      // ENOTEMPTY/EEXIST: another writer refilled it between the readdir and
      // the rmdir — a benign race, and the directory is wanted after all.
      // ENOENT: a concurrent prune won. Both mean "stop", not "fail".
      if (err && (err.code === "ENOTEMPTY" || err.code === "EEXIST" || err.code === "ENOENT")) return;
      throw err;
    }
    await this.#pruneEmptyDirs(path.dirname(resolved));
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
