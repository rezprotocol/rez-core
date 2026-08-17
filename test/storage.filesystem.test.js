import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

import { FileSystemDataStore } from "../src/storage/fs/FileSystemDataStore.js";

async function withTempStore(fn) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rez-fsds-"));
  const store = new FileSystemDataStore({ basePath: dir });
  try {
    await fn(store, dir);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}

test("FileSystemDataStore — constructor requires basePath", () => {
  assert.throws(() => new FileSystemDataStore({}), /requires basePath/);
  assert.throws(() => new FileSystemDataStore({ basePath: "" }), /requires basePath/);
});

test("FileSystemDataStore — put and get", async () => {
  await withTempStore(async (store) => {
    await store.put("hello", { msg: "world" });
    const v = await store.get("hello");
    assert.deepEqual(v, { msg: "world" });
  });
});

test("FileSystemDataStore — get returns null for missing key", async () => {
  await withTempStore(async (store) => {
    assert.equal(await store.get("nope"), null);
  });
});

test("FileSystemDataStore — put overwrites", async () => {
  await withTempStore(async (store) => {
    await store.put("k", 1);
    await store.put("k", 2);
    assert.equal(await store.get("k"), 2);
  });
});

test("FileSystemDataStore — nested keys create directories", async () => {
  await withTempStore(async (store, dir) => {
    await store.put("mbox/abc/meta", { vis: "private" });
    const filePath = path.join(dir, "mbox", "abc", "meta.json");
    const stat = await fs.stat(filePath);
    assert.ok(stat.isFile());
    const v = await store.get("mbox/abc/meta");
    assert.deepEqual(v, { vis: "private" });
  });
});

test("FileSystemDataStore — has", async () => {
  await withTempStore(async (store) => {
    assert.equal(await store.has("x"), false);
    await store.put("x", 1);
    assert.equal(await store.has("x"), true);
  });
});

test("FileSystemDataStore — remove", async () => {
  await withTempStore(async (store) => {
    assert.equal(await store.remove("x"), false);
    await store.put("x", 1);
    assert.equal(await store.remove("x"), true);
    assert.equal(await store.has("x"), false);
  });
});

test("FileSystemDataStore — remove prunes empty parent dirs", async () => {
  await withTempStore(async (store, dir) => {
    await store.put("a/b/c/leaf", 42);
    assert.equal(await store.remove("a/b/c/leaf"), true);

    // a/b/c should be pruned, a/b should be pruned, a should be pruned
    const entries = await fs.readdir(dir);
    assert.equal(entries.length, 0, "basePath should be empty after pruning");
  });
});

test("FileSystemDataStore — clear", async () => {
  await withTempStore(async (store) => {
    await store.put("a", 1);
    await store.put("deep/nested/key", 2);
    await store.clear();
    assert.equal(await store.has("a"), false);
    assert.equal(await store.has("deep/nested/key"), false);
  });
});

test("FileSystemDataStore — list with prefix", async () => {
  await withTempStore(async (store) => {
    await store.put("mbox/a/evt/1", "e1");
    await store.put("mbox/a/evt/2", "e2");
    await store.put("mbox/a/meta", "meta");
    await store.put("mbox/b/evt/1", "e3");

    const { items } = await store.list("mbox/a/evt/");
    assert.equal(items.length, 2);
    assert.equal(items[0].key, "mbox/a/evt/1");
    assert.equal(items[1].key, "mbox/a/evt/2");
  });
});

test("FileSystemDataStore — list sorted", async () => {
  await withTempStore(async (store) => {
    await store.put("c", 3);
    await store.put("a", 1);
    await store.put("b", 2);

    const { items } = await store.list("");
    assert.deepEqual(items.map((i) => i.key), ["a", "b", "c"]);
  });
});

test("FileSystemDataStore — list with reverse", async () => {
  await withTempStore(async (store) => {
    await store.put("a", 1);
    await store.put("b", 2);
    await store.put("c", 3);

    const { items } = await store.list("", { reverse: true });
    assert.deepEqual(items.map((i) => i.key), ["c", "b", "a"]);
  });
});

test("FileSystemDataStore — list with limit and cursor", async () => {
  await withTempStore(async (store) => {
    for (let i = 0; i < 5; i++) {
      await store.put(`k${i}`, i);
    }

    const page1 = await store.list("", { limit: 2 });
    assert.equal(page1.items.length, 2);
    assert.equal(page1.nextCursor, "k1");

    const page2 = await store.list("", { limit: 2, cursor: page1.nextCursor });
    assert.equal(page2.items.length, 2);
    assert.equal(page2.items[0].key, "k2");

    const page3 = await store.list("", { limit: 2, cursor: page2.nextCursor });
    assert.equal(page3.items.length, 1);
    assert.equal(page3.nextCursor, null);
  });
});

test("FileSystemDataStore — rejects path traversal keys", async () => {
  await withTempStore(async (store) => {
    await assert.rejects(() => store.put("../escape", 1), /must not contain/);
    await assert.rejects(() => store.put("a/../../b", 1), /must not contain/);
    await assert.rejects(() => store.put("a//b", 1), /must not contain empty/);
  });
});

test("FileSystemDataStore — atomic write (crash safety)", async () => {
  await withTempStore(async (store, dir) => {
    await store.put("safe", { data: "original" });

    // Verify no .tmp files remain after successful put
    const files = await fs.readdir(dir);
    const tmpFiles = files.filter((f) => f.endsWith(".tmp"));
    assert.equal(tmpFiles.length, 0, "no temp files should remain");

    const v = await store.get("safe");
    assert.deepEqual(v, { data: "original" });
  });
});

test("FileSystemDataStore — list empty store returns empty", async () => {
  await withTempStore(async (store) => {
    const { items, nextCursor } = await store.list("");
    assert.equal(items.length, 0);
    assert.equal(nextCursor, null);
  });
});

test("FileSystemDataStore — Uint8Array round-trips byte-identical via put/get", async () => {
  await withTempStore(async (store) => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    await store.put("mbox/abc/evt/evt_1", {
      objectId: "obj-1",
      bytes,
      metadata: { contentType: "rez.test/v1" },
      createdAt: 12345,
    });

    const got = await store.get("mbox/abc/evt/evt_1");
    assert.ok(got, "stored value should be retrievable");
    assert.ok(got.bytes instanceof Uint8Array, "bytes must round-trip as Uint8Array (not digit-keyed object)");
    assert.equal(got.bytes.length, bytes.length);
    for (let i = 0; i < bytes.length; i += 1) {
      assert.equal(got.bytes[i], bytes[i], "byte at " + i + " must match");
    }
    assert.equal(got.objectId, "obj-1");
    assert.equal(got.createdAt, 12345);
  });
});

test("FileSystemDataStore — Uint8Array survives store restart (file-on-disk)", async () => {
  await withTempStore(async (store, dir) => {
    const bytes = new Uint8Array([42, 7, 0, 255]);
    await store.put("mbox/x/evt/evt_a", { bytes, objectId: "o", createdAt: 1 });

    // Drop the store and recreate it pointing at the same dir — simulates a
    // relay process restart with on-disk persistence.
    const reopened = new FileSystemDataStore({ basePath: dir });
    const got = await reopened.get("mbox/x/evt/evt_a");
    assert.ok(got.bytes instanceof Uint8Array);
    assert.deepEqual(Array.from(got.bytes), [42, 7, 0, 255]);
  });
});

// ---------------------------------------------------------------------------
// CORE-1 — sibling-prefix containment
// ---------------------------------------------------------------------------
// `#pruneEmptyDirs` guarded with `resolved.startsWith(this.#basePath)`, which is
// a PREFIX test, not a containment test: `/tmp/base2` starts with `/tmp/base`.
// The correct form (path.relative) already existed 120 lines up in the same
// file — the two had simply drifted.
//
// HONEST SCOPE: the two sibling/root tests below pass against the OLD code too,
// and that is stated rather than hidden. The bug was never reachable — prune is
// only ever seeded from an already-validated in-base path and stops on the way
// up the moment it reaches the root, so no caller could hand it an outside
// path. It was a wrong guard, not a live traversal.
//
// They are kept as CHARACTERIZATION tests, not regression guards: they pin what
// the guard must mean if a future call site ever seeds prune from somewhere new,
// which is exactly the change that would turn the old prefix test into a real
// bug. The test below them — a storage fault being raised rather than swallowed
// — IS a behavioural regression guard, and does fail against the old code.

test("FileSystemDataStore — CORE-1: a sibling dir sharing the base's name prefix is NOT treated as inside", async () => {
  const parent = await fs.mkdtemp(path.join(os.tmpdir(), "rez-core1-"));
  const base = path.join(parent, "base");
  const sibling = path.join(parent, "base2"); // startsWith(base) === true
  await fs.mkdir(base, { recursive: true });
  await fs.mkdir(path.join(sibling, "empty-child"), { recursive: true });

  try {
    const store = new FileSystemDataStore({ basePath: base });
    await store.put("a/b/c", { v: 1 });
    await store.remove("a/b/c");

    // The sibling must be untouched. Under the prefix test it read as "inside
    // the store", making its empty directories eligible for pruning.
    const siblingStillThere = await fs.stat(path.join(sibling, "empty-child"))
      .then(() => true, () => false);
    assert.equal(siblingStillThere, true,
      "a directory that merely shares a name prefix is not inside the store");
  } finally {
    await fs.rm(parent, { recursive: true, force: true });
  }
});

test("FileSystemDataStore — CORE-1: the basePath itself is never pruned", async () => {
  await withTempStore(async (store, dir) => {
    await store.put("solo", { v: 1 });
    await store.remove("solo");
    const baseStillThere = await fs.stat(dir).then(() => true, () => false);
    assert.equal(baseStillThere, true, "pruning must stop at the store root, not delete it");
  });
});

test("FileSystemDataStore — pruning still removes the empty parents it owns", async () => {
  // The containment fix must not cost the behaviour: deep empty parents inside
  // the base are still cleaned up.
  await withTempStore(async (store, dir) => {
    await store.put("x/y/z/leaf", { v: 1 });
    await store.remove("x/y/z/leaf");
    for (const rel of ["x/y/z", "x/y", "x"]) {
      const gone = await fs.stat(path.join(dir, rel)).then(() => false, () => true);
      assert.equal(gone, true, `${rel} should have been pruned`);
    }
  });
});

test("FileSystemDataStore — a storage fault during prune is raised, not swallowed", async () => {
  // The old catch-all hid every failure, so a failing disk looked like a tidy
  // one. Only the benign races (already gone, refilled) are absorbed now.
  await withTempStore(async (store, dir) => {
    await store.put("p/q/leaf", { v: 1 });
    const realReaddir = fs.readdir;
    fs.readdir = async (target, ...rest) => {
      if (String(target).startsWith(path.join(dir, "p"))) {
        const err = new Error("simulated I/O failure");
        err.code = "EIO";
        throw err;
      }
      return realReaddir(target, ...rest);
    };
    try {
      await assert.rejects(() => store.remove("p/q/leaf"), /simulated I\/O failure/);
    } finally {
      fs.readdir = realReaddir;
    }
  });
});

test("FileSystemDataStore — a concurrently-removed dir during prune is absorbed", async () => {
  await withTempStore(async (store, dir) => {
    await store.put("r/s/leaf", { v: 1 });
    const realRmdir = fs.rmdir;
    fs.rmdir = async (target, ...rest) => {
      if (String(target) === path.join(dir, "r", "s")) {
        const err = new Error("gone");
        err.code = "ENOENT";
        throw err;
      }
      return realRmdir(target, ...rest);
    };
    try {
      await store.remove("r/s/leaf"); // must not throw
    } finally {
      fs.rmdir = realRmdir;
    }
  });
});

test("FileSystemDataStore — CORE-1: list() rejects a traversing prefix BEFORE walking anything", async () => {
  // `list` is public and used to join prefix segments raw, with none of the
  // validation keys get. `../../..` built a path outside the store and
  // #collectFiles walked it; the containment assert in #pathToKey only fired
  // afterwards, once the traversal had already happened.
  await withTempStore(async (store) => {
    await assert.rejects(() => store.list("../.."), /prefix must not contain \. or \.\. segments/);
    await assert.rejects(() => store.list("a/../../etc"), /prefix must not contain \. or \.\. segments/);
    await assert.rejects(() => store.list("./x"), /prefix must not contain \. or \.\. segments/);
  });
});

test("FileSystemDataStore — CORE-1: keys and prefixes now share one rule", async () => {
  await withTempStore(async (store) => {
    // The same string must not be safe as a key and a traversal as a prefix.
    await assert.rejects(() => store.get("../escape"), /key must not contain \. or \.\. segments/);
    await assert.rejects(() => store.list("../escape"), /prefix must not contain \. or \.\. segments/);
  });
});

test("FileSystemDataStore — a trailing slash in a prefix still works", async () => {
  // Established calling convention; the empty segment is inert. Tightening
  // containment must not cost it.
  await withTempStore(async (store) => {
    await store.put("mbox/a/evt/1", "e1");
    await store.put("mbox/a/evt/2", "e2");
    const withSlash = await store.list("mbox/a/evt/");
    const without = await store.list("mbox/a/evt");
    assert.equal(withSlash.items.length, 2);
    assert.deepEqual(withSlash.items.map((i) => i.key), without.items.map((i) => i.key));
  });
});
