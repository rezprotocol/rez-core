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
