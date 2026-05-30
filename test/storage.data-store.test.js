import test from "node:test";
import assert from "node:assert/strict";

import { RDataStore } from "../src/storage/RDataStore.js";
import { MemoryDataStore } from "../src/storage/memory/MemoryDataStore.js";

test("RDataStore is abstract", async () => {
  const store = new RDataStore();
  assert.equal(store.type, "RDataStore");

  const methods = ["put", "get", "list", "remove", "has", "clear"];
  for (const m of methods) {
    assert.throws(() => store[m]("k"), (err) => err.name === "RezAbstractError");
  }
});

test("MemoryDataStore — put and get", async () => {
  const store = new MemoryDataStore();
  await store.put("a", { x: 1 });
  const v = await store.get("a");
  assert.deepEqual(v, { x: 1 });
});

test("MemoryDataStore — get returns null for missing key", async () => {
  const store = new MemoryDataStore();
  assert.equal(await store.get("missing"), null);
});

test("MemoryDataStore — put overwrites", async () => {
  const store = new MemoryDataStore();
  await store.put("a", 1);
  await store.put("a", 2);
  assert.equal(await store.get("a"), 2);
});

test("MemoryDataStore — values are cloned (not references)", async () => {
  const store = new MemoryDataStore();
  const orig = { nested: { val: 42 } };
  await store.put("obj", orig);
  const fetched = await store.get("obj");
  fetched.nested.val = 999;
  const again = await store.get("obj");
  assert.equal(again.nested.val, 42);
});

test("MemoryDataStore — has", async () => {
  const store = new MemoryDataStore();
  assert.equal(await store.has("x"), false);
  await store.put("x", 1);
  assert.equal(await store.has("x"), true);
});

test("MemoryDataStore — remove", async () => {
  const store = new MemoryDataStore();
  assert.equal(await store.remove("x"), false);
  await store.put("x", 1);
  assert.equal(await store.remove("x"), true);
  assert.equal(await store.has("x"), false);
});

test("MemoryDataStore — clear", async () => {
  const store = new MemoryDataStore();
  await store.put("a", 1);
  await store.put("b", 2);
  await store.clear();
  assert.equal(await store.has("a"), false);
  assert.equal(await store.has("b"), false);
});

test("MemoryDataStore — list with prefix", async () => {
  const store = new MemoryDataStore();
  await store.put("mbox/a/evt/1", "e1");
  await store.put("mbox/a/evt/2", "e2");
  await store.put("mbox/a/meta", "meta");
  await store.put("mbox/b/evt/1", "e3");

  const { items } = await store.list("mbox/a/evt/");
  assert.equal(items.length, 2);
  assert.equal(items[0].key, "mbox/a/evt/1");
  assert.equal(items[1].key, "mbox/a/evt/2");
});

test("MemoryDataStore — list returns sorted keys", async () => {
  const store = new MemoryDataStore();
  await store.put("c", 3);
  await store.put("a", 1);
  await store.put("b", 2);

  const { items } = await store.list("");
  assert.deepEqual(items.map((i) => i.key), ["a", "b", "c"]);
});

test("MemoryDataStore — list with reverse", async () => {
  const store = new MemoryDataStore();
  await store.put("a", 1);
  await store.put("b", 2);
  await store.put("c", 3);

  const { items } = await store.list("", { reverse: true });
  assert.deepEqual(items.map((i) => i.key), ["c", "b", "a"]);
});

test("MemoryDataStore — list with limit and cursor", async () => {
  const store = new MemoryDataStore();
  for (let i = 0; i < 5; i++) {
    await store.put(`k${i}`, i);
  }

  const page1 = await store.list("", { limit: 2 });
  assert.equal(page1.items.length, 2);
  assert.equal(page1.items[0].key, "k0");
  assert.equal(page1.items[1].key, "k1");
  assert.equal(page1.nextCursor, "k1");

  const page2 = await store.list("", { limit: 2, cursor: page1.nextCursor });
  assert.equal(page2.items.length, 2);
  assert.equal(page2.items[0].key, "k2");
  assert.equal(page2.items[1].key, "k3");

  const page3 = await store.list("", { limit: 2, cursor: page2.nextCursor });
  assert.equal(page3.items.length, 1);
  assert.equal(page3.nextCursor, null);
});

test("MemoryDataStore — list empty prefix returns all", async () => {
  const store = new MemoryDataStore();
  await store.put("x", 1);
  await store.put("y", 2);
  const { items } = await store.list();
  assert.equal(items.length, 2);
});

test("MemoryDataStore — put rejects non-string key", async () => {
  const store = new MemoryDataStore();
  await assert.rejects(() => store.put(123, "v"), /non-empty string key/);
  await assert.rejects(() => store.put("", "v"), /non-empty string key/);
});
