import test from "node:test";
import assert from "node:assert/strict";
import { MemoryKeyValueStore } from "../src/storage/memory/MemoryKeyValueStore.js";

test("MemoryKeyValueStore set/get/delete", () => {
  const store = new MemoryKeyValueStore();

  store.set("a", { ok: true });
  assert.deepEqual(store.get("a"), { ok: true });
  assert.equal(store.delete("a"), true);
  assert.equal(store.get("a"), undefined);
});

test("MemoryKeyValueStore keys filters by prefix", () => {
  const store = new MemoryKeyValueStore();

  store.set("a/1", 1);
  store.set("a/2", 2);
  store.set("b/1", 3);

  assert.deepEqual(store.keys("a/"), ["a/1", "a/2"]);
});
