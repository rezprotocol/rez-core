import test from "node:test";
import assert from "node:assert/strict";

import { RObjectStore } from "../src/objectstore/RObjectStore.js";
import { MemoryDataStore } from "../src/storage/memory/MemoryDataStore.js";

function createStore() {
  return new RObjectStore({ store: new MemoryDataStore() });
}

test("RObjectStore — constructor requires RDataStore", () => {
  assert.throws(() => new RObjectStore({}), /requires store/);
  assert.throws(() => new RObjectStore({ store: {} }), /requires store/);
});

test("RObjectStore — publish and get", async () => {
  const store = createStore();
  const result = await store.publish("res_1", "obj_1", "Y2lwaGVydGV4dA==", { contentType: "text/plain" });
  assert.equal(result.objectId, "obj_1");
  assert.ok(result.createdAtMs > 0);

  const obj = await store.get("res_1", "obj_1");
  assert.equal(obj.objectId, "obj_1");
  assert.equal(obj.ciphertextB64, "Y2lwaGVydGV4dA==");
  assert.deepEqual(obj.metadata, { contentType: "text/plain" });
  assert.ok(obj.createdAtMs > 0);
});

test("RObjectStore — get returns null for unknown", async () => {
  const store = createStore();
  assert.equal(await store.get("res_1", "nope"), null);
});

test("RObjectStore — list objects", async () => {
  const store = createStore();
  await store.publish("res_1", "obj_a", "AAAA", {});
  await store.publish("res_1", "obj_b", "BBBB", {});
  await store.publish("res_1", "obj_c", "CCCC", {});

  const { items } = await store.list("res_1");
  assert.equal(items.length, 3);
  assert.equal(items[0].objectId, "obj_a");
  assert.equal(items[1].objectId, "obj_b");
  assert.equal(items[2].objectId, "obj_c");
});

test("RObjectStore — list with limit and cursor pagination", async () => {
  const store = createStore();
  await store.publish("res_1", "obj_a", "AAAA", {});
  await store.publish("res_1", "obj_b", "BBBB", {});
  await store.publish("res_1", "obj_c", "CCCC", {});

  const page1 = await store.list("res_1", { limit: 2 });
  assert.equal(page1.items.length, 2);
  assert.ok(page1.nextCursor);

  const page2 = await store.list("res_1", { cursor: page1.nextCursor, limit: 2 });
  assert.equal(page2.items.length, 1);
  assert.equal(page2.items[0].objectId, "obj_c");
});

test("RObjectStore — resources are isolated", async () => {
  const store = createStore();
  await store.publish("res_1", "obj_1", "AAAA", {});
  await store.publish("res_2", "obj_2", "BBBB", {});

  const { items: items1 } = await store.list("res_1");
  const { items: items2 } = await store.list("res_2");

  assert.equal(items1.length, 1);
  assert.equal(items1[0].objectId, "obj_1");
  assert.equal(items2.length, 1);
  assert.equal(items2[0].objectId, "obj_2");
});

test("RObjectStore — delete removes object", async () => {
  const store = createStore();
  await store.publish("res_1", "obj_1", "AAAA", {});
  assert.equal(await store.delete("res_1", "obj_1"), true);
  assert.equal(await store.get("res_1", "obj_1"), null);
});

test("RObjectStore — delete returns false for missing", async () => {
  const store = createStore();
  assert.equal(await store.delete("res_1", "nope"), false);
});

test("RObjectStore — has returns true/false", async () => {
  const store = createStore();
  assert.equal(await store.has("res_1", "obj_1"), false);
  await store.publish("res_1", "obj_1", "AAAA", {});
  assert.equal(await store.has("res_1", "obj_1"), true);
});

test("RObjectStore — publish overwrites existing object", async () => {
  const store = createStore();
  await store.publish("res_1", "obj_1", "AAAA", { v: 1 });
  await store.publish("res_1", "obj_1", "BBBB", { v: 2 });

  const obj = await store.get("res_1", "obj_1");
  assert.equal(obj.ciphertextB64, "BBBB");
  assert.deepEqual(obj.metadata, { v: 2 });
});

test("RObjectStore — rejects empty resourceId", async () => {
  const store = createStore();
  await assert.rejects(() => store.publish("", "obj", "AA", {}), /non-empty.*resourceId/);
  await assert.rejects(() => store.get("", "obj"), /non-empty.*resourceId/);
  await assert.rejects(() => store.list(""), /non-empty.*resourceId/);
  await assert.rejects(() => store.delete("", "obj"), /non-empty.*resourceId/);
  await assert.rejects(() => store.has("", "obj"), /non-empty.*resourceId/);
});

test("RObjectStore — rejects empty objectId", async () => {
  const store = createStore();
  await assert.rejects(() => store.publish("res", "", "AA", {}), /non-empty.*objectId/);
  await assert.rejects(() => store.get("res", ""), /non-empty.*objectId/);
  await assert.rejects(() => store.delete("res", ""), /non-empty.*objectId/);
  await assert.rejects(() => store.has("res", ""), /non-empty.*objectId/);
});

test("RObjectStore — rejects empty ciphertextB64", async () => {
  const store = createStore();
  await assert.rejects(() => store.publish("res", "obj", "", {}), /non-empty.*ciphertextB64/);
  await assert.rejects(() => store.publish("res", "obj", null, {}), /non-empty.*ciphertextB64/);
});

test("RObjectStore — publish defaults metadata to empty object", async () => {
  const store = createStore();
  await store.publish("res_1", "obj_1", "AAAA");
  const obj = await store.get("res_1", "obj_1");
  assert.deepEqual(obj.metadata, {});
});
