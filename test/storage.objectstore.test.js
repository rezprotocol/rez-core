import test from "node:test";
import assert from "node:assert/strict";
import { Header } from "../src/objects/Header.js";
import { Envelope } from "../src/objects/Envelope.js";
import { MemoryObjectStore } from "../src/storage/memory/MemoryObjectStore.js";

test("MemoryObjectStore put/get round-trip", () => {
  const store = new MemoryObjectStore();
  const header = new Header({ id: "obj-1", type: "message", createdAt: 1 });
  const envelope = new Envelope({ header, body: { hello: "world" } });

  store.put(envelope);
  const loaded = store.get("obj-1");

  assert.deepEqual(loaded?.toJSON(), envelope.toJSON());
});

test("MemoryObjectStore has/delete/listIds", () => {
  const store = new MemoryObjectStore();
  const header = new Header({ id: "obj-2", type: "message", createdAt: 1 });
  const envelope = new Envelope({ header, body: { ok: true } });

  assert.equal(store.has("obj-2"), false);
  store.put(envelope);
  assert.equal(store.has("obj-2"), true);
  assert.deepEqual(store.listIds(), ["obj-2"]);
  assert.equal(store.delete("obj-2"), true);
  assert.equal(store.has("obj-2"), false);
});
