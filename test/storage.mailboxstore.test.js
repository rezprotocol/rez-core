import test from "node:test";
import assert from "node:assert/strict";
import { MemoryMailboxStore } from "../src/storage/memory/MemoryMailboxStore.js";

test("MemoryMailboxStore append/list ordering", () => {
  const store = new MemoryMailboxStore();

  store.append("mb1", "a");
  store.append("mb1", "b");

  assert.deepEqual(store.list("mb1"), ["a", "b"]);
});

test("MemoryMailboxStore list returns copy", () => {
  const store = new MemoryMailboxStore();
  store.append("mb1", "a");

  const list = store.list("mb1");
  list.push("b");

  assert.deepEqual(store.list("mb1"), ["a"]);
});

test("MemoryMailboxStore deleteMailbox returns boolean", () => {
  const store = new MemoryMailboxStore();
  store.append("mb1", "a");

  assert.equal(store.deleteMailbox("mb1"), true);
  assert.equal(store.deleteMailbox("mb1"), false);
});
