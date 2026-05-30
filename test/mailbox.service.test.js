import test from "node:test";
import assert from "node:assert/strict";

import { RMailbox } from "../src/mailbox/RMailbox.js";
import { AppDepositRecord } from "../src/mailbox/AppDepositRecord.js";
import { OuterPacketRecord } from "../src/packets/OuterPacketRecord.js";
import { encodeOuterPacket } from "../src/packets/OuterPacket.js";
import { MemoryDataStore } from "../src/storage/memory/MemoryDataStore.js";
import { createDefaultRegistry } from "../src/mailbox/createDefaultRegistry.js";

function createMailbox() {
  return new RMailbox({ store: new MemoryDataStore(), registry: createDefaultRegistry() });
}

function makeOuterRecord(bodyBytes) {
  const wireBytes = encodeOuterPacket({
    bodyBytes: bodyBytes || new Uint8Array([1, 2, 3]),
  });
  return OuterPacketRecord.fromBytes(wireBytes);
}

function makeAppRecord(objectId, payloadBytes) {
  return new AppDepositRecord({
    objectId: objectId || "obj_test",
    payloadBytes: payloadBytes || new Uint8Array([1, 2, 3]),
  });
}

test("RMailbox — constructor requires RDataStore", () => {
  assert.throws(() => new RMailbox({}), /requires store/);
  assert.throws(() => new RMailbox({ store: {} }), /requires store/);
});

test("RMailbox — createMailbox and getMailboxMeta", async () => {
  const mbox = createMailbox();
  await mbox.createMailbox("inbox_001", { visibility: "private", ownerAccountId: "rez:acct:alice" });

  const meta = await mbox.getMailboxMeta("inbox_001");
  assert.equal(meta.visibility, "private");
  assert.equal(meta.ownerAccountId, "rez:acct:alice");
  assert.ok(meta.createdAtMs > 0);
});

test("RMailbox — getMailboxMeta returns null for unknown", async () => {
  const mbox = createMailbox();
  assert.equal(await mbox.getMailboxMeta("nope"), null);
});

test("RMailbox — createMailbox defaults to private", async () => {
  const mbox = createMailbox();
  await mbox.createMailbox("m1");
  const meta = await mbox.getMailboxMeta("m1");
  assert.equal(meta.visibility, "private");
});

test("RMailbox — deposit and fetch with AppDepositRecord", async () => {
  const mbox = createMailbox();
  await mbox.createMailbox("m1");

  const record = makeAppRecord("obj_1", new Uint8Array([1, 2, 3]));
  const eventId = await mbox.deposit("m1", record);
  assert.ok(typeof eventId === "string" && eventId.length > 0);

  const evt = await mbox.fetch("m1", eventId);
  assert.equal(evt.objectId, "obj_1");
  assert.equal(evt.metadata.contentType, "rez.app.deposit");
  assert.ok(evt.createdAt > 0);
});

test("RMailbox — deposit and fetch with OuterPacketRecord", async () => {
  const mbox = createMailbox();
  await mbox.createMailbox("m1");

  const record = makeOuterRecord(new Uint8Array([42]));
  const eventId = await mbox.deposit("m1", record);
  assert.ok(typeof eventId === "string" && eventId.length > 0);

  const evt = await mbox.fetch("m1", eventId);
  assert.equal(evt.metadata.contentType, "rez.outer");
  assert.ok(evt.bytes instanceof Uint8Array || Array.isArray(evt.bytes));
});

test("RMailbox — fetch returns null for unknown", async () => {
  const mbox = createMailbox();
  assert.equal(await mbox.fetch("m1", "nope"), null);
});

test("RMailbox — list events", async () => {
  const mbox = createMailbox();
  await mbox.createMailbox("m1");

  await mbox.deposit("m1", makeAppRecord("obj_1", new Uint8Array([1])));
  await mbox.deposit("m1", makeAppRecord("obj_2", new Uint8Array([2])));
  await mbox.deposit("m1", makeAppRecord("obj_3", new Uint8Array([3])));

  const { items } = await mbox.list("m1");
  assert.equal(items.length, 3);
  assert.equal(items[0].objectId, "obj_1");
  assert.equal(items[2].objectId, "obj_3");
});

test("RMailbox — list with limit", async () => {
  const mbox = createMailbox();
  await mbox.createMailbox("m1");

  await mbox.deposit("m1", makeOuterRecord(new Uint8Array([1])));
  await mbox.deposit("m1", makeOuterRecord(new Uint8Array([2])));
  await mbox.deposit("m1", makeOuterRecord(new Uint8Array([3])));

  const page1 = await mbox.list("m1", { limit: 2 });
  assert.equal(page1.items.length, 2);
  assert.ok(page1.nextCursor);

  const page2 = await mbox.list("m1", { cursor: page1.nextCursor, limit: 2 });
  assert.equal(page2.items.length, 1);
});

test("RMailbox — ack removes event", async () => {
  const mbox = createMailbox();
  await mbox.createMailbox("m1");

  const eventId = await mbox.deposit("m1", makeAppRecord("obj_1"));
  assert.equal(await mbox.ack("m1", eventId), true);
  assert.equal(await mbox.fetch("m1", eventId), null);
});

test("RMailbox — ack returns false for missing", async () => {
  const mbox = createMailbox();
  assert.equal(await mbox.ack("m1", "nope"), false);
});

test("RMailbox — waitForDeposit resolves on deposit", async () => {
  const mbox = createMailbox();
  await mbox.createMailbox("m1");

  const waitPromise = mbox.waitForDeposit("m1", { timeoutMs: 5000 });

  setTimeout(async () => {
    await mbox.deposit("m1", makeAppRecord("obj_late", new Uint8Array([99])));
  }, 50);

  const item = await waitPromise;
  assert.equal(item.objectId, "obj_late");
});

test("RMailbox — waitForDeposit times out", async () => {
  const mbox = createMailbox();
  await assert.rejects(
    () => mbox.waitForDeposit("m1", { timeoutMs: 50 }),
    /timeout/
  );
});

test("RMailbox — multiple mailboxes are isolated", async () => {
  const mbox = createMailbox();
  await mbox.createMailbox("m1");
  await mbox.createMailbox("m2");

  await mbox.deposit("m1", makeAppRecord("obj_1", new Uint8Array([1])));
  await mbox.deposit("m2", makeAppRecord("obj_2", new Uint8Array([2])));

  const { items: items1 } = await mbox.list("m1");
  const { items: items2 } = await mbox.list("m2");

  assert.equal(items1.length, 1);
  assert.equal(items1[0].objectId, "obj_1");
  assert.equal(items2.length, 1);
  assert.equal(items2[0].objectId, "obj_2");
});

test("RMailbox — VISIBILITY constant", () => {
  assert.equal(RMailbox.VISIBILITY.PRIVATE, "private");
  assert.equal(RMailbox.VISIBILITY.PUBLIC_READ, "public-read");
  assert.ok(Object.isFrozen(RMailbox.VISIBILITY));
});

test("RMailbox — CONTENT_TYPES constant", () => {
  assert.equal(RMailbox.CONTENT_TYPES.OUTER, "rez.outer");
  assert.equal(RMailbox.CONTENT_TYPES.APP_DEPOSIT, "rez.app.deposit");
  assert.ok(Object.isFrozen(RMailbox.CONTENT_TYPES));
});

test("RMailbox — public-read visibility", async () => {
  const mbox = createMailbox();
  await mbox.createMailbox("public_feed", { visibility: "public-read" });
  const meta = await mbox.getMailboxMeta("public_feed");
  assert.equal(meta.visibility, "public-read");
});

test("RMailbox — rejects empty mailboxId", async () => {
  const mbox = createMailbox();
  await assert.rejects(() => mbox.deposit("", makeAppRecord("obj")), /non-empty/);
  await assert.rejects(() => mbox.list(""), /non-empty/);
  await assert.rejects(() => mbox.fetch("", "evt"), /non-empty/);
  await assert.rejects(() => mbox.ack("", "evt"), /non-empty/);
});

test("RMailbox — deposit rejects non-record arguments", async () => {
  const mbox = createMailbox();
  await mbox.createMailbox("m1");

  // Raw bytes — not a record
  await assert.rejects(
    () => mbox.deposit("m1", new Uint8Array([1])),
    /requires record with toBytes/
  );

  // Plain object without toBytes
  await assert.rejects(
    () => mbox.deposit("m1", { contentType: "rez.outer.v1" }),
    /requires record with toBytes/
  );

  // Object with toBytes but wrong contentType
  await assert.rejects(
    () => mbox.deposit("m1", { toBytes() { return new Uint8Array([1]); }, contentType: "garbage" }),
    /requires record.contentType/
  );

  // Object with toBytes but no contentType
  await assert.rejects(
    () => mbox.deposit("m1", { toBytes() { return new Uint8Array([1]); } }),
    /requires record.contentType/
  );
});

test("RMailbox — OuterPacketRecord rejects invalid wire bytes", () => {
  assert.throws(() => OuterPacketRecord.fromBytes(new Uint8Array([0xff, 0x00])), /packet too short|invalid version/);
  assert.throws(() => OuterPacketRecord.fromBytes(new Uint8Array([])), /requires non-empty/);
});

test("RMailbox — AppDepositRecord rejects missing fields", () => {
  assert.throws(() => new AppDepositRecord({}), /requires non-empty string objectId/);
  assert.throws(() => new AppDepositRecord({ objectId: "x" }), /requires Uint8Array payloadBytes/);
});

test("RMailbox — setOnDeposit callback fires on deposit", async () => {
  const mbox = createMailbox();
  await mbox.createMailbox("m1");

  const calls = [];
  mbox.setOnDeposit((mailboxId, eventId) => {
    calls.push({ mailboxId, eventId });
  });

  const eventId = await mbox.deposit("m1", makeAppRecord("obj_cb"));
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(calls.length, 1);
  assert.equal(calls[0].mailboxId, "m1");
  assert.equal(calls[0].eventId, eventId);
});

test("RMailbox — setOnDeposit callback errors dont fail deposit", async () => {
  const mbox = createMailbox();
  await mbox.createMailbox("m1");

  mbox.setOnDeposit(() => { throw new Error("boom"); });

  const eventId = await mbox.deposit("m1", makeAppRecord("obj_err"));
  assert.ok(typeof eventId === "string");
});

test("RMailbox — setOnDeposit(null) clears callback", async () => {
  const mbox = createMailbox();
  await mbox.createMailbox("m1");

  const calls = [];
  mbox.setOnDeposit(() => calls.push(1));
  await mbox.deposit("m1", makeAppRecord("obj_a"));
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(calls.length, 1);

  mbox.setOnDeposit(null);
  await mbox.deposit("m1", makeAppRecord("obj_b"));
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(calls.length, 1);
});
