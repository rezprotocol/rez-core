import test from "node:test";
import assert from "node:assert/strict";

import { RResource } from "../src/capability/RResource.js";

test("RResource — construct and seal", () => {
  const r = new RResource({ kind: "mailbox", id: "abc123" });
  assert.equal(r.type, "RResource");
  assert.equal(r.kind, "mailbox");
  assert.equal(r.id, "abc123");
});

test("RResource — toString", () => {
  const r = RResource.mailbox("inbox_001");
  assert.equal(r.toString(), "mailbox:inbox_001");
});

test("RResource — parse valid", () => {
  const r = RResource.parse("channel:room42");
  assert.equal(r.kind, "channel");
  assert.equal(r.id, "room42");
});

test("RResource — parse with colon in id", () => {
  const r = RResource.parse("object:urn:uuid:12345");
  assert.equal(r.kind, "object");
  assert.equal(r.id, "urn:uuid:12345");
});

test("RResource — parse rejects invalid format", () => {
  assert.throws(() => RResource.parse("nocolon"), /invalid format/);
  assert.throws(() => RResource.parse(123), /requires a string/);
});

test("RResource — factory methods", () => {
  const m = RResource.mailbox("m1");
  assert.equal(m.kind, "mailbox");
  assert.equal(m.id, "m1");

  const c = RResource.channel("c1");
  assert.equal(c.kind, "channel");
  assert.equal(c.id, "c1");

  const o = RResource.object("o1");
  assert.equal(o.kind, "object");
  assert.equal(o.id, "o1");
});

test("RResource — validates kind", () => {
  assert.throws(() => new RResource({ kind: "invalid", id: "x" }), /must be one of/);
  assert.throws(() => new RResource({ kind: "", id: "x" }), /must be one of/);
});

test("RResource — validates id", () => {
  assert.throws(() => new RResource({ kind: "mailbox", id: "" }), /non-empty string/);
  assert.throws(() => new RResource({ kind: "mailbox", id: 123 }), /non-empty string/);
  assert.throws(() => new RResource({ kind: "mailbox", id: "x".repeat(513) }), /at most 512/);
});

test("RResource — toJSON / fromJSON round-trip", () => {
  const r = RResource.mailbox("test_id");
  const json = r.toJSON();
  assert.deepEqual(json, { kind: "mailbox", id: "test_id" });

  const restored = RResource.fromJSON(json);
  assert.equal(restored.kind, "mailbox");
  assert.equal(restored.id, "test_id");
});

test("RResource — KINDS constant", () => {
  assert.equal(RResource.KINDS.MAILBOX, "mailbox");
  assert.equal(RResource.KINDS.CHANNEL, "channel");
  assert.equal(RResource.KINDS.OBJECT, "object");
  assert.ok(Object.isFrozen(RResource.KINDS));
});

test("RResource — is frozen after construction", () => {
  const r = RResource.mailbox("frozen");
  assert.throws(() => { r.id = "changed"; }, TypeError);
});
