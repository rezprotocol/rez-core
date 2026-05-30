import test from "node:test";
import assert from "node:assert/strict";
import { Header } from "../src/objects/Header.js";
import { Link } from "../src/objects/Link.js";

test("Header round-trip toJSON/fromJSON", () => {
  const h1 = new Header({
    id: "abc",
    type: "message",
    createdAt: 1234567890,
    links: [new Link({ rel: "repliesTo", target: "xyz" })],
  });

  const json = h1.toJSON();
  const h2 = Header.fromJSON(json);

  assert.deepEqual(h2.toJSON(), json);
});

test("Header requires id/type/createdAt", () => {
  assert.throws(() => new Header({ type: "x", createdAt: 1 }), /Header\.id/);
  assert.throws(() => new Header({ id: "x", createdAt: 1 }), /Header\.type/);
  assert.throws(() => new Header({ id: "x", type: "y", createdAt: NaN }), /Header\.createdAt/);
});

test("Header validates links shape", () => {
  assert.throws(() => new Header({ id: "x", type: "y", createdAt: 1, links: "nope" }), /Header\.links/);
  assert.throws(
    () => new Header({ id: "x", type: "y", createdAt: 1, links: [{ rel: "a" }] }),
    /Header\.links entries must be Link/
  );
});

test("Header accepts legacy-ish plain objects in fromJSON", () => {
  const json = {
    id: "x",
    type: "y",
    createdAt: 1,
    links: [{ rel: "repliesTo", target: "z" }],
  };

  const header = Header.fromJSON(json);
  assert.deepEqual(header.toJSON(), {
    schemaVersion: Header.schemaVersion,
    id: "x",
    type: "y",
    createdAt: 1,
    links: [{ schemaVersion: Link.schemaVersion, rel: "repliesTo", target: "z", meta: undefined }],
  });
});
