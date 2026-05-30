import test from "node:test";
import assert from "node:assert/strict";
import { Header } from "../src/objects/Header.js";
import { Envelope } from "../src/objects/Envelope.js";

test("Envelope round-trip toJSON/fromJSON", () => {
  const header = new Header({ id: "1", type: "message", createdAt: 1 });
  const e1 = new Envelope({ header, body: { hello: "world" }, meta: { hop: 2 } });

  const json = e1.toJSON();
  const e2 = Envelope.fromJSON(json);

  assert.deepEqual(e2.toJSON(), json);
});

test("Envelope requires header and body", () => {
  const header = new Header({ id: "1", type: "message", createdAt: 1 });
  assert.throws(() => new Envelope({ body: {} }), /Envelope\.header/);
  assert.throws(() => new Envelope({ header }), /Envelope\.body/);
});

test("Envelope.meta must be a plain object if provided", () => {
  const header = new Header({ id: "1", type: "message", createdAt: 1 });
  assert.throws(() => new Envelope({ header, body: {}, meta: [] }), /Envelope\.meta/);
});
