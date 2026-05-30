import test from "node:test";
import assert from "node:assert/strict";

import { RCodec } from "@rezprotocol/core";
import { RSerializable } from "@rezprotocol/core";
import { RAbstract, RObject } from "@rezprotocol/core";


test("RObject.type is set", () => {
  const base = new RObject();
  assert.equal(base.type, "RObject");

  class Custom extends RObject {
    static type = "CustomType";
  }

  const custom = new Custom();
  assert.equal(custom.type, "CustomType");
});


test("RAbstract.abstract throws", () => {
  const obj = new RAbstract();
  assert.throws(
    () => obj.abstract("doThing"),
    (err) => err?.name === "RezAbstractError"
  );
});


test("RSerializable requires toJSON/fromJSON", () => {
  class Thing extends RSerializable {}

  const instance = new Thing();
  assert.throws(
    () => instance.toJSON(),
    (err) => err?.name === "RezAbstractError"
  );

  assert.throws(
    () => Thing.fromJSON({}),
    /must implement static fromJSON\(json\)/
  );
});


test("RCodec encode/decode are abstract", () => {
  const codec = new RCodec();

  assert.throws(
    () => codec.encode({}),
    (err) => err?.name === "RezAbstractError"
  );

  assert.throws(
    () => codec.decode({}),
    (err) => err?.name === "RezAbstractError"
  );
});
