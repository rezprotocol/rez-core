import test from "node:test";
import assert from "node:assert/strict";
import { Body } from "../src/objects/Body.js";

test("Body is abstract", () => {
  assert.throws(() => new Body(), /Body is abstract/);
});
