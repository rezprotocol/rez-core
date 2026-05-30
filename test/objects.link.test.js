import test from "node:test";
import assert from "node:assert/strict";
import { Link } from "../src/objects/Link.js";

test("Link round-trip toJSON/fromJSON", () => {
  const link1 = new Link({ rel: "repliesTo", target: "abc", meta: { hop: 1 } });
  const json = link1.toJSON();
  const link2 = Link.fromJSON(json);

  assert.deepEqual(link2.toJSON(), json);
});
