import test from "node:test";
import assert from "node:assert/strict";
import { canonicalize, canonicalJSONStringify } from "../src/util/canonicalize.js";

test("canonicalize sorts object keys", () => {
  const out = canonicalize({ b: 1, a: 2 });
  assert.deepEqual(Object.keys(out), ["a", "b"]);
});

test("canonicalize sorts nested keys", () => {
  const out = canonicalize({ z: { b: 1, a: 2 }, a: 0 });
  assert.deepEqual(Object.keys(out), ["a", "z"]);
  assert.deepEqual(Object.keys(out.z), ["a", "b"]);
});

test("canonicalize preserves array ordering", () => {
  const out = canonicalize({ a: [{ b: 2, a: 1 }] });
  // only check that it didn't reorder array items and it canonicalized object keys inside
  assert.equal(Array.isArray(out.a), true);
  assert.deepEqual(Object.keys(out.a[0]), ["a", "b"]);
});

test("canonicalJSONStringify returns deterministic string", () => {
  const s1 = canonicalJSONStringify({ b: 1, a: 2 });
  const s2 = canonicalJSONStringify({ a: 2, b: 1 });
  assert.equal(s1, s2);
});
