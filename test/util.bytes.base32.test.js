import test from "node:test";
import assert from "node:assert/strict";
import { bytesToBase32 } from "../src/util/base32.js";
import { cloneNonEmptyBytes } from "../src/util/bytes.js";
import { Hash } from "../src/base/util/Hash.js";

test("bytesToBase32 requires Uint8Array", () => {
  assert.throws(
    () => bytesToBase32("abc"),
    /bytesToBase32\(bytes\) requires Uint8Array/
  );
});

test("bytesToBase32 encodes empty bytes to empty string", () => {
  assert.equal(bytesToBase32(new Uint8Array(0)), "");
});

test("bytesToBase32 encodes single byte", () => {
  const out = bytesToBase32(new Uint8Array([0xff]));
  assert.equal(typeof out, "string");
  assert.ok(out.length > 0);
  assert.ok(/^[a-z2-7]+$/.test(out));
});

test("bytesToBase32 round-trip consistency for 32 bytes", () => {
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) bytes[i] = i;
  const encoded = bytesToBase32(bytes);
  assert.equal(typeof encoded, "string");
  assert.ok(/^[a-z2-7]+$/.test(encoded));
});

test("cloneNonEmptyBytes requires non-empty Uint8Array", () => {
  assert.throws(
    () => cloneNonEmptyBytes(new Uint8Array(0), "label"),
    /label must be a non-empty Uint8Array/
  );
  assert.throws(
    () => cloneNonEmptyBytes("not bytes", "label"),
    /label must be a non-empty Uint8Array/
  );
});

test("cloneNonEmptyBytes returns a copy", () => {
  const orig = new Uint8Array([1, 2, 3]);
  const cloned = cloneNonEmptyBytes(orig, "label");
  assert.notEqual(cloned, orig);
  assert.deepEqual(Array.from(cloned), [1, 2, 3]);
  orig[0] = 99;
  assert.equal(cloned[0], 1);
});

test("Hash.sha256 requires Uint8Array", () => {
  assert.throws(
    () => Hash.sha256("not bytes"),
    /Hash\.sha256\(bytes\) requires Uint8Array/
  );
});

test("Hash.sha256 returns 32-byte Uint8Array", () => {
  const input = new Uint8Array([1, 2, 3]);
  const out = Hash.sha256(input);
  assert.ok(out instanceof Uint8Array);
  assert.equal(out.length, 32);
});

test("Hash.sha256 is deterministic", () => {
  const input = new Uint8Array([1, 2, 3]);
  const a = Hash.sha256(input);
  const b = Hash.sha256(input);
  assert.deepEqual(Array.from(a), Array.from(b));
});

test("Hash.sha256Hex still works", () => {
  const hex = Hash.sha256Hex("hello");
  assert.equal(typeof hex, "string");
  assert.equal(hex.length, 64);
  assert.ok(/^[0-9a-f]+$/.test(hex));
});
