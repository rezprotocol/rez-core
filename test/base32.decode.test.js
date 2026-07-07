import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import { bytesToBase32, base32ToBytes } from "../src/util/base32.js";

// S10 P1 — the strict base32 decoder for the device-link code's PSK segment.
// Strictness is load-bearing: a forgiving decoder would let distinct strings
// decode to the same 32-byte secret, breaking canonical-string comparisons.

test("round-trips every byte length 0..64 (random content)", () => {
  for (let len = 0; len <= 64; len += 1) {
    const bytes = new Uint8Array(crypto.randomBytes(len));
    const encoded = bytesToBase32(bytes);
    assert.deepEqual(base32ToBytes(encoded), bytes, "length " + len);
  }
});

test("round-trips edge contents (all-zero, all-0xff)", () => {
  for (const fill of [0x00, 0xff]) {
    const bytes = new Uint8Array(32).fill(fill);
    assert.deepEqual(base32ToBytes(bytesToBase32(bytes)), bytes);
  }
});

test("rejects characters outside the alphabet", () => {
  const good = bytesToBase32(new Uint8Array(crypto.randomBytes(32)));
  assert.throws(() => base32ToBytes(good.slice(0, -1) + "0"), /invalid character/); // "0" not in alphabet
  assert.throws(() => base32ToBytes(good.slice(0, -1) + "A"), /invalid character/); // uppercase not in alphabet
  assert.throws(() => base32ToBytes(good + "!"), /invalid character|non-canonical length/);
});

test("rejects lengths that cannot come from whole bytes", () => {
  // Valid base32 lengths are ceil(8n/5) — lengths ≡ 1, 3, or 6 (mod 8) can
  // never come from whole bytes. 32 bytes encode to 52 chars.
  const good = bytesToBase32(new Uint8Array(crypto.randomBytes(32)));
  assert.equal(good.length, 52);
  assert.throws(() => base32ToBytes(good.slice(0, 51)), /non-canonical length/); // 51 ≡ 3 (mod 8)
  assert.throws(() => base32ToBytes(good.slice(0, 49)), /non-canonical length/); // 49 ≡ 1 (mod 8)
  assert.throws(() => base32ToBytes(good.slice(0, 46)), /non-canonical length/); // 46 ≡ 6 (mod 8)
  // A 1-char string carries only 5 bits — no whole byte.
  assert.throws(() => base32ToBytes("a"), /non-canonical length/);
});

test("rejects non-canonical trailing bits", () => {
  // 1 byte encodes to 2 chars with 2 trailing zero bits in the second char.
  // Flip those bits: same length, decodes to the same byte under a lax
  // decoder, but the string is not what the encoder would emit.
  const one = bytesToBase32(new Uint8Array([0xff])); // "74": 11111 11(000)
  assert.equal(base32ToBytes(one)[0], 0xff);
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  const lastIdx = alphabet.indexOf(one[1]);
  const tampered = one[0] + alphabet[lastIdx | 1]; // set a trailing bit
  assert.notEqual(tampered, one);
  assert.throws(() => base32ToBytes(tampered), /non-canonical trailing bits/);
});

test("rejects non-string input", () => {
  assert.throws(() => base32ToBytes(null), /requires a string/);
  assert.throws(() => base32ToBytes(42), /requires a string/);
});

test("empty string decodes to empty bytes", () => {
  assert.deepEqual(base32ToBytes(""), new Uint8Array(0));
});
