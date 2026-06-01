// Pin the BIP39 English wordlist to its canonical published form so that
// accidental edits, encoding corruption, or supply-chain tampering of
// bip39Wordlist.js fail CI.
//
// The canonical SHA-256 below is computed over the joined wordlist bytes
// (words separated by single '\n', NO trailing newline). This matches the
// derivation used in scripts/generate (see the comment header in
// src/crypto/bip39Wordlist.js for the original-file hash).

import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { BIP39_ENGLISH as DIRECT } from "../src/crypto/bip39Wordlist.js";

const CANONICAL_JOINED_SHA256 = "187db04a869dd9bc7be80d21a86497d692c0db6abd3aa8cb6be5d618ff757fae";

test("BIP39 English wordlist is exactly 2048 entries", () => {
  assert.equal(DIRECT.length, 2048);
});

test("BIP39 English wordlist hashes match canonical published value", () => {
  const joined = DIRECT.join("\n");
  const hash = createHash("sha256").update(joined, "utf8").digest("hex");
  assert.equal(
    hash,
    CANONICAL_JOINED_SHA256,
    "Wordlist has been modified. If this change is intentional, recompute the hash from the canonical bitcoin/bips english.txt and update this test plus the comment in bip39Wordlist.js.",
  );
});

test("BIP39 English wordlist is frozen and all-lowercase ASCII", () => {
  assert.equal(Object.isFrozen(DIRECT), true);
  for (let i = 0; i < DIRECT.length; i += 1) {
    const w = DIRECT[i];
    if (!/^[a-z]+$/.test(w)) {
      assert.fail(`word at index ${i} is not pure lowercase ASCII: "${w}"`);
    }
  }
});
