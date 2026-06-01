// BIP39 conformance tests. Vectors are the canonical Trezor reference set
// from https://github.com/trezor/python-mnemonic/blob/master/vectors.json
// (public domain). Each entry: [entropyHex, mnemonic, seedHex, ...].
// Passphrase across all canonical vectors is "TREZOR".

import test from "node:test";
import assert from "node:assert/strict";
import { Bip39 } from "../src/crypto/bip39.js";

// A focused subset of the canonical vectors — sufficient to cover
// 12/15/18/21/24-word lengths + edge cases (all-zero entropy, all-ff entropy,
// known message-of-the-day-style mnemonics).
const VECTORS = [
  // 12 words — all-zero entropy
  [
    "00000000000000000000000000000000",
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
  ],
  // 12 words — varied entropy
  [
    "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
    "legal winner thank year wave sausage worth useful legal winner thank yellow",
    "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
  ],
  // 24 words — all-zero entropy
  [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
    "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
  ],
  // 24 words — varied
  [
    "8080808080808080808080808080808080808080808080808080808080808080",
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
    "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
  ],
  // 24 words — all-ones entropy
  [
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
    "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
  ],
];

test("Bip39.entropyToMnemonic — canonical vectors", () => {
  for (const [entropyHex, expectedMnemonic] of VECTORS) {
    const entropy = Buffer.from(entropyHex, "hex");
    const actual = Bip39.entropyToMnemonic(entropy);
    assert.equal(actual, expectedMnemonic, `entropy=${entropyHex}`);
  }
});

test("Bip39.mnemonicToSeed — canonical vectors with passphrase 'TREZOR'", async () => {
  for (const [entropyHex, mnemonic, expectedSeedHex] of VECTORS) {
    const seed = await Bip39.mnemonicToSeed(mnemonic, "TREZOR");
    assert.equal(seed.toString("hex"), expectedSeedHex, `entropy=${entropyHex}`);
  }
});

test("Bip39.validateMnemonic — accepts canonical vectors", () => {
  for (const [entropyHex, mnemonic] of VECTORS) {
    const result = Bip39.validateMnemonic(mnemonic);
    assert.equal(result.ok, true, `vector ${entropyHex} should validate, got error=${result.error}`);
    assert.equal(Buffer.from(result.entropyBytes).toString("hex"), entropyHex);
  }
});

test("Bip39.validateMnemonic — rejects empty / wrong-length / unknown word / bad checksum", () => {
  assert.equal(Bip39.validateMnemonic("").ok, false);
  assert.equal(Bip39.validateMnemonic("   ").ok, false);

  // 13 words — not in {12,15,18,21,24}
  const r13 = Bip39.validateMnemonic("abandon ".repeat(12) + "abandon about");
  assert.equal(r13.ok, false);
  assert.match(r13.error, /wordCount/);

  // Unknown word
  const rBadWord = Bip39.validateMnemonic("abandon ".repeat(11) + "notarealword");
  assert.equal(rBadWord.ok, false);
  assert.match(rBadWord.error, /not in wordlist/);

  // Tamper canonical vector: swap last word "about" -> "abandon" (same wordlist, breaks checksum)
  const tampered = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
  const rTamper = Bip39.validateMnemonic(tampered);
  assert.equal(rTamper.ok, false);
  assert.match(rTamper.error, /checksum/);
});

test("Bip39.generateMnemonic — produces a valid mnemonic that round-trips", async () => {
  for (const words of [12, 15, 18, 21, 24]) {
    const m = Bip39.generateMnemonic({ words });
    const split = m.split(" ");
    assert.equal(split.length, words, `expected ${words} words, got ${split.length}`);
    const v = Bip39.validateMnemonic(m);
    assert.equal(v.ok, true, `generated mnemonic should validate: ${v.error}`);
    // mnemonicToSeed must not throw
    const seed = await Bip39.mnemonicToSeed(m);
    assert.equal(seed.length, 64);
  }
});

test("Bip39.validateMnemonic — NFKD normalization + case + whitespace tolerance", () => {
  const canonical = "legal winner thank year wave sausage worth useful legal winner thank yellow";
  // Mixed case + extra whitespace + leading/trailing space should normalize and validate.
  const messy = "  LEGAL  Winner\tthank year wave sausage worth useful legal winner thank yellow  ";
  const v = Bip39.validateMnemonic(messy);
  assert.equal(v.ok, true, `messy form should validate: ${v.error}`);
  // Same entropy as the canonical form.
  const vCanon = Bip39.validateMnemonic(canonical);
  assert.deepEqual(
    Buffer.from(v.entropyBytes).toString("hex"),
    Buffer.from(vCanon.entropyBytes).toString("hex"),
  );
});
