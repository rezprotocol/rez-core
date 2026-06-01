import test from "node:test";
import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { Bip39 } from "../src/crypto/bip39.js";
import { SeedKeys } from "../src/crypto/seedDerivation.js";

const FIXED_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

async function fixedSeed() {
  return Bip39.mnemonicToSeed(FIXED_MNEMONIC);
}

// SeedKeys.deriveEd25519 returns PKCS#8/SPKI DER bytes (matching Identity.toObject()),
// so these test helpers can rebuild KeyObjects with createPrivate/PublicKey directly.
function privKeyFromB64(privateKeyB64) {
  return createPrivateKey({ key: Buffer.from(privateKeyB64, "base64"), format: "der", type: "pkcs8" });
}

function pubKeyFromB64(publicKeyB64) {
  return createPublicKey({ key: Buffer.from(publicKeyB64, "base64"), format: "der", type: "spki" });
}

test("SeedKeys.deriveBytes — deterministic for same seed + label", async () => {
  const seed = await fixedSeed();
  const a = SeedKeys.deriveBytes({ seed, label: "rez/test/v1", length: 32 });
  const b = SeedKeys.deriveBytes({ seed, label: "rez/test/v1", length: 32 });
  assert.equal(a.toString("hex"), b.toString("hex"));
  assert.equal(a.length, 32);
});

test("SeedKeys.deriveBytes — different labels produce different bytes", async () => {
  const seed = await fixedSeed();
  const a = SeedKeys.deriveBytes({ seed, label: "rez/identity/desktop-account/v1" });
  const b = SeedKeys.deriveBytes({ seed, label: "rez/identity/chat-server/v1" });
  assert.notEqual(a.toString("hex"), b.toString("hex"));
});

test("SeedKeys.deriveEd25519 — deterministic + roundtrips sign/verify", async () => {
  const seed = await fixedSeed();
  const k1 = SeedKeys.deriveEd25519({ seed, label: "rez/identity/desktop-account/v1" });
  const k2 = SeedKeys.deriveEd25519({ seed, label: "rez/identity/desktop-account/v1" });
  assert.equal(k1.privateKeyB64, k2.privateKeyB64);
  assert.equal(k1.publicKeyB64, k2.publicKeyB64);
  // SPKI Ed25519 pubkey is 44 bytes; PKCS#8 Ed25519 privkey is 48 bytes.
  assert.equal(Buffer.from(k1.publicKeyB64, "base64").length, 44);
  assert.equal(Buffer.from(k1.privateKeyB64, "base64").length, 48);

  const msg = Buffer.from("hello rez", "utf8");
  const sig = sign(null, msg, privKeyFromB64(k1.privateKeyB64));
  assert.equal(verify(null, msg, pubKeyFromB64(k1.publicKeyB64), sig), true);

  // Signature from a different seed-derived key must not verify against k1's pubkey.
  const otherSeed = Buffer.alloc(64, 0xab);
  const kOther = SeedKeys.deriveEd25519({ seed: otherSeed, label: "rez/identity/desktop-account/v1" });
  const sigOther = sign(null, msg, privKeyFromB64(kOther.privateKeyB64));
  assert.equal(verify(null, msg, pubKeyFromB64(k1.publicKeyB64), sigOther), false);
});

test("SeedKeys.deriveEd25519 — different labels produce different keypairs", async () => {
  const seed = await fixedSeed();
  const desktop = SeedKeys.deriveEd25519({ seed, label: "rez/identity/desktop-account/v1" });
  const chatServer = SeedKeys.deriveEd25519({ seed, label: "rez/identity/chat-server/v1" });
  assert.notEqual(desktop.privateKeyB64, chatServer.privateKeyB64);
  assert.notEqual(desktop.publicKeyB64, chatServer.publicKeyB64);
});

test("SeedKeys.deriveBytes — rejects malformed input", async () => {
  const seed = await fixedSeed();
  assert.throws(() => SeedKeys.deriveBytes({ seed: "not bytes", label: "x" }), /Uint8Array or Buffer/);
  assert.throws(() => SeedKeys.deriveBytes({ seed: Buffer.alloc(16), label: "x" }), />= 32 bytes/);
  assert.throws(() => SeedKeys.deriveBytes({ seed, label: "" }), /label is required/);
  assert.throws(() => SeedKeys.deriveBytes({ seed, label: "x", length: 0 }), /out of range/);
});
