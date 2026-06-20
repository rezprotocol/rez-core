import test from "node:test";
import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey, sign, verify, diffieHellman } from "node:crypto";
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

test("SeedKeys.deriveX25519 — deterministic, correct DER sizes, label-separated", async () => {
  const seed = await fixedSeed();
  const k1 = SeedKeys.deriveX25519({ seed, label: "rez/identity/x3dh-dh/v1" });
  const k2 = SeedKeys.deriveX25519({ seed, label: "rez/identity/x3dh-dh/v1" });
  assert.equal(k1.privateKeyB64, k2.privateKeyB64, "same seed+label is deterministic");
  assert.equal(k1.publicKeyB64, k2.publicKeyB64);
  // SPKI X25519 pubkey is 44 bytes; PKCS#8 X25519 privkey is 48 bytes — the same
  // shape cryptoProvider.dhGenerateKeyPair() produces, so they interoperate.
  assert.equal(Buffer.from(k1.publicKeyB64, "base64").length, 44);
  assert.equal(Buffer.from(k1.privateKeyB64, "base64").length, 48);

  const other = SeedKeys.deriveX25519({ seed, label: "rez/identity/chat-server/v1" });
  assert.notEqual(other.publicKeyB64, k1.publicKeyB64, "a different label gives a different key");
});

test("SeedKeys.deriveX25519 — keys perform a commutative X25519 agreement (account-level seal)", async () => {
  // Two accounts' seed-derived identity-DH keys must agree on a shared secret —
  // this is what makes the peer-scoped device-set seal openable by both sides
  // (and, when re-derived on a second device of the SAME account, identical).
  const a = SeedKeys.deriveX25519({ seed: Buffer.alloc(64, 1), label: "rez/identity/x3dh-dh/v1" });
  const b = SeedKeys.deriveX25519({ seed: Buffer.alloc(64, 2), label: "rez/identity/x3dh-dh/v1" });
  const aPriv = privKeyFromB64(a.privateKeyB64);
  const aPub = pubKeyFromB64(a.publicKeyB64);
  const bPriv = privKeyFromB64(b.privateKeyB64);
  const bPub = pubKeyFromB64(b.publicKeyB64);
  const ab = diffieHellman({ privateKey: aPriv, publicKey: bPub });
  const ba = diffieHellman({ privateKey: bPriv, publicKey: aPub });
  assert.equal(Buffer.compare(ab, ba), 0, "X25519(aPriv,bPub) === X25519(bPriv,aPub)");
  assert.equal(ab.length, 32);
});

test("SeedKeys.deriveBytes — rejects malformed input", async () => {
  const seed = await fixedSeed();
  assert.throws(() => SeedKeys.deriveBytes({ seed: "not bytes", label: "x" }), /Uint8Array or Buffer/);
  assert.throws(() => SeedKeys.deriveBytes({ seed: Buffer.alloc(16), label: "x" }), />= 32 bytes/);
  assert.throws(() => SeedKeys.deriveBytes({ seed, label: "" }), /label is required/);
  assert.throws(() => SeedKeys.deriveBytes({ seed, label: "x", length: 0 }), /out of range/);
});
