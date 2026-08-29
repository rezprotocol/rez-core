import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  TerminalInboxCloseV1,
  canonicalTerminalCloseBytes,
  signTerminalInboxClose,
  verifyTerminalInboxClose,
} from "../src/objects/inbox/TerminalInboxCloseV1.js";

// Portable inbox lease L1: the self-authorizing kill-switch record.

const CRYPTO = {
  async sign({ privateKey, msg }) {
    const key = crypto.createPrivateKey({ key: Buffer.from(privateKey), format: "der", type: "pkcs8" });
    return new Uint8Array(crypto.sign(null, Buffer.from(msg), key));
  },
  async verify({ publicKey, msg, sig }) {
    const key = crypto.createPublicKey({ key: Buffer.from(publicKey), format: "der", type: "spki" });
    return crypto.verify(null, Buffer.from(msg), key, Buffer.from(sig));
  },
};

function keypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    publicKeyB64: Buffer.from(publicKey.export({ format: "der", type: "spki" })).toString("base64"),
    privateKey: new Uint8Array(privateKey.export({ format: "der", type: "pkcs8" })),
  };
}

test("record validation: every invalid shape throws, nothing partial", () => {
  const good = { inboxId: "inbox:" + "a".repeat(24), finalGeneration: 1, closedAtMs: 5, signatureB64: "AA==" };
  assert.ok(new TerminalInboxCloseV1(good) instanceof TerminalInboxCloseV1);
  for (const [label, bad] of [
    ["v != 1", { ...good, v: 2 }],
    ["no inboxId", { ...good, inboxId: "" }],
    ["generation 0", { ...good, finalGeneration: 0 }],
    ["fractional generation", { ...good, finalGeneration: 1.5 }],
    ["no closedAtMs", { ...good, closedAtMs: 0 }],
    ["no signature", { ...good, signatureB64: "" }],
  ]) {
    assert.throws(() => new TerminalInboxCloseV1(bad), Error, label);
  }
});

test("sign/verify round-trip; wrong key and tampered fields are refused", async () => {
  const closeKey = keypair();
  const other = keypair();
  const close = await signTerminalInboxClose({
    inboxId: "inbox:" + "b".repeat(24),
    finalGeneration: 3,
    closedAtMs: 1234,
    closePublicKeyB64: closeKey.publicKeyB64,
    crypto: CRYPTO,
    closePrivateKey: closeKey.privateKey,
  });
  assert.equal(await verifyTerminalInboxClose({ close, expectedClosePublicKeyB64: closeKey.publicKeyB64, crypto: CRYPTO }), true);
  assert.equal(await verifyTerminalInboxClose({ close, expectedClosePublicKeyB64: other.publicKeyB64, crypto: CRYPTO }), false);

  // Any tampered signed field breaks verification.
  for (const patch of [{ finalGeneration: 4 }, { closedAtMs: 9999 }, { inboxId: "inbox:" + "c".repeat(24) }]) {
    const tampered = TerminalInboxCloseV1.fromJSON({ ...close.toJSON(), ...patch });
    assert.equal(await verifyTerminalInboxClose({ tampered, close: tampered, expectedClosePublicKeyB64: closeKey.publicKeyB64, crypto: CRYPTO }), false);
  }

  // Mismatched keypair at signing time fails loud, never returns a bad record.
  await assert.rejects(() => signTerminalInboxClose({
    inboxId: "inbox:" + "b".repeat(24),
    finalGeneration: 1,
    closedAtMs: 1,
    closePublicKeyB64: other.publicKeyB64,
    crypto: CRYPTO,
    closePrivateKey: closeKey.privateKey,
  }), /does not match/);
});

test("canonical bytes are stable and cover exactly the identity fields", () => {
  const bytes = canonicalTerminalCloseBytes({ inboxId: "inbox:x", finalGeneration: 2, closedAtMs: 7 });
  const text = new TextDecoder().decode(bytes);
  assert.ok(text.includes("terminal-inbox-close"));
  assert.ok(text.includes("\"finalGeneration\":2"));
  assert.ok(!text.includes("signature"), "the signature never signs itself");
});
