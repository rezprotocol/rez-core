import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import { CapabilitySigner } from "../src/capability/CapabilitySigner.js";
import { RCapability } from "../src/capability/RCapability.js";

const cryptoProvider = {
  randomBytes(len) {
    return crypto.randomBytes(len);
  },
  async sign({ privateKey, msg }) {
    const keyObj = crypto.createPrivateKey({
      key: Buffer.concat([
        Buffer.from("302e020100300506032b657004220420", "hex"),
        Buffer.from(privateKey),
      ]),
      format: "der",
      type: "pkcs8",
    });
    return new Uint8Array(crypto.sign(null, msg, keyObj));
  },
  async verify({ publicKey, msg, sig }) {
    const keyObj = crypto.createPublicKey({
      key: Buffer.concat([
        Buffer.from("302a300506032b6570032100", "hex"),
        Buffer.from(publicKey),
      ]),
      format: "der",
      type: "spki",
    });
    return crypto.verify(null, msg, keyObj, sig);
  },
};

function generateEd25519KeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pubRaw = publicKey.export({ format: "der", type: "spki" }).subarray(12);
  const privRaw = privateKey.export({ format: "der", type: "pkcs8" }).subarray(16);
  return {
    publicKey: new Uint8Array(pubRaw),
    privateKey: new Uint8Array(privRaw),
    publicKeyB64: Buffer.from(pubRaw).toString("base64"),
  };
}

test("CapabilitySigner — constructor requires crypto", () => {
  assert.throws(() => new CapabilitySigner({}), /requires crypto/);
});

test("CapabilitySigner — createRootCapability", async () => {
  const signer = new CapabilitySigner({ crypto: cryptoProvider });
  const alice = generateEd25519KeyPair();

  const cap = await signer.createRootCapability({
    resource: "mailbox:inbox_001",
    actions: ["read", "post"],
    constraints: { expiresAt: 9999999999999 },
    signerPublicKeyB64: alice.publicKeyB64,
    privateKeyBytes: alice.privateKey,
  });

  assert.ok(cap instanceof RCapability);
  assert.ok(cap.capId.startsWith("cap_"));
  assert.equal(cap.parentCapId, null);
  assert.equal(cap.resource, "mailbox:inbox_001");
  assert.deepEqual(cap.actions, ["post", "read"]);
  assert.equal(cap.signerPublicKeyB64, alice.publicKeyB64);
  assert.equal(cap.granteePublicKeyB64, null);
  assert.ok(typeof cap.signatureB64 === "string" && cap.signatureB64.length > 0);
});

test("CapabilitySigner — signed cap verifies with embedded key", async () => {
  const signer = new CapabilitySigner({ crypto: cryptoProvider });
  const bob = generateEd25519KeyPair();

  const cap = await signer.createRootCapability({
    resource: "mailbox:m1",
    actions: ["read"],
    signerPublicKeyB64: bob.publicKeyB64,
    privateKeyBytes: bob.privateKey,
  });

  const payloadBytes = new TextEncoder().encode(cap._toSignablePayload());
  const sigBytes = _b64ToBytes(cap.signatureB64);
  const valid = await cryptoProvider.verify({
    publicKey: bob.publicKey,
    msg: payloadBytes,
    sig: sigBytes,
  });
  assert.ok(valid, "signature must verify against the embedded pubkey");
});

test("CapabilitySigner — signed cap fails with wrong key", async () => {
  const signer = new CapabilitySigner({ crypto: cryptoProvider });
  const alice = generateEd25519KeyPair();
  const bob = generateEd25519KeyPair();

  const cap = await signer.createRootCapability({
    resource: "mailbox:m1",
    actions: ["read"],
    signerPublicKeyB64: alice.publicKeyB64,
    privateKeyBytes: alice.privateKey,
  });

  const payloadBytes = new TextEncoder().encode(cap._toSignablePayload());
  const sigBytes = _b64ToBytes(cap.signatureB64);
  const valid = await cryptoProvider.verify({
    publicKey: bob.publicKey,
    msg: payloadBytes,
    sig: sigBytes,
  });
  assert.equal(valid, false);
});

test("CapabilitySigner — delegateCapability with grantee", async () => {
  const signer = new CapabilitySigner({ crypto: cryptoProvider });
  const alice = generateEd25519KeyPair();
  const bob = generateEd25519KeyPair();
  const carol = generateEd25519KeyPair();

  const root = await signer.createRootCapability({
    resource: "mailbox:shared",
    actions: ["read", "post", "write", "grant"],
    signerPublicKeyB64: alice.publicKeyB64,
    granteePublicKeyB64: bob.publicKeyB64,
    privateKeyBytes: alice.privateKey,
  });

  const child = await signer.delegateCapability({
    parentCapability: root,
    actions: ["read", "post"],
    constraints: { maxUses: 10 },
    signerPublicKeyB64: bob.publicKeyB64,
    granteePublicKeyB64: carol.publicKeyB64,
    privateKeyBytes: bob.privateKey,
  });

  assert.equal(child.parentCapId, root.capId);
  assert.equal(child.resource, root.resource);
  assert.deepEqual(child.actions, ["post", "read"]);
  assert.deepEqual(child.constraints, { maxUses: 10 });
  assert.equal(child.signerPublicKeyB64, bob.publicKeyB64);
  assert.equal(child.granteePublicKeyB64, carol.publicKeyB64);
  assert.ok(child.signatureB64);
});

test("CapabilitySigner — rotateCapability preserves grantee", async () => {
  const signer = new CapabilitySigner({ crypto: cryptoProvider });
  const alice = generateEd25519KeyPair();
  const bob = generateEd25519KeyPair();

  const original = await signer.createRootCapability({
    resource: "mailbox:m1",
    actions: ["read", "write"],
    constraints: { expiresAt: 1000 },
    signerPublicKeyB64: alice.publicKeyB64,
    granteePublicKeyB64: bob.publicKeyB64,
    privateKeyBytes: alice.privateKey,
  });

  const rotated = await signer.rotateCapability({
    oldCapability: original,
    signerPublicKeyB64: alice.publicKeyB64,
    privateKeyBytes: alice.privateKey,
    newConstraints: { expiresAt: 2000 },
  });

  assert.notEqual(rotated.capId, original.capId);
  assert.equal(rotated.parentCapId, null);
  assert.equal(rotated.resource, original.resource);
  assert.deepEqual(rotated.actions, original.actions);
  assert.deepEqual(rotated.constraints, { expiresAt: 2000 });
  assert.equal(rotated.granteePublicKeyB64, bob.publicKeyB64);
  assert.ok(rotated.signatureB64);
});

function _b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
