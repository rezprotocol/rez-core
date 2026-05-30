import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import { CapabilityValidator } from "../src/capability/CapabilityValidator.js";
import { CapabilitySigner } from "../src/capability/CapabilitySigner.js";
import { RCapability } from "../src/capability/RCapability.js";

const cryptoProvider = {
  randomBytes(len) { return crypto.randomBytes(len); },
  async sign({ privateKey, msg }) {
    const keyObj = crypto.createPrivateKey({
      key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(privateKey)]),
      format: "der", type: "pkcs8",
    });
    return new Uint8Array(crypto.sign(null, msg, keyObj));
  },
  async verify({ publicKey, msg, sig }) {
    const keyObj = crypto.createPublicKey({
      key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(publicKey)]),
      format: "der", type: "spki",
    });
    return crypto.verify(null, msg, keyObj, sig);
  },
};

function genKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pubBytes = new Uint8Array(publicKey.export({ format: "der", type: "spki" }).subarray(12));
  const privBytes = new Uint8Array(privateKey.export({ format: "der", type: "pkcs8" }).subarray(16));
  return {
    publicKey: pubBytes,
    privateKey: privBytes,
    publicKeyB64: Buffer.from(pubBytes).toString("base64"),
  };
}

// Stable dummy pubkey b64 for unsigned-cap tests where signature verification
// is irrelevant — RCapability.validate() requires non-empty signerPublicKeyB64.
const DUMMY_PUBKEY_B64 = Buffer.from(new Uint8Array(32)).toString("base64");

test("CapabilityValidator — constructor requires crypto", () => {
  assert.throws(() => new CapabilityValidator({}), /requires crypto/);
});

test("CapabilityValidator — verifySignature valid", async () => {
  const signer = new CapabilitySigner({ crypto: cryptoProvider });
  const validator = new CapabilityValidator({ crypto: cryptoProvider });
  const alice = genKeys();

  const cap = await signer.createRootCapability({
    resource: "mailbox:m1",
    actions: ["read"],
    signerPublicKeyB64: alice.publicKeyB64,
    privateKeyBytes: alice.privateKey,
  });

  const result = await validator.verifySignature(cap);
  assert.ok(result.ok);
});

test("CapabilityValidator — verifySignature rejects tampered cap (signer pubkey mismatched with signing privkey)", async () => {
  const signer = new CapabilitySigner({ crypto: cryptoProvider });
  const validator = new CapabilityValidator({ crypto: cryptoProvider });
  const alice = genKeys();
  const bob = genKeys();

  // Cap claims Bob is the signer but is actually signed with Alice's privkey.
  const cap = await signer.createRootCapability({
    resource: "mailbox:m1",
    actions: ["read"],
    signerPublicKeyB64: bob.publicKeyB64,
    privateKeyBytes: alice.privateKey,
  });

  const result = await validator.verifySignature(cap);
  assert.equal(result.ok, false);
  assert.ok(result.reason.includes("verification failed"));
});

test("CapabilityValidator — verifySignature rejects unsigned cap", async () => {
  const validator = new CapabilityValidator({ crypto: cryptoProvider });

  const cap = new RCapability({
    capId: "cap_test",
    resource: "mailbox:m1",
    actions: ["read"],
    signerPublicKeyB64: DUMMY_PUBKEY_B64,
    signatureB64: null,
  });

  const result = await validator.verifySignature(cap);
  assert.equal(result.ok, false);
  assert.ok(result.reason.includes("no signature"));
});

test("CapabilityValidator — validateScopeNarrowing valid", () => {
  const validator = new CapabilityValidator({ crypto: cryptoProvider });

  const parent = new RCapability({
    capId: "cap_parent",
    resource: "mailbox:m1",
    actions: ["read", "write", "post"],
    constraints: { expiresAt: 2000, maxUses: 10 },
    signerPublicKeyB64: DUMMY_PUBKEY_B64,
  });

  const child = new RCapability({
    capId: "cap_child",
    parentCapId: "cap_parent",
    resource: "mailbox:m1",
    actions: ["read", "post"],
    constraints: { expiresAt: 1500, maxUses: 5 },
    signerPublicKeyB64: DUMMY_PUBKEY_B64,
  });

  const result = validator.validateScopeNarrowing(child, parent);
  assert.ok(result.ok);
});

test("CapabilityValidator — validateScopeNarrowing rejects resource mismatch", () => {
  const validator = new CapabilityValidator({ crypto: cryptoProvider });

  const parent = new RCapability({
    capId: "cap_p", resource: "mailbox:m1", actions: ["read"],
    signerPublicKeyB64: DUMMY_PUBKEY_B64,
  });
  const child = new RCapability({
    capId: "cap_c", parentCapId: "cap_p", resource: "mailbox:m2", actions: ["read"],
    signerPublicKeyB64: DUMMY_PUBKEY_B64,
  });

  const result = validator.validateScopeNarrowing(child, parent);
  assert.equal(result.ok, false);
  assert.ok(result.reason.includes("resource mismatch"));
});

test("CapabilityValidator — validateScopeNarrowing rejects action escalation", () => {
  const validator = new CapabilityValidator({ crypto: cryptoProvider });

  const parent = new RCapability({
    capId: "cap_p", resource: "mailbox:m1", actions: ["read"],
    signerPublicKeyB64: DUMMY_PUBKEY_B64,
  });
  const child = new RCapability({
    capId: "cap_c", parentCapId: "cap_p", resource: "mailbox:m1", actions: ["read", "write"],
    signerPublicKeyB64: DUMMY_PUBKEY_B64,
  });

  const result = validator.validateScopeNarrowing(child, parent);
  assert.equal(result.ok, false);
  assert.ok(result.reason.includes("write"));
});

test("CapabilityValidator — validateScopeNarrowing rejects widened expiresAt", () => {
  const validator = new CapabilityValidator({ crypto: cryptoProvider });

  const parent = new RCapability({
    capId: "cap_p", resource: "mailbox:m1", actions: ["read"],
    constraints: { expiresAt: 1000 },
    signerPublicKeyB64: DUMMY_PUBKEY_B64,
  });
  const child = new RCapability({
    capId: "cap_c", parentCapId: "cap_p", resource: "mailbox:m1", actions: ["read"],
    constraints: { expiresAt: 2000 },
    signerPublicKeyB64: DUMMY_PUBKEY_B64,
  });

  const result = validator.validateScopeNarrowing(child, parent);
  assert.equal(result.ok, false);
  assert.ok(result.reason.includes("expiresAt"));
});

test("CapabilityValidator — validateScopeNarrowing rejects missing child constraint", () => {
  const validator = new CapabilityValidator({ crypto: cryptoProvider });

  const parent = new RCapability({
    capId: "cap_p", resource: "mailbox:m1", actions: ["read"],
    constraints: { maxUses: 5 },
    signerPublicKeyB64: DUMMY_PUBKEY_B64,
  });
  const child = new RCapability({
    capId: "cap_c", parentCapId: "cap_p", resource: "mailbox:m1", actions: ["read"],
    constraints: {},
    signerPublicKeyB64: DUMMY_PUBKEY_B64,
  });

  const result = validator.validateScopeNarrowing(child, parent);
  assert.equal(result.ok, false);
  assert.ok(result.reason.includes("maxUses"));
});

test("CapabilityValidator — validateChain bearer end-to-end", async () => {
  const signer = new CapabilitySigner({ crypto: cryptoProvider });
  const validator = new CapabilityValidator({ crypto: cryptoProvider });
  const alice = genKeys();
  const bob = genKeys();

  const root = await signer.createRootCapability({
    resource: "mailbox:shared",
    actions: ["read", "post", "write", "grant"],
    signerPublicKeyB64: alice.publicKeyB64,
    granteePublicKeyB64: bob.publicKeyB64,
    privateKeyBytes: alice.privateKey,
  });

  const delegated = await signer.delegateCapability({
    parentCapability: root,
    actions: ["read", "post"],
    signerPublicKeyB64: bob.publicKeyB64,
    privateKeyBytes: bob.privateKey,
  });

  const result = await validator.validateChain([root, delegated]);
  assert.ok(result.ok, result.reason);
  assert.equal(result.leaf.capId, delegated.capId);
});

test("CapabilityValidator — validateChain rejects empty chain", async () => {
  const validator = new CapabilityValidator({ crypto: cryptoProvider });
  const result = await validator.validateChain([]);
  assert.equal(result.ok, false);
  assert.ok(result.reason.includes("empty"));
});

test("CapabilityValidator — validateChain rejects broken parent linkage", async () => {
  const signer = new CapabilitySigner({ crypto: cryptoProvider });
  const validator = new CapabilityValidator({ crypto: cryptoProvider });
  const alice = genKeys();
  const bob = genKeys();

  const root = await signer.createRootCapability({
    resource: "mailbox:m1", actions: ["read"],
    signerPublicKeyB64: alice.publicKeyB64, privateKeyBytes: alice.privateKey,
  });

  const rogue = await signer.createRootCapability({
    resource: "mailbox:m1", actions: ["read"],
    signerPublicKeyB64: bob.publicKeyB64, privateKeyBytes: bob.privateKey,
  });
  const delegated = await signer.delegateCapability({
    parentCapability: rogue, actions: ["read"],
    signerPublicKeyB64: bob.publicKeyB64, privateKeyBytes: bob.privateKey,
  });

  const result = await validator.validateChain([root, delegated]);
  assert.equal(result.ok, false);
  assert.ok(result.reason.includes("parentCapId mismatch"));
});

test("CapabilityValidator — validateChain rejects child signer not matching parent grantee", async () => {
  const signer = new CapabilitySigner({ crypto: cryptoProvider });
  const validator = new CapabilityValidator({ crypto: cryptoProvider });
  const alice = genKeys();
  const bob = genKeys();
  const eve = genKeys();

  // Alice grants Bob, but Eve (not Bob) signs the child.
  const root = await signer.createRootCapability({
    resource: "mailbox:m1", actions: ["read"],
    signerPublicKeyB64: alice.publicKeyB64,
    granteePublicKeyB64: bob.publicKeyB64,
    privateKeyBytes: alice.privateKey,
  });
  const eveDelegation = await signer.delegateCapability({
    parentCapability: root, actions: ["read"],
    signerPublicKeyB64: eve.publicKeyB64, privateKeyBytes: eve.privateKey,
  });

  const result = await validator.validateChain([root, eveDelegation]);
  assert.equal(result.ok, false);
  assert.ok(result.reason.includes("child signer does not match parent grantee"));
});

test("CapabilityValidator — validateChain enforces presenter matches leaf grantee", async () => {
  const signer = new CapabilitySigner({ crypto: cryptoProvider });
  const validator = new CapabilityValidator({ crypto: cryptoProvider });
  const alice = genKeys();
  const bob = genKeys();
  const carol = genKeys();

  const root = await signer.createRootCapability({
    resource: "mailbox:alice", actions: ["post"],
    signerPublicKeyB64: alice.publicKeyB64,
    granteePublicKeyB64: bob.publicKeyB64,
    privateKeyBytes: alice.privateKey,
  });

  // Bob presenting — ok
  const okResult = await validator.validateChain([root], { presenterPublicKeyB64: bob.publicKeyB64 });
  assert.ok(okResult.ok, okResult.reason);

  // Carol presenting Bob's cap — rejected
  const badResult = await validator.validateChain([root], { presenterPublicKeyB64: carol.publicKeyB64 });
  assert.equal(badResult.ok, false);
  assert.ok(badResult.reason.includes("leaf grantee does not match presenter"));
});

test("CapabilityValidator — validateChain bearer (no grantee) ignores presenter", async () => {
  const signer = new CapabilitySigner({ crypto: cryptoProvider });
  const validator = new CapabilityValidator({ crypto: cryptoProvider });
  const alice = genKeys();
  const anyone = genKeys();

  const bearer = await signer.createRootCapability({
    resource: "mailbox:alice", actions: ["post"],
    signerPublicKeyB64: alice.publicKeyB64,
    privateKeyBytes: alice.privateKey,
  });

  const result = await validator.validateChain([bearer], { presenterPublicKeyB64: anyone.publicKeyB64 });
  assert.ok(result.ok, result.reason);
});

test("CapabilityValidator — checkConstraints expired", () => {
  const validator = new CapabilityValidator({ crypto: cryptoProvider });

  const cap = new RCapability({
    capId: "cap_x", resource: "mailbox:m1", actions: ["read"],
    constraints: { expiresAt: 1000 }, signerPublicKeyB64: DUMMY_PUBKEY_B64,
  });

  assert.ok(validator.checkConstraints(cap, { nowMs: 999 }).ok);
  assert.equal(validator.checkConstraints(cap, { nowMs: 1000 }).ok, false);
  assert.equal(validator.checkConstraints(cap, { nowMs: 1001 }).ok, false);
});

test("CapabilityValidator — checkConstraints maxUses", () => {
  const validator = new CapabilityValidator({ crypto: cryptoProvider });

  const cap = new RCapability({
    capId: "cap_x", resource: "mailbox:m1", actions: ["read"],
    constraints: { maxUses: 5 }, signerPublicKeyB64: DUMMY_PUBKEY_B64,
  });

  assert.ok(validator.checkConstraints(cap, { usageCount: 4 }).ok);
  assert.equal(validator.checkConstraints(cap, { usageCount: 5 }).ok, false);
});

test("CapabilityValidator — checkConstraints no constraints always ok", () => {
  const validator = new CapabilityValidator({ crypto: cryptoProvider });

  const cap = new RCapability({
    capId: "cap_x", resource: "mailbox:m1", actions: ["read"],
    signerPublicKeyB64: DUMMY_PUBKEY_B64,
  });

  assert.ok(validator.checkConstraints(cap).ok);
  assert.ok(validator.checkConstraints(cap, { nowMs: 99999, usageCount: 99999 }).ok);
});
