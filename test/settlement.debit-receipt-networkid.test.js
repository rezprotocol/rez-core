import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import { DebitReceiptV1 } from "../src/objects/settlement/DebitReceiptV1.js";
import { verifySettlementReceipt } from "../src/receipts/verifySettlementReceipt.js";
import { canonicalJSONStringify } from "../src/util/canonicalize.js";

const cryptoProvider = {
  async verify({ publicKey, msg, sig }) {
    const keyObj = crypto.createPublicKey({
      key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(publicKey)]),
      format: "der",
      type: "spki",
    });
    return crypto.verify(null, msg, keyObj, sig);
  },
};

function generateEd25519KeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    publicKey: new Uint8Array(publicKey.export({ format: "der", type: "spki" }).subarray(12)),
    privateKey: new Uint8Array(privateKey.export({ format: "der", type: "pkcs8" }).subarray(16)),
  };
}

// Sign exactly as ReceiptSigner does: Ed25519 over canonicalJSONStringify(body),
// where body is every field EXCEPT sig.
function signBody(body, privateKey, relayKeyId) {
  const keyObj = crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(privateKey)]),
    format: "der",
    type: "pkcs8",
  });
  const bytes = new TextEncoder().encode(canonicalJSONStringify(body));
  const sig = new Uint8Array(crypto.sign(null, bytes, keyObj));
  return { alg: "ed25519", relayKeyId, sig };
}

const RELAY_KEY_ID = "relay-key-1";

function makeSignedReceipt(kp, overrides = {}) {
  const body = {
    v: 1,
    receiptId: "rcpt-1",
    accountId: "rez:acct:abc",
    amount: 10,
    serviceId: "mailbox.deposit",
    serviceRef: "mailbox:ibx-1",
    networkId: "rez:testnet:v1",
    relayKeyId: RELAY_KEY_ID,
    createdAtMs: 1_700_000_000_000,
    ...overrides,
  };
  const sig = signBody(body, kp.privateKey, RELAY_KEY_ID);
  return new DebitReceiptV1({ ...body, sig });
}

test("DebitReceiptV1 requires a non-empty networkId", () => {
  const kp = generateEd25519KeyPair();
  const sig = signBody({ v: 1 }, kp.privateKey, RELAY_KEY_ID); // shape only; body invalid
  assert.throws(
    () => new DebitReceiptV1({
      v: 1, receiptId: "r", accountId: "a", amount: 1,
      serviceId: "s", serviceRef: "ref", relayKeyId: RELAY_KEY_ID, createdAtMs: 1, sig,
    }),
    /networkId must be non-empty string/,
  );
});

test("networkId round-trips through toJSON/fromJSON", () => {
  const kp = generateEd25519KeyPair();
  const receipt = makeSignedReceipt(kp);
  const json = receipt.toJSON();
  assert.equal(json.networkId, "rez:testnet:v1");
  const back = DebitReceiptV1.fromJSON(json);
  assert.equal(back.networkId, "rez:testnet:v1");
});

test("a correctly-signed receipt (carrying networkId) verifies", async () => {
  const kp = generateEd25519KeyPair();
  const receipt = makeSignedReceipt(kp);
  const res = await verifySettlementReceipt({
    receipt: receipt.toJSON(),
    lookupRelayPublicKey: async (id) => (id === RELAY_KEY_ID ? kp.publicKey : null),
    crypto: cryptoProvider,
  });
  assert.equal(res.ok, true, res.reason);
});

test("THE HOLE CLOSED: networkId is in the signed region — tampering it fails verification", async () => {
  const kp = generateEd25519KeyPair();
  const receipt = makeSignedReceipt(kp);
  const tampered = receipt.toJSON();
  // A relay/attacker rebrands a valid network-A receipt as network B without
  // re-signing. Because networkId is inside the signed body, the signature no
  // longer matches and the receipt is rejected.
  tampered.networkId = "rez:mainnet:v1";
  const res = await verifySettlementReceipt({
    receipt: tampered,
    lookupRelayPublicKey: async (id) => (id === RELAY_KEY_ID ? kp.publicKey : null),
    crypto: cryptoProvider,
  });
  assert.equal(res.ok, false);
  assert.equal(res.reason, "signature invalid");
});
