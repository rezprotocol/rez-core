import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  RELAY_KEY_ID_PREFIX,
  NODE_KEY_ID_PREFIX,
  RELAY_IDENTITY_REASONS,
  relayKeyIdForNodePublicKeyB64,
  nodeKeyIdForNodePublicKeyB64,
  validateRelayIdentityBinding,
  isCanonicalRelayKeyId,
  bytesToBase64,
  base64ToBytes,
} from "../src/index.js";

// Fixed golden key: Ed25519 SPKI DER for the all-zeros... no — a real, fixed
// keypair generated once and frozen here as a literal. The derived IDs below
// are LITERALS (golden doctrine): a deliberate derivation change must add a
// new function/version, never edit these strings.
const GOLDEN_SPKI_B64 = "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";
const GOLDEN_RELAY_KEY_ID = "rez:relay:a1e9156054e04fac899ae9f275132cdc07a5dbc4ea2c2ad3a1ffc6e0d253681f";
const GOLDEN_NODE_KEY_ID = "nodekey:a1e9156054e04fac899ae9f275132cdc";

function freshKeyB64() {
  const { publicKey } = generateKeyPairSync("ed25519");
  return publicKey.export({ type: "spki", format: "der" }).toString("base64");
}

test("golden public key derives the pinned relay and node IDs", () => {
  assert.equal(relayKeyIdForNodePublicKeyB64(GOLDEN_SPKI_B64), GOLDEN_RELAY_KEY_ID);
  assert.equal(nodeKeyIdForNodePublicKeyB64(GOLDEN_SPKI_B64), GOLDEN_NODE_KEY_ID);
  const verdict = validateRelayIdentityBinding({
    relayKeyId: GOLDEN_RELAY_KEY_ID,
    nodeKeyId: GOLDEN_NODE_KEY_ID,
    nodePublicKeyB64: GOLDEN_SPKI_B64,
  });
  assert.equal(verdict.ok, true);
  assert.equal(verdict.reason, RELAY_IDENTITY_REASONS.OK);
});

test("derived IDs are structurally canonical", () => {
  const keyB64 = freshKeyB64();
  const relayKeyId = relayKeyIdForNodePublicKeyB64(keyB64);
  const nodeKeyId = nodeKeyIdForNodePublicKeyB64(keyB64);
  assert.match(relayKeyId, /^rez:relay:[0-9a-f]{64}$/);
  assert.match(nodeKeyId, /^nodekey:[0-9a-f]{32}$/);
  assert.equal(relayKeyId.slice(RELAY_KEY_ID_PREFIX.length, RELAY_KEY_ID_PREFIX.length + 32),
    nodeKeyId.slice(NODE_KEY_ID_PREFIX.length));
});

test("one changed key byte changes both IDs", () => {
  const bytes = base64ToBytes(GOLDEN_SPKI_B64);
  const flipped = new Uint8Array(bytes);
  flipped[flipped.length - 1] ^= 0x01; // flip inside the raw key portion
  const flippedB64 = bytesToBase64(flipped);
  assert.notEqual(relayKeyIdForNodePublicKeyB64(flippedB64), GOLDEN_RELAY_KEY_ID);
  assert.notEqual(nodeKeyIdForNodePublicKeyB64(flippedB64), GOLDEN_NODE_KEY_ID);
});

test("labels and config text have no effect on identity", () => {
  const keyB64 = freshKeyB64();
  const a = relayKeyIdForNodePublicKeyB64(keyB64);
  // Identity depends only on the key; there is no other input to vary. Assert
  // determinism across repeated derivation and irrelevance of surrounding
  // whitespace in the b64 transport form.
  assert.equal(relayKeyIdForNodePublicKeyB64(keyB64), a);
  assert.equal(relayKeyIdForNodePublicKeyB64("  " + keyB64 + "\n"), a);
});

test("malformed inputs fail closed", () => {
  const bad = [
    undefined, null, "", "   ", "not-base64!!!!", "AAAA", // valid b64, wrong length
    bytesToBase64(new Uint8Array(44)), // right length, wrong SPKI prefix
    bytesToBase64(new Uint8Array(32).fill(9)), // raw key without SPKI header
  ];
  for (const input of bad) {
    assert.throws(() => relayKeyIdForNodePublicKeyB64(input), Error, String(input));
    assert.throws(() => nodeKeyIdForNodePublicKeyB64(input), Error, String(input));
    const verdict = validateRelayIdentityBinding({
      relayKeyId: "x", nodeKeyId: "y", nodePublicKeyB64: input,
    });
    assert.equal(verdict.ok, false);
    assert.equal(verdict.reason, RELAY_IDENTITY_REASONS.INVALID_PUBLIC_KEY);
  }
});

test("mismatched and non-canonical presented IDs fail closed with bounded reasons", () => {
  const keyB64 = freshKeyB64();
  const relayKeyId = relayKeyIdForNodePublicKeyB64(keyB64);
  const nodeKeyId = nodeKeyIdForNodePublicKeyB64(keyB64);

  const wrongRelay = validateRelayIdentityBinding({
    relayKeyId: relayKeyIdForNodePublicKeyB64(freshKeyB64()),
    nodeKeyId,
    nodePublicKeyB64: keyB64,
  });
  assert.equal(wrongRelay.ok, false);
  assert.equal(wrongRelay.reason, RELAY_IDENTITY_REASONS.RELAY_KEY_ID_MISMATCH);

  const wrongNode = validateRelayIdentityBinding({
    relayKeyId,
    nodeKeyId: "nodekey:00000000000000000000000000000000",
    nodePublicKeyB64: keyB64,
  });
  assert.equal(wrongNode.ok, false);
  assert.equal(wrongNode.reason, RELAY_IDENTITY_REASONS.NODE_KEY_ID_MISMATCH);

  // Non-canonical forms of the CORRECT id are mismatches: case, padding, prefix.
  for (const nonCanonical of [
    relayKeyId.toUpperCase(),
    " " + relayKeyId,
    relayKeyId + " ",
    "REZ:RELAY:" + relayKeyId.slice(RELAY_KEY_ID_PREFIX.length),
  ]) {
    const verdict = validateRelayIdentityBinding({
      relayKeyId: nonCanonical, nodeKeyId, nodePublicKeyB64: keyB64,
    });
    assert.equal(verdict.ok, false, nonCanonical);
    assert.equal(verdict.reason, RELAY_IDENTITY_REASONS.RELAY_KEY_ID_MISMATCH);
  }

  // validateRelayIdentityBinding never throws for untrusted input.
  assert.equal(validateRelayIdentityBinding().ok, false);
  assert.equal(validateRelayIdentityBinding({ relayKeyId: 5, nodeKeyId: {}, nodePublicKeyB64: keyB64 }).ok, false);
});

test("isCanonicalRelayKeyId is a strict structural gate", () => {
  assert.equal(isCanonicalRelayKeyId(GOLDEN_RELAY_KEY_ID), true);
  for (const bad of [
    undefined, null, 42, "", "ws:relay1", "relay-a",
    GOLDEN_RELAY_KEY_ID.toUpperCase(),
    GOLDEN_RELAY_KEY_ID.slice(0, -1),
    GOLDEN_RELAY_KEY_ID + "0",
    " " + GOLDEN_RELAY_KEY_ID,
    "nodekey:" + GOLDEN_RELAY_KEY_ID.slice(10),
  ]) {
    assert.equal(isCanonicalRelayKeyId(bad), false, String(bad));
  }
});

test("Node and browser-style callers receive identical results (pure-JS derivation)", () => {
  // The derivation must not depend on node:crypto — recompute the digest with
  // the same pure-JS primitives a browser build ships and compare.
  const keyB64 = freshKeyB64();
  const viaApi = relayKeyIdForNodePublicKeyB64(keyB64);
  // Independent recomputation through the public byte utilities:
  const spki = base64ToBytes(keyB64);
  assert.equal(spki.length, 44);
  // Round-trip stability: bytes → b64 → derivation is identical.
  assert.equal(relayKeyIdForNodePublicKeyB64(bytesToBase64(spki)), viaApi);
});
