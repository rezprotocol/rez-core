/**
 * P2.1 (ATLAS_PREREQUISITES) — one canonical descriptor validator.
 *
 * A table-driven corpus is run through BOTH entry points — direct
 * `RelayDescriptorV1.fromJSON()` and the compatibility adapter
 * `validateRelayDescriptorV1()` — and must produce the same accept/reject
 * outcome for every input. The adapter owns no schema of its own; an
 * architecture assertion pins that (no field lists / regexes in its source).
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { generateKeyPairSync, createHash } from "node:crypto";
import {
  RelayDescriptorV1,
  RELAY_TRANSPORT_NAMES,
  validateRelayDescriptorV1,
  OnionKeyRecordV1,
  relayKeyIdForNodePublicKeyB64,
  nodeKeyIdForNodePublicKeyB64,
} from "../src/index.js";

const NOW = 1_700_000_000_000;

function identity() {
  const { publicKey } = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { format: "der", type: "spki" },
  });
  const nodePublicKeyB64 = Buffer.from(publicKey).toString("base64");
  return {
    nodePublicKeyB64,
    relayKeyId: relayKeyIdForNodePublicKeyB64(nodePublicKeyB64),
    nodeKeyId: nodeKeyIdForNodePublicKeyB64(nodePublicKeyB64),
  };
}

const ID = identity();
const OTHER = identity();

function baseDescriptor(overrides = {}) {
  return {
    v: 1,
    relayKeyId: ID.relayKeyId,
    endpoints: [{ host: "127.0.0.1", port: 4650 }],
    onionKeys: [{
      onionKeyId: "ok-1",
      publicKeyBytes: Array.from(new Uint8Array(32).fill(5)),
      format: "raw",
      createdAt: NOW - 1000,
      notBefore: NOW - 1000,
      notAfter: NOW + 60_000,
      status: "active",
    }],
    expiresAt: NOW + 60_000,
    meta: {
      v: 1,
      capabilities: { transports: ["tcp"] },
      node: { keyId: ID.nodeKeyId, publicKeyB64: ID.nodePublicKeyB64, protocolVersion: 4 },
    },
    ...overrides,
  };
}

function withMeta(patch) {
  const d = baseDescriptor();
  d.meta = { ...d.meta, ...patch };
  return d;
}

// [label, input, expectOk]
const CORPUS = [
  ["valid identity-bound descriptor", baseDescriptor(), true],
  ["valid without meta.node (no key material, label id)", (() => {
    const d = baseDescriptor({ relayKeyId: "legacy-label" });
    d.meta = { v: 1, capabilities: { transports: ["tcp"] } };
    return d;
  })(), true],
  ["expired", baseDescriptor({ expiresAt: NOW - 1 }), false],
  ["missing endpoints", baseDescriptor({ endpoints: [] }), false],
  ["endpoint without port", baseDescriptor({ endpoints: [{ host: "h" }] }), false],
  ["missing onionKeys", baseDescriptor({ onionKeys: [] }), false],
  ["unknown top-level meta field", withMeta({ evil: 1 }), false],
  ["non-empty top-level capabilities (reserved)", baseDescriptor({ capabilities: { cpu: 64 } }), false],
  ["empty top-level capabilities allowed", baseDescriptor({ capabilities: {} }), true],
  ["meta.capabilities unknown field", withMeta({ capabilities: { transports: ["tcp"], battery: 1 } }), false],
  ["meta.capabilities duplicate transport", withMeta({ capabilities: { transports: ["tcp", "tcp"] } }), false],
  ["meta.capabilities transport outside canonical enum", withMeta({ capabilities: { transports: ["quic"] } }), false],
  ["meta.capabilities may use any canonical transport name", withMeta({ capabilities: { transports: ["wss"] } }), true],
  ["nickname over 32 chars", withMeta({ nickname: "x".repeat(33) }), false],
  ["nickname bad charset", withMeta({ nickname: "bad☠name" }), false],
  ["meta.node unknown field", withMeta({ node: { keyId: ID.nodeKeyId, publicKeyB64: ID.nodePublicKeyB64, gpu: true } }), false],
  ["identity mismatch: someone else's relayKeyId", baseDescriptor({ relayKeyId: OTHER.relayKeyId }), false],
  ["identity mismatch: wrong nodeKeyId for key", withMeta({ node: { keyId: OTHER.nodeKeyId, publicKeyB64: ID.nodePublicKeyB64 } }), false],
  ["sig unknown field", baseDescriptor({ sig: { scheme: "ed25519", keyId: ID.nodeKeyId, sigB64: "c2ln", extra: 1 } }), false],
  ["sig keyId != meta.node.keyId", baseDescriptor({ sig: { scheme: "ed25519", keyId: "nodekey:ffffffffffffffffffffffffffffffff", sigB64: "c2ln" } }), false],
  ["services entry with negative cost", withMeta({ services: { store: { costPerUnit: -1, unit: "per_kb" } } }), false],
];

test("corpus: fromJSON and the compatibility adapter agree on every input", () => {
  for (const [label, input, expectOk] of CORPUS) {
    let classOk = true;
    try {
      RelayDescriptorV1.fromJSON(structuredClone(input), { nowMs: NOW });
    } catch (err) {
      if (!(err instanceof Error)) throw err;
      classOk = false;
    }
    const adapterVerdict = validateRelayDescriptorV1(structuredClone(input), { nowMs: NOW });
    assert.equal(classOk, expectOk, label + " (class)");
    assert.equal(adapterVerdict.ok, expectOk, label + " (adapter): " + (adapterVerdict.reason || ""));
    assert.equal(adapterVerdict.ok, classOk, label + " (agreement)");
  }
});

test("adapter re-validates instances: an expired instance is rejected like its JSON", () => {
  // Construct WITHOUT nowMs (the only way an expired instance can exist).
  const expired = RelayDescriptorV1.fromJSON(baseDescriptor({ expiresAt: NOW - 5000 }));
  const verdict = validateRelayDescriptorV1(expired, { nowMs: NOW });
  assert.equal(verdict.ok, false, "instanceof short-circuit must not skip expiry");
  // And a valid instance still passes.
  const valid = RelayDescriptorV1.fromJSON(baseDescriptor(), { nowMs: NOW });
  assert.equal(validateRelayDescriptorV1(valid, { nowMs: NOW }).ok, true);
});

test("architecture: the adapter owns no schema (no field lists, limits, or regexes)", () => {
  const source = readFileSync(new URL("../src/directory/validateRelayDescriptorV1.js", import.meta.url), "utf8");
  assert.equal(/new Set\(/.test(source), false, "no allowlists in the adapter");
  assert.equal(/\.length\s*[<>]/.test(source), false, "no length limits in the adapter");
  assert.equal(/\/\^/.test(source), false, "no validation regexes in the adapter");
  assert.ok(source.includes("RelayDescriptorV1.fromJSON"), "delegates to the canonical class");
});

test("one canonical transport vocabulary", () => {
  assert.deepEqual([...RELAY_TRANSPORT_NAMES], ["http", "https", "tcp", "ws", "wss"]);
  // Both transport fields accept the same names now.
  const d = withMeta({
    capabilities: { transports: ["ws", "wss"] },
    node: { keyId: ID.nodeKeyId, publicKeyB64: ID.nodePublicKeyB64, transports: ["ws", "wss"] },
  });
  assert.equal(validateRelayDescriptorV1(d, { nowMs: NOW }).ok, true);
});
