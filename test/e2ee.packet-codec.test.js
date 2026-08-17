import test from "node:test";
import assert from "node:assert/strict";
import { E2eePacketCodec } from "../src/e2ee/E2eePacketCodec.js";
import { E2eeHandshakePacketV1 } from "../src/e2ee/E2eeHandshakePacketV1.js";

// CORE-4: `decryptIncoming` returned the handshake object WITHOUT the signature
// that authenticates it. The finding is about API shape, not a live break — the
// production peer-link path parses handshakes elsewhere — but a codec that hands
// back an unverifiable handshake and no way to notice is an invitation to the
// unsafe half of that split.

const HANDSHAKE = Object.freeze({
  inviteId: "inv_1",
  senderIdentitySigningPubKeyB64: "c2lnbmluZy1wdWI=",
  senderIdentityDhPubKeyB64: "ZGgtcHVi",
  senderIdentityDhSignatureB64: "ZGgtc2ln",
  ackNonce: "bm9uY2U=",
  ephemeralPublicKeyB64: "ZXBoLXB1Yg==",
  initiatorDhPublicKeyB64: "aW5pdC1kaA==",
});
const SIGNATURE_B64 = "aGFuZHNoYWtlLXNpZ25hdHVyZQ==";

function codec({ decryptPayload } = {}) {
  return new E2eePacketCodec({
    secureChannelManager: {
      hasSession: () => true,
      encryptPayload: async (_peer, bytes) => bytes,
      decryptPayload: decryptPayload || (async () => null),
    },
  });
}

function bytes(obj) {
  return new TextEncoder().encode(JSON.stringify(obj));
}

test("CORE-4: a handshake result carries the signature that authenticates it", async () => {
  const packet = E2eePacketCodec.createHandshakePacket({
    handshakeData: { ...HANDSHAKE },
    signatureB64: SIGNATURE_B64,
  });
  const result = await codec().decryptIncoming({ packetBytes: bytes(packet.toJSON()) });

  assert.deepEqual(result.handshake, HANDSHAKE);
  assert.equal(result.handshakeSignatureB64, SIGNATURE_B64,
    "without this a caller cannot verify the handshake it was just handed");
  assert.equal(result.encrypted, false);
  assert.equal(result.peerId, null);
});

test("CORE-4: handshake and its signature are present or absent together, on every branch", async () => {
  // The drift that produced this finding was ONE branch returning a different
  // field set from its siblings, so every exit is pinned, not just the fixed one.
  const encryptedPacket = { e2ee: 1, v: 1, payload: "cGF5bG9hZA==" };
  const branches = [
    ["empty input", codec(), { packetBytes: new Uint8Array(0) }],
    ["not json", codec(), { packetBytes: new TextEncoder().encode("not json at all") }],
    ["json without the e2ee marker", codec(), { packetBytes: bytes({ hello: "world" }) }],
    ["e2ee json of an unknown shape", codec(), { packetBytes: bytes({ e2ee: 1, v: 9 }) }],
    ["encrypted, no session match", codec({ decryptPayload: async () => null }), { packetBytes: bytes(encryptedPacket) }],
    ["encrypted, ratchet throws", codec({ decryptPayload: async () => { throw new Error("aead"); } }), { packetBytes: bytes(encryptedPacket) }],
    ["encrypted, decrypts", codec({ decryptPayload: async () => ({ plaintextBytes: new Uint8Array([1]), peerId: "rez:acct:p" }) }), { packetBytes: bytes(encryptedPacket) }],
  ];

  for (const [label, instance, args] of branches) {
    const result = await instance.decryptIncoming(args);
    assert.deepEqual(
      Object.keys(result).sort(),
      ["encrypted", "handshake", "handshakeSignatureB64", "peerId", "plaintextBytes"],
      label + ": result shape must not drift between branches",
    );
    assert.equal(result.handshake, null, label);
    assert.equal(result.handshakeSignatureB64, null, label);
  }
});

test("CORE-4: an unsigned handshake packet is rejected outright, not returned unsigned", async () => {
  // The record requires signatureB64, so there is no "handshake without a
  // signature" result to hand back — the pairing above cannot be defeated by
  // simply omitting it on the wire.
  const unsigned = { e2ee: 1, type: E2eeHandshakePacketV1.wireType, handshake: { ...HANDSHAKE } };
  await assert.rejects(() => codec().decryptIncoming({ packetBytes: bytes(unsigned) }), /signatureB64/);
});

test("a packet carrying a prototype-poisoning key is refused, not passed on as plaintext", async () => {
  // SDK-1/CORE-2 class: this codec's job is to tell encrypted from plaintext.
  // Hostile JSON is neither, and returning it as "plaintext" would hand it to
  // the app layer to parse a second time.
  const hostile = new TextEncoder().encode(String.raw`{"e2ee":1,"v":1,"__proto__":{"x":1}}`);
  await assert.rejects(
    () => codec().decryptIncoming({ packetBytes: hostile }),
    (err) => err.code === "UNSAFE_JSON_KEY",
  );
});
