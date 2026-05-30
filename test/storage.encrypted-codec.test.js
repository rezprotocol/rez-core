import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { FakeCryptoProvider } from "./support/FakeCryptoProvider.js";
import { EncryptedStorageCodec } from "../src/storage/encrypted/EncryptedStorageCodec.js";
import { EncryptedStoreEnvelopeV1 } from "../src/storage/encrypted/EncryptedStoreEnvelopeV1.js";
import { StorageRecordRegistry } from "../src/storage/encrypted/StorageRecordRegistry.js";
import { SecureSessionRecord } from "../src/objects/ratchet/SecureSessionRecord.js";
import { RatchetState } from "../src/objects/ratchet/RatchetState.js";
import { RatchetKeyPair } from "../src/objects/ratchet/RatchetKeyPair.js";
import { RatchetChainState } from "../src/objects/ratchet/RatchetChainState.js";
import { RSerializable } from "../src/base/index.js";

function makeCrypto() {
  return new FakeCryptoProvider({ seed: 42 });
}

function makeKey(crypto) {
  return crypto.randomBytes(32);
}

function makeSessionRecord(crypto) {
  const sid = crypto.randomBytes(16);
  const rootKey = crypto.randomBytes(32);
  const keyPair = crypto.dhGenerateKeyPair();
  const remotePub = crypto.randomBytes(32);
  const ratchetState = new RatchetState({
    rootKey,
    sendingChain: new RatchetChainState({
      chainKey: crypto.randomBytes(32),
      messageIndex: 0,
    }),
    receivingChain: null,
    selfDhKeyPair: new RatchetKeyPair({
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
    }),
    remoteDhPublicKey: remotePub,
  });
  return new SecureSessionRecord({
    sid,
    peerId: "peer-abc-123",
    ratchetState,
    includeDh: false,
  });
}

function makeRegistry() {
  const registry = new StorageRecordRegistry();
  registry.register(SecureSessionRecord);
  return registry;
}

describe("EncryptedStoreEnvelopeV1", () => {
  it("validates required fields", () => {
    assert.throws(() => new EncryptedStoreEnvelopeV1({}));
    assert.throws(() => new EncryptedStoreEnvelopeV1({ contentType: "", nonceB64: "a", ciphertextB64: "b" }));
    assert.throws(() => new EncryptedStoreEnvelopeV1({ contentType: "X", nonceB64: "", ciphertextB64: "b" }));
    assert.throws(() => new EncryptedStoreEnvelopeV1({ contentType: "X", nonceB64: "a", ciphertextB64: "" }));
  });

  it("round-trips through toJSON/fromJSON", () => {
    const envelope = new EncryptedStoreEnvelopeV1({
      contentType: "TestRecord",
      nonceB64: "AAAAAAAAAAAAAAAA",
      ciphertextB64: "BBBBBBBBBBB=",
    });
    const json = envelope.toJSON();
    assert.equal(json.v, 1);
    assert.equal(json.contentType, "TestRecord");
    const restored = EncryptedStoreEnvelopeV1.fromJSON(json);
    assert.equal(restored.contentType, "TestRecord");
    assert.equal(restored.nonceB64, envelope.nonceB64);
    assert.equal(restored.ciphertextB64, envelope.ciphertextB64);
  });

  it("rejects wrong version in fromJSON", () => {
    assert.throws(() => EncryptedStoreEnvelopeV1.fromJSON({ v: 2, contentType: "X", nonceB64: "a", ciphertextB64: "b" }));
  });
});

describe("StorageRecordRegistry", () => {
  it("registers and retrieves record classes", () => {
    const registry = makeRegistry();
    assert.equal(registry.isRegistered("SecureSessionRecord"), true);
    assert.equal(registry.isRegistered("UnknownType"), false);
    assert.equal(registry.get("SecureSessionRecord"), SecureSessionRecord);
  });

  it("rejects duplicate registration", () => {
    const registry = makeRegistry();
    assert.throws(() => registry.register(SecureSessionRecord));
  });

  it("throws on unknown type lookup", () => {
    const registry = makeRegistry();
    assert.throws(() => registry.get("Nope"), /unknown type/);
  });

  it("rejects class without static type", () => {
    class BadRecord extends RSerializable {}
    // RSerializable sets type from constructor name, so override it
    BadRecord.type = "";
    assert.throws(() => new StorageRecordRegistry().register(BadRecord));
  });

  it("rejects class without fromJSON", () => {
    class NoFromJson {
      static type = "NoFromJson";
    }
    assert.throws(() => new StorageRecordRegistry().register(NoFromJson));
  });
});

describe("EncryptedStorageCodec", () => {
  it("seal + open round-trips a SecureSessionRecord", () => {
    const crypto = makeCrypto();
    const key = makeKey(crypto);
    const codec = new EncryptedStorageCodec({ crypto, key });
    const registry = makeRegistry();
    const record = makeSessionRecord(crypto);

    const envelope = codec.seal(record);
    assert.ok(envelope instanceof EncryptedStoreEnvelopeV1);
    assert.equal(envelope.contentType, "SecureSessionRecord");

    const restored = codec.open(envelope, registry);
    assert.ok(restored instanceof SecureSessionRecord);
    assert.equal(restored.peerId, record.peerId);
    assert.equal(restored.includeDh, record.includeDh);
    assert.deepStrictEqual(Array.from(restored.sid), Array.from(record.sid));
    assert.deepStrictEqual(
      Array.from(restored.ratchetState.rootKey),
      Array.from(record.ratchetState.rootKey),
    );
  });

  it("envelope JSON round-trips through disk simulation", () => {
    const crypto = makeCrypto();
    const key = makeKey(crypto);
    const codec = new EncryptedStorageCodec({ crypto, key });
    const registry = makeRegistry();
    const record = makeSessionRecord(crypto);

    const envelope = codec.seal(record);
    // Simulate writing to disk and reading back
    const diskJson = JSON.stringify(envelope.toJSON());
    const fromDisk = EncryptedStoreEnvelopeV1.fromJSON(JSON.parse(diskJson));
    const restored = codec.open(fromDisk, registry);

    assert.ok(restored instanceof SecureSessionRecord);
    assert.equal(restored.peerId, record.peerId);
  });

  it("rejects tampered ciphertext", () => {
    const crypto = makeCrypto();
    const key = makeKey(crypto);
    const codec = new EncryptedStorageCodec({ crypto, key });
    const registry = makeRegistry();
    const record = makeSessionRecord(crypto);

    const envelope = codec.seal(record);
    // Tamper with ciphertext by flipping a character
    const tamperedB64 = envelope.ciphertextB64.slice(0, -2) + "XX";
    const tampered = new EncryptedStoreEnvelopeV1({
      contentType: envelope.contentType,
      nonceB64: envelope.nonceB64,
      ciphertextB64: tamperedB64,
    });

    assert.throws(() => codec.open(tampered, registry), /integrity/i);
  });

  it("rejects unregistered contentType", () => {
    const crypto = makeCrypto();
    const key = makeKey(crypto);
    const codec = new EncryptedStorageCodec({ crypto, key });
    const registry = makeRegistry();
    const record = makeSessionRecord(crypto);

    const envelope = codec.seal(record);
    // Create envelope with wrong contentType
    const spoofed = new EncryptedStoreEnvelopeV1({
      contentType: "MaliciousRecord",
      nonceB64: envelope.nonceB64,
      ciphertextB64: envelope.ciphertextB64,
    });

    assert.throws(() => codec.open(spoofed, registry), /unknown contentType/);
  });

  it("rejects wrong key", () => {
    const crypto = makeCrypto();
    const key1 = crypto.randomBytes(32);
    const key2 = crypto.randomBytes(32);
    const codec1 = new EncryptedStorageCodec({ crypto, key: key1 });
    const codec2 = new EncryptedStorageCodec({ crypto, key: key2 });
    const registry = makeRegistry();
    const record = makeSessionRecord(crypto);

    const envelope = codec1.seal(record);
    assert.throws(() => codec2.open(envelope, registry), /integrity/i);
  });

  it("rejects spoofed contentType even with valid ciphertext", () => {
    const crypto = makeCrypto();
    const key = makeKey(crypto);
    const codec = new EncryptedStorageCodec({ crypto, key });
    const registry = makeRegistry();
    const record = makeSessionRecord(crypto);

    const envelope = codec.seal(record);
    // Swap contentType — AAD mismatch should cause integrity failure
    // First register a fake type so registry doesn't reject
    class FakeRecord extends RSerializable {
      static type = "FakeRecord";
      static fromJSON(json) { return new FakeRecord(); }
      toJSON() { return {}; }
    }
    registry.register(FakeRecord);

    const spoofed = new EncryptedStoreEnvelopeV1({
      contentType: "FakeRecord",
      nonceB64: envelope.nonceB64,
      ciphertextB64: envelope.ciphertextB64,
    });

    // Should fail because contentType is used as AAD — changing it breaks the MAC
    assert.throws(() => codec.open(spoofed, registry), /integrity/i);
  });

  it("rejects seal of record without toJSON", () => {
    const crypto = makeCrypto();
    const key = makeKey(crypto);
    const codec = new EncryptedStorageCodec({ crypto, key });
    assert.throws(() => codec.seal({ constructor: { type: "X" } }), /toJSON/);
  });

  it("rejects seal of record without static type", () => {
    const crypto = makeCrypto();
    const key = makeKey(crypto);
    const codec = new EncryptedStorageCodec({ crypto, key });
    assert.throws(() => codec.seal({ toJSON: () => ({}) }), /static type/);
  });

  it("constructor rejects bad inputs", () => {
    const crypto = makeCrypto();
    assert.throws(() => new EncryptedStorageCodec({ crypto, key: new Uint8Array(16) }), /32-byte/);
    assert.throws(() => new EncryptedStorageCodec({ crypto: {}, key: crypto.randomBytes(32) }), /RCryptoProvider/);
  });
});

describe("SecureSessionRecord serialization", () => {
  it("round-trips through toJSON/fromJSON", () => {
    const crypto = makeCrypto();
    const record = makeSessionRecord(crypto);
    const json = record.toJSON();
    const restored = SecureSessionRecord.fromJSON(json);

    assert.ok(restored instanceof SecureSessionRecord);
    assert.equal(restored.peerId, record.peerId);
    assert.equal(restored.includeDh, record.includeDh);
    assert.deepStrictEqual(Array.from(restored.sid), Array.from(record.sid));
    assert.deepStrictEqual(
      Array.from(restored.ratchetState.rootKey),
      Array.from(record.ratchetState.rootKey),
    );
  });

  it("fromJSON rejects non-object", () => {
    assert.throws(() => SecureSessionRecord.fromJSON(null));
    assert.throws(() => SecureSessionRecord.fromJSON("bad"));
  });
});
