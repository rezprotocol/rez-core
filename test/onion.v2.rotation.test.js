import test from "node:test";
import assert from "node:assert/strict";
import {
  OnionEncodeCodecV2,
  OnionPeelCodecV2,
  OnionPacketV2,
  OnionKeyRecordV1,
  RelayDescriptorV1,
  OnionKeyringV1,
  OnionReplayCacheV2,
  NoUsableOnionKeyError,
  OnionKeyNotUsableError,
  Header,
  Envelope,
} from "../src/index.js";
import { parseOnionLayerV2 } from "../src/codec/onion/parseOnionLayerV2.js";
import { bytesToHex } from "../src/util/bytes.js";
import { FakeCryptoProvider } from "./support/FakeCryptoProvider.js";

function makeProvider() {
  return new FakeCryptoProvider();
}

function onionKeyIdFor(crypto, pubKeyBytes) {
  return bytesToHex(crypto.hashSha256(pubKeyBytes));
}

function makeOnionEnvelope(payload, sizeClass, id) {
  const packet = new OnionPacketV2({ v: 2, sizeClass, payload });
  const header = new Header({ id, type: "rez.onion.v2", createdAt: 1 });
  return new Envelope({ header, body: packet.toJSON() });
}

function buildDescriptor({ keys, nowMs }) {
  return new RelayDescriptorV1({
    relayKeyId: "relay-key",
    endpoints: [{ host: "127.0.0.1", port: 7777 }],
    onionKeys: keys,
    expiresAt: nowMs + 60_000,
    nowMs,
  });
}

function buildKeyRecord({ crypto, keyPair, status, createdAt, notBefore, notAfter }) {
  return new OnionKeyRecordV1({
    onionKeyId: onionKeyIdFor(crypto, keyPair.publicKey),
    publicKeyBytes: keyPair.publicKey,
    format: "raw",
    createdAt,
    notBefore,
    notAfter,
    status,
  });
}

test("Onion v2 sender prefers newest active key", async (t) => {
  const crypto = makeProvider();
  const nowMs = 1_000_000;
  const keyOld = crypto.dhGenerateKeyPair();
  const keyNew = crypto.dhGenerateKeyPair();

  const recordOld = buildKeyRecord({
    crypto,
    keyPair: keyOld,
    status: "active",
    createdAt: nowMs - 1000,
    notBefore: nowMs - 1000,
    notAfter: nowMs + 1000,
  });
  const recordNew = buildKeyRecord({
    crypto,
    keyPair: keyNew,
    status: "active",
    createdAt: nowMs - 10,
    notBefore: nowMs - 10,
    notAfter: nowMs + 1000,
  });

  const descriptor = buildDescriptor({ keys: [recordOld, recordNew], nowMs });
  const path = [{ endpoint: { host: "127.0.0.1", port: 1111 }, relayDescriptor: descriptor }];

  const encode = new OnionEncodeCodecV2({ crypto });
  const encCtx = await encode.encode({
    bytes: new Uint8Array([1, 2, 3]),
    meta: { onion: { path, finalEndpoint: { host: "127.0.0.1", port: 2222 } }, nowMs },
  });

  const packet = OnionPacketV2.fromJSON(encCtx.envelope.body);
  const cipherObj = parseOnionLayerV2(packet.payload);

  assert.equal(cipherObj.onionKeyId, recordNew.onionKeyId);
});

test("Onion v2 sender falls back to draining", async (t) => {
  const crypto = makeProvider();
  const nowMs = 2_000_000;
  const keyDrain = crypto.dhGenerateKeyPair();

  const recordDrain = buildKeyRecord({
    crypto,
    keyPair: keyDrain,
    status: "draining",
    createdAt: nowMs - 100,
    notBefore: nowMs - 100,
    notAfter: nowMs + 1000,
  });

  const descriptor = buildDescriptor({ keys: [recordDrain], nowMs });
  const path = [{ endpoint: { host: "127.0.0.1", port: 1111 }, relayDescriptor: descriptor }];

  const encode = new OnionEncodeCodecV2({ crypto });
  const encCtx = await encode.encode({
    bytes: new Uint8Array([4, 5, 6]),
    meta: { onion: { path, finalEndpoint: { host: "127.0.0.1", port: 2222 } }, nowMs },
  });

  const packet = OnionPacketV2.fromJSON(encCtx.envelope.body);
  const cipherObj = parseOnionLayerV2(packet.payload);

  assert.equal(cipherObj.onionKeyId, recordDrain.onionKeyId);
});

test("Onion v2 sender rejects expired keys", async (t) => {
  const crypto = makeProvider();
  const nowMs = 3_000_000;
  const keyExpired = crypto.dhGenerateKeyPair();

  const recordExpired = buildKeyRecord({
    crypto,
    keyPair: keyExpired,
    status: "active",
    createdAt: nowMs - 10_000,
    notBefore: nowMs - 10_000,
    notAfter: nowMs - 1,
  });

  const descriptor = buildDescriptor({ keys: [recordExpired], nowMs });
  const path = [{ endpoint: { host: "127.0.0.1", port: 1111 }, relayDescriptor: descriptor }];

  const encode = new OnionEncodeCodecV2({ crypto });
  await assert.rejects(
    () => encode.encode({
      bytes: new Uint8Array([7, 8, 9]),
      meta: { onion: { path, finalEndpoint: { host: "127.0.0.1", port: 2222 } }, nowMs },
    }),
    (err) => err instanceof NoUsableOnionKeyError
  );
});

test("Onion v2 relay accepts draining key within window", async (t) => {
  const crypto = makeProvider();
  const nowMs = 4_000_000;
  const hopKey = crypto.dhGenerateKeyPair();
  const onionKeyId = onionKeyIdFor(crypto, hopKey.publicKey);

  const path = [{
    endpoint: { host: "127.0.0.1", port: 1111 },
    onionPubKeyBytes: hopKey.publicKey,
    onionKeyId,
  }];

  const encode = new OnionEncodeCodecV2({ crypto });
  const encCtx = await encode.encode({
    bytes: new Uint8Array([10, 11, 12]),
    meta: { onion: { path, finalEndpoint: { host: "127.0.0.1", port: 2222 } }, nowMs },
  });

  const keyring = new OnionKeyringV1();
  keyring.addKey({
    onionKeyId,
    privateKeyBytes: hopKey.privateKey,
    notBefore: nowMs - 1000,
    notAfter: nowMs + 1000,
    status: "draining",
  });

  const peel = new OnionPeelCodecV2({ crypto, replayCache: new OnionReplayCacheV2() });
  const decCtx = await peel.decode({
    envelope: encCtx.envelope,
    meta: { onion: { hopIndex: 0, keyring }, nowMs },
  });

  assert.ok(decCtx.bytes instanceof Uint8Array);
});

test("Onion v2 relay rejects revoked key", async (t) => {
  const crypto = makeProvider();
  const nowMs = 5_000_000;
  const hopKey = crypto.dhGenerateKeyPair();
  const onionKeyId = onionKeyIdFor(crypto, hopKey.publicKey);

  const path = [{
    endpoint: { host: "127.0.0.1", port: 1111 },
    onionPubKeyBytes: hopKey.publicKey,
    onionKeyId,
  }];

  const encode = new OnionEncodeCodecV2({ crypto });
  const encCtx = await encode.encode({
    bytes: new Uint8Array([13, 14, 15]),
    meta: { onion: { path, finalEndpoint: { host: "127.0.0.1", port: 2222 } }, nowMs },
  });

  const keyring = new OnionKeyringV1();
  keyring.addKey({
    onionKeyId,
    privateKeyBytes: hopKey.privateKey,
    notBefore: nowMs - 1000,
    notAfter: nowMs + 1000,
    status: "revoked",
  });

  const peel = new OnionPeelCodecV2({ crypto, replayCache: new OnionReplayCacheV2() });
  await assert.rejects(
    () => peel.decode({
      envelope: encCtx.envelope,
      meta: { onion: { hopIndex: 0, keyring }, nowMs },
    }),
    (err) => err instanceof OnionKeyNotUsableError
  );
});
