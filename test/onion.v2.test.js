import test from "node:test";
import assert from "node:assert/strict";
import {
  Header,
  Envelope,
  OnionPacketV2,
  OnionEncodeCodecV2,
  OnionPeelCodecV2,
} from "../src/index.js";
import { OnionReplayCacheV2 } from "../src/services/onion/OnionReplayCacheV2.js";
import { parseOnionLayerV2 } from "../src/codec/onion/parseOnionLayerV2.js";
import { canonicalJSONStringify } from "../src/util/canonicalize.js";
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

function sliceBytes(bytes, len) {
  return bytes.subarray(0, len);
}

function encodeJsonBytes(obj) {
  const encoder = new TextEncoder();
  return encoder.encode(canonicalJSONStringify(obj));
}

function padToSize(bytes, sizeClass) {
  const padded = new Uint8Array(sizeClass);
  padded.set(bytes, 0);
  return padded;
}

function buildKeyResolver(keys) {
  return (onionKeyId) => {
    const entry = keys.get(onionKeyId);
    return entry ? entry.privateKey : null;
  };
}

test("Onion v2 3-hop peel roundtrip", async (t) => {
  const crypto = makeProvider();
  const hops = [
    { endpoint: { host: "127.0.0.1", port: 1111 }, key: crypto.dhGenerateKeyPair() },
    { endpoint: { host: "127.0.0.1", port: 2222 }, key: crypto.dhGenerateKeyPair() },
    { endpoint: { host: "127.0.0.1", port: 3333 }, key: crypto.dhGenerateKeyPair() },
  ];

  const path = hops.map((hop) => ({
    endpoint: hop.endpoint,
    onionPubKeyBytes: hop.key.publicKey,
    onionKeyId: onionKeyIdFor(crypto, hop.key.publicKey),
  }));

  const finalEndpoint = { host: "127.0.0.1", port: 4444 };
  const innerBytes = new Uint8Array([1, 2, 3, 4, 5, 6]);

  const encode = new OnionEncodeCodecV2({ crypto });
  const encCtx = await encode.encode({
    bytes: innerBytes,
    meta: { onion: { path, finalEndpoint, ttl: 3 } },
  });

  const packet = OnionPacketV2.fromJSON(encCtx.envelope.body);
  const sizeClass = packet.sizeClass;

  const keyMap = new Map();
  for (const hop of hops) {
    keyMap.set(onionKeyIdFor(crypto, hop.key.publicKey), hop.key);
  }

  const peel = new OnionPeelCodecV2({ crypto, replayCache: new OnionReplayCacheV2() });
  let env = encCtx.envelope;
  let ttl = 3;

  for (let hopIndex = 0; hopIndex < 3; hopIndex += 1) {
    const decCtx = await peel.decode({
      envelope: env,
      meta: {
        onion: {
          hopIndex,
          keyResolver: buildKeyResolver(keyMap),
        },
      },
    });

    ttl = decCtx.meta.onion.ttl;
    env = makeOnionEnvelope(decCtx.bytes, sizeClass, `hop-${hopIndex + 1}`);

    if (hopIndex === 2) {
      assert.deepEqual(sliceBytes(decCtx.bytes, innerBytes.length), innerBytes);
    }
  }
});

test("Onion v2 tamper fails", async (t) => {
  const crypto = makeProvider();
  const hop = { endpoint: { host: "127.0.0.1", port: 1111 }, key: crypto.dhGenerateKeyPair() };
  const path = [{
    endpoint: hop.endpoint,
    onionPubKeyBytes: hop.key.publicKey,
    onionKeyId: onionKeyIdFor(crypto, hop.key.publicKey),
  }];
  const finalEndpoint = { host: "127.0.0.1", port: 4444 };

  const encode = new OnionEncodeCodecV2({ crypto });
  const encCtx = await encode.encode({
    bytes: new Uint8Array([9, 9, 9]),
    meta: { onion: { path, finalEndpoint, ttl: 1 } },
  });

  const packet = OnionPacketV2.fromJSON(encCtx.envelope.body);
  const tampered = new Uint8Array(packet.payload);
  tampered[0] ^= 0xff;

  const peel = new OnionPeelCodecV2({ crypto, replayCache: new OnionReplayCacheV2() });
  await assert.rejects(
    () => peel.decode({
      envelope: makeOnionEnvelope(tampered, packet.sizeClass, "tamper"),
      meta: { onion: { hopIndex: 0, keyResolver: buildKeyResolver(new Map([[onionKeyIdFor(crypto, hop.key.publicKey), hop.key]])) } },
    }),
    /integrity|decrypt|AES-GCM|Authentication|JSON|Syntax/i
  );
});

test("Onion v2 ttl tamper fails before decrypt", async (t) => {
  const crypto = makeProvider();
  const hop = { endpoint: { host: "127.0.0.1", port: 1111 }, key: crypto.dhGenerateKeyPair() };
  const path = [{
    endpoint: hop.endpoint,
    onionPubKeyBytes: hop.key.publicKey,
    onionKeyId: onionKeyIdFor(crypto, hop.key.publicKey),
  }];
  const finalEndpoint = { host: "127.0.0.1", port: 4444 };

  const encode = new OnionEncodeCodecV2({ crypto });
  const encCtx = await encode.encode({
    bytes: new Uint8Array([3, 3, 3]),
    meta: { onion: { path, finalEndpoint, ttl: 1 } },
  });

  const packet = OnionPacketV2.fromJSON(encCtx.envelope.body);
  const cipherObj = parseOnionLayerV2(packet.payload);
  assert.equal(cipherObj.hopIndex, 0);
  const tamperedCipher = { ...cipherObj, ttl: cipherObj.ttl + 1 };
  const tamperedPayload = padToSize(encodeJsonBytes(tamperedCipher), packet.sizeClass);

  const peel = new OnionPeelCodecV2({ crypto, replayCache: new OnionReplayCacheV2() });
  await assert.rejects(
    () => peel.decode({
      envelope: makeOnionEnvelope(tamperedPayload, packet.sizeClass, "ttl-tamper"),
      meta: { onion: { hopIndex: 0, keyResolver: buildKeyResolver(new Map([[onionKeyIdFor(crypto, hop.key.publicKey), hop.key]])) } },
    }),
    /integrity|decrypt|AES-GCM|Authentication|OperationError/i
  );
});

test("Onion v2 ttl enforced", async (t) => {
  const crypto = makeProvider();
  const hops = [
    { endpoint: { host: "127.0.0.1", port: 1111 }, key: crypto.dhGenerateKeyPair() },
    { endpoint: { host: "127.0.0.1", port: 2222 }, key: crypto.dhGenerateKeyPair() },
    { endpoint: { host: "127.0.0.1", port: 3333 }, key: crypto.dhGenerateKeyPair() },
  ];
  const path = hops.map((hop) => ({
    endpoint: hop.endpoint,
    onionPubKeyBytes: hop.key.publicKey,
    onionKeyId: onionKeyIdFor(crypto, hop.key.publicKey),
  }));
  const finalEndpoint = { host: "127.0.0.1", port: 4444 };

  const encode = new OnionEncodeCodecV2({ crypto });
  const encCtx = await encode.encode({
    bytes: new Uint8Array([1, 2, 3]),
    meta: { onion: { path, finalEndpoint, ttl: 1 } },
  });

  const packet = OnionPacketV2.fromJSON(encCtx.envelope.body);
  const sizeClass = packet.sizeClass;

  const keyMap = new Map();
  for (const hop of hops) {
    keyMap.set(onionKeyIdFor(crypto, hop.key.publicKey), hop.key);
  }

  const peel = new OnionPeelCodecV2({ crypto, replayCache: new OnionReplayCacheV2() });
  const hop0 = await peel.decode({
    envelope: encCtx.envelope,
    meta: { onion: { hopIndex: 0, keyResolver: buildKeyResolver(keyMap) } },
  });

  await assert.rejects(
    () => peel.decode({
      envelope: makeOnionEnvelope(hop0.bytes, sizeClass, "hop-1"),
      meta: { onion: { hopIndex: 1, keyResolver: buildKeyResolver(keyMap) } },
    }),
    /OnionTTLExpired/
  );
});

test("Onion v2 replay keying includes onionKeyId", async (t) => {
  const crypto = makeProvider();
  const hop = { endpoint: { host: "127.0.0.1", port: 1111 }, key: crypto.dhGenerateKeyPair() };
  const onionKeyId = onionKeyIdFor(crypto, hop.key.publicKey);

  const path = [{
    endpoint: hop.endpoint,
    onionPubKeyBytes: hop.key.publicKey,
    onionKeyId,
  }];
  const finalEndpoint = { host: "127.0.0.1", port: 4444 };

  const encode = new OnionEncodeCodecV2({ crypto });
  const encCtx = await encode.encode({
    bytes: new Uint8Array([7, 7, 7]),
    meta: { onion: { path, finalEndpoint, ttl: 1 } },
  });

  const cache = new OnionReplayCacheV2();
  const peel = new OnionPeelCodecV2({ crypto, replayCache: cache });

  await peel.decode({
    envelope: encCtx.envelope,
    meta: { onion: { hopIndex: 0, keyResolver: buildKeyResolver(new Map([[onionKeyId, hop.key]])) } },
  });

  await assert.rejects(
    () => peel.decode({
      envelope: encCtx.envelope,
      meta: { onion: { hopIndex: 0, keyResolver: buildKeyResolver(new Map([[onionKeyId, hop.key]])) } },
    }),
    /ReplayDetected/
  );
});

test("Onion v2 size class selection", async (t) => {
  const crypto = makeProvider();
  const hop = { endpoint: { host: "127.0.0.1", port: 1111 }, key: crypto.dhGenerateKeyPair() };
  const path = [{
    endpoint: hop.endpoint,
    onionPubKeyBytes: hop.key.publicKey,
    onionKeyId: onionKeyIdFor(crypto, hop.key.publicKey),
  }];
  const finalEndpoint = { host: "127.0.0.1", port: 4444 };

  const encode = new OnionEncodeCodecV2({ crypto });

  const small = await encode.encode({
    bytes: new Uint8Array(10),
    meta: { onion: { path, finalEndpoint, ttl: 1 } },
  });
  const smallPacket = OnionPacketV2.fromJSON(small.envelope.body);
  assert.equal(smallPacket.sizeClass, 4096);

  const big = await encode.encode({
    bytes: new Uint8Array(9000),
    meta: { onion: { path, finalEndpoint, ttl: 1 } },
  });
  const bigPacket = OnionPacketV2.fromJSON(big.envelope.body);
  assert.equal(bigPacket.sizeClass, 16384);
});
