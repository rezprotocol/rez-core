import test from "node:test";
import assert from "node:assert/strict";
import { CodecChain } from "../src/codec/CodecChain.js";
import { JsonCodec } from "../src/codec/JsonCodec.js";
import { CanonicalizeCodec } from "../src/codec/CanonicalizeCodec.js";
import { EncryptEnvelopeCodec } from "../src/codec/EncryptEnvelopeCodec.js";
import { DecryptEnvelopeCodec } from "../src/codec/DecryptEnvelopeCodec.js";
import { RatchetService } from "../src/services/RatchetService.js";
import { SkipLimitExceededError, SkippedKeyStoreLimitExceededError } from "../src/services/ratchet/errors.js";
import { Header } from "../src/objects/Header.js";
import { Envelope } from "../src/objects/Envelope.js";
import { RatchetKeyPair } from "../src/objects/ratchet/RatchetKeyPair.js";
import { FakeCryptoProvider } from "./support/FakeCryptoProvider.js";

function makeProvider() {
  return new FakeCryptoProvider();
}

function fixedSid() {
  const bytes = new Uint8Array(32);
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = 100 + i;
  return bytes;
}

function makeRatchetStates(ratchet, crypto, sharedSecret) {
  const senderDh = crypto.dhGenerateKeyPair();
  const receiverDh = crypto.dhGenerateKeyPair();
  const sendState = ratchet.initializeAsInitiator({
    sharedSecret,
    selfDhKeyPair: new RatchetKeyPair({ publicKey: senderDh.publicKey, privateKey: senderDh.privateKey }),
    remoteDhPublicKey: receiverDh.publicKey,
  });
  const recvState = ratchet.initializeAsResponder({
    sharedSecret,
    selfDhKeyPair: new RatchetKeyPair({ publicKey: receiverDh.publicKey, privateKey: receiverDh.privateKey }),
    remoteDhPublicKey: senderDh.publicKey,
  });
  return { sendState, recvState };
}

function buildCodecs(ratchet) {
  const innerChain = new CodecChain([new CanonicalizeCodec(), new JsonCodec()]);
  return {
    enc: new EncryptEnvelopeCodec({ innerCodecChain: innerChain, ratchetService: ratchet }),
    dec: new DecryptEnvelopeCodec({ innerCodecChain: innerChain, ratchetService: ratchet }),
  };
}

function makeEnvelope(id, body) {
  return new Envelope({
    header: new Header({ id, type: "test.object", createdAt: 1 }),
    body,
  });
}

test("Out-of-order decrypt succeeds with skipped keys", async (t) => {
  const crypto = makeProvider();
  const ratchet = new RatchetService({ crypto });
  const sharedSecret = new Uint8Array(32);
  const { enc, dec } = buildCodecs(ratchet);
  let { sendState, recvState } = makeRatchetStates(ratchet, crypto, sharedSecret);

  const env0 = makeEnvelope("sk-0", { n: 0 });
  const env1 = makeEnvelope("sk-1", { n: 1 });
  const env2 = makeEnvelope("sk-2", { n: 2 });

  const enc0 = await enc.encode({ envelope: env0, meta: { secureChannel: { sid: fixedSid(), ratchetState: sendState } } });
  sendState = enc0.meta.secureChannel.ratchetState;
  const enc1 = await enc.encode({ envelope: env1, meta: { secureChannel: { sid: fixedSid(), ratchetState: sendState } } });
  sendState = enc1.meta.secureChannel.ratchetState;
  const enc2 = await enc.encode({ envelope: env2, meta: { secureChannel: { sid: fixedSid(), ratchetState: sendState } } });
  sendState = enc2.meta.secureChannel.ratchetState;

  const dec0 = await dec.decode({ envelope: enc0.envelope, meta: { secureChannel: { sid: fixedSid(), ratchetState: recvState } } });
  recvState = dec0.meta.secureChannel.ratchetState;
  assert.deepEqual(dec0.envelope.toJSON(), env0.toJSON());

  const dec2 = await dec.decode({ envelope: enc2.envelope, meta: { secureChannel: { sid: fixedSid(), ratchetState: recvState } } });
  recvState = dec2.meta.secureChannel.ratchetState;
  assert.deepEqual(dec2.envelope.toJSON(), env2.toJSON());
  assert.equal(recvState.skipped.size(), 1);

  const dec1 = await dec.decode({ envelope: enc1.envelope, meta: { secureChannel: { sid: fixedSid(), ratchetState: recvState } } });
  recvState = dec1.meta.secureChannel.ratchetState;
  assert.deepEqual(dec1.envelope.toJSON(), env1.toJSON());
  assert.equal(recvState.skipped.size(), 0);
});

test("Skip limit exceeded throws", async (t) => {
  const crypto = makeProvider();
  const ratchet = new RatchetService({ crypto });
  const sharedSecret = new Uint8Array(32);
  const { enc, dec } = buildCodecs(ratchet);
  let { sendState, recvState } = makeRatchetStates(ratchet, crypto, sharedSecret);

  recvState.maxSkip = 1;

  const envs = [];
  for (let i = 0; i < 4; i += 1) {
    envs.push(makeEnvelope(`sk-limit-${i}`, { n: i }));
  }

  let encEnvelope;
  for (const env of envs) {
    const encCtx = await enc.encode({ envelope: env, meta: { secureChannel: { sid: fixedSid(), ratchetState: sendState } } });
    sendState = encCtx.meta.secureChannel.ratchetState;
    encEnvelope = encCtx.envelope;
  }

  await assert.rejects(
    () => dec.decode({ envelope: encEnvelope, meta: { secureChannel: { sid: fixedSid(), ratchetState: recvState } } }),
    SkipLimitExceededError
  );
});

test("Skipped key store limit exceeded throws", async (t) => {
  const crypto = makeProvider();
  const ratchet = new RatchetService({ crypto });
  const sharedSecret = new Uint8Array(32);
  const { enc, dec } = buildCodecs(ratchet);
  let { sendState, recvState } = makeRatchetStates(ratchet, crypto, sharedSecret);

  recvState.maxSkip = 10;
  recvState.maxSkippedKeys = 1;

  const envs = [];
  for (let i = 0; i < 3; i += 1) {
    envs.push(makeEnvelope(`sk-store-${i}`, { n: i }));
  }

  let encEnvelope;
  for (const env of envs) {
    const encCtx = await enc.encode({ envelope: env, meta: { secureChannel: { sid: fixedSid(), ratchetState: sendState } } });
    sendState = encCtx.meta.secureChannel.ratchetState;
    encEnvelope = encCtx.envelope;
  }

  await assert.rejects(
    () => dec.decode({ envelope: encEnvelope, meta: { secureChannel: { sid: fixedSid(), ratchetState: recvState } } }),
    SkippedKeyStoreLimitExceededError
  );
});

test("DH step with skipped keys derives and stores intermediate keys", async (t) => {
  const crypto = makeProvider();
  const ratchet = new RatchetService({ crypto });
  const sharedSecret = new Uint8Array(32);
  const { recvState } = makeRatchetStates(ratchet, crypto, sharedSecret);

  const newRemote = crypto.dhGenerateKeyPair();
  const { nextState, usedSkipped } = await ratchet.deriveReceivingKeyForHeader(
    recvState,
    { n: 2, dh: newRemote.publicKey },
    { sid: fixedSid() }
  );

  assert.equal(usedSkipped, false);
  assert.deepEqual(nextState.remoteDhPublicKey, newRemote.publicKey);
  assert.equal(nextState.receivingChain.messageIndex, 3);
  assert.equal(nextState.skipped.size(), 2);
});
