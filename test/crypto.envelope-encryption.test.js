import test from "node:test";
import assert from "node:assert/strict";
import { CodecChain } from "../src/codec/CodecChain.js";
import { JsonCodec } from "../src/codec/JsonCodec.js";
import { CanonicalizeCodec } from "../src/codec/CanonicalizeCodec.js";
import { EncryptEnvelopeCodec } from "../src/codec/EncryptEnvelopeCodec.js";
import { DecryptEnvelopeCodec } from "../src/codec/DecryptEnvelopeCodec.js";
import { RatchetService } from "../src/services/RatchetService.js";
import { Header } from "../src/objects/Header.js";
import { Envelope } from "../src/objects/Envelope.js";
import { RatchetKeyPair } from "../src/objects/ratchet/RatchetKeyPair.js";
import { FakeCryptoProvider } from "./support/FakeCryptoProvider.js";

function makeProvider() {
  return new FakeCryptoProvider();
}

function fixedSid() {
  const bytes = new Uint8Array(32);
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = 255 - i;
  return bytes;
}

function buildRatchetState(ratchet, sharedSecret, selfDh, remoteDh) {
  return ratchet.initializeAsInitiator({
    sharedSecret,
    selfDhKeyPair: new RatchetKeyPair({ publicKey: selfDh.publicKey, privateKey: selfDh.privateKey }),
    remoteDhPublicKey: remoteDh.publicKey,
  });
}

test("Encrypted envelope round-trip", async (t) => {
  const crypto = makeProvider();
  const ratchet = new RatchetService({ crypto });
  const senderDh = crypto.dhGenerateKeyPair();
  const receiverDh = crypto.dhGenerateKeyPair();
  const sharedSecret = new Uint8Array(32);
  const stateSend = buildRatchetState(ratchet, sharedSecret, senderDh, receiverDh);
  const stateRecv = ratchet.initializeAsResponder({
    sharedSecret,
    selfDhKeyPair: new RatchetKeyPair({ publicKey: receiverDh.publicKey, privateKey: receiverDh.privateKey }),
    remoteDhPublicKey: senderDh.publicKey,
  });

  const innerChain = new CodecChain([new CanonicalizeCodec(), new JsonCodec()]);
  const encCodec = new EncryptEnvelopeCodec({ innerCodecChain: innerChain, ratchetService: ratchet });
  const decCodec = new DecryptEnvelopeCodec({ innerCodecChain: innerChain, ratchetService: ratchet });

  const header = new Header({ id: "enc-1", type: "test.object", createdAt: 1 });
  const inner = new Envelope({ header, body: { hello: "world" } });

  const encCtx = await encCodec.encode({
    envelope: inner,
    meta: { secureChannel: { sid: fixedSid(), ratchetState: stateSend } },
  });

  const decCtx = await decCodec.decode({
    envelope: encCtx.envelope,
    meta: { secureChannel: { sid: fixedSid(), ratchetState: stateRecv } },
  });

  assert.deepEqual(decCtx.envelope.toJSON(), inner.toJSON());
});

test("AAD tamper fails", async (t) => {
  const crypto = makeProvider();
  const ratchet = new RatchetService({ crypto });
  const senderDh = crypto.dhGenerateKeyPair();
  const receiverDh = crypto.dhGenerateKeyPair();
  const sharedSecret = new Uint8Array(32);
  const stateSend = buildRatchetState(ratchet, sharedSecret, senderDh, receiverDh);
  const stateRecv = ratchet.initializeAsResponder({
    sharedSecret,
    selfDhKeyPair: new RatchetKeyPair({ publicKey: receiverDh.publicKey, privateKey: receiverDh.privateKey }),
    remoteDhPublicKey: senderDh.publicKey,
  });

  const innerChain = new CodecChain([new CanonicalizeCodec(), new JsonCodec()]);
  const encCodec = new EncryptEnvelopeCodec({ innerCodecChain: innerChain, ratchetService: ratchet });
  const decCodec = new DecryptEnvelopeCodec({ innerCodecChain: innerChain, ratchetService: ratchet });

  const header = new Header({ id: "enc-2", type: "test.object", createdAt: 1 });
  const inner = new Envelope({ header, body: { ok: true } });

  const encCtx = await encCodec.encode({
    envelope: inner,
    meta: { secureChannel: { sid: fixedSid(), ratchetState: stateSend } },
  });

  const tampered = new Envelope({
    header: new Header({ id: "enc-2-tamper", type: "rez.encrypted.v1", createdAt: 1 }),
    body: encCtx.envelope.body,
  });

  await assert.rejects(
    () => decCodec.decode({ envelope: tampered, meta: { secureChannel: { sid: fixedSid(), ratchetState: stateRecv } } }),
    /integrity|decrypt|Authentication|Operation failed|tag/i
  );
});

test("Header tamper fails", async (t) => {
  const crypto = makeProvider();
  const ratchet = new RatchetService({ crypto });
  const senderDh = crypto.dhGenerateKeyPair();
  const receiverDh = crypto.dhGenerateKeyPair();
  const sharedSecret = new Uint8Array(32);
  const stateSend = buildRatchetState(ratchet, sharedSecret, senderDh, receiverDh);
  const stateRecv = ratchet.initializeAsResponder({
    sharedSecret,
    selfDhKeyPair: new RatchetKeyPair({ publicKey: receiverDh.publicKey, privateKey: receiverDh.privateKey }),
    remoteDhPublicKey: senderDh.publicKey,
  });

  const innerChain = new CodecChain([new CanonicalizeCodec(), new JsonCodec()]);
  const encCodec = new EncryptEnvelopeCodec({ innerCodecChain: innerChain, ratchetService: ratchet });
  const decCodec = new DecryptEnvelopeCodec({ innerCodecChain: innerChain, ratchetService: ratchet });

  const header = new Header({ id: "enc-3", type: "test.object", createdAt: 1 });
  const inner = new Envelope({ header, body: { ok: true } });

  const encCtx = await encCodec.encode({
    envelope: inner,
    meta: { secureChannel: { sid: fixedSid(), ratchetState: stateSend } },
  });

  const body = { ...encCtx.envelope.body, header: { ...encCtx.envelope.body.header, n: 999 } };
  const tampered = new Envelope({
    header: encCtx.envelope.header,
    body,
  });

  await assert.rejects(
    () => decCodec.decode({ envelope: tampered, meta: { secureChannel: { sid: fixedSid(), ratchetState: stateRecv } } }),
    /SkipLimitExceeded|decrypt|Authentication/i
  );
});
