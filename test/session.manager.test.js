import test from "node:test";
import assert from "node:assert/strict";
import { RatchetService } from "../src/services/RatchetService.js";
import { RatchetKeyPair } from "../src/objects/ratchet/RatchetKeyPair.js";
import { deriveSessionIdV1 } from "../src/crypto/sessions/deriveSessionIdV1.js";
import { MemorySessionManager } from "../src/services/sessions/MemorySessionManager.js";
import { NoSessionForPeerError, UnknownSessionError } from "../src/services/sessions/errors.js";
import { FakeCryptoProvider } from "./support/FakeCryptoProvider.js";

function makeProvider() {
  return new FakeCryptoProvider();
}

function fixedSecret() {
  const bytes = new Uint8Array(32);
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = i;
  return bytes;
}

test("deriveSessionIdV1 is deterministic", async () => {
  const crypto = makeProvider();
  const secret = fixedSecret();
  const sid1 = await deriveSessionIdV1(crypto, secret);
  const sid2 = await deriveSessionIdV1(crypto, secret);
  assert.equal(sid1.length, 32);
  assert.deepEqual(sid1, sid2);
});

test("createInitiatorSession stores and returns sid", async (t) => {
  const crypto = makeProvider();
  const ratchet = new RatchetService({ crypto });
  const selfDh = crypto.dhGenerateKeyPair();
  const remoteDh = crypto.dhGenerateKeyPair();

  const manager = new MemorySessionManager({ ratchetService: ratchet, crypto });
  const sid = await manager.createInitiatorSession({
    peerId: "peer-a",
    sharedSecret: fixedSecret(),
    selfDhKeyPair: new RatchetKeyPair({ publicKey: selfDh.publicKey, privateKey: selfDh.privateKey }),
    remoteDhPublicKey: remoteDh.publicKey,
  });

  const ctx = manager.getSendContext("peer-a");
  assert.deepEqual(ctx.sid, sid);
  assert.ok(ctx.ratchetState);
});

test("createResponderSession stores and getRecvContext works", async (t) => {
  const crypto = makeProvider();
  const ratchet = new RatchetService({ crypto });
  const selfDh = crypto.dhGenerateKeyPair();
  const remoteDh = crypto.dhGenerateKeyPair();

  const manager = new MemorySessionManager({ ratchetService: ratchet, crypto });
  const sid = await manager.createResponderSession({
    peerId: "peer-b",
    sharedSecret: fixedSecret(),
    selfDhKeyPair: new RatchetKeyPair({ publicKey: selfDh.publicKey, privateKey: selfDh.privateKey }),
    remoteDhPublicKey: remoteDh.publicKey,
  });

  const ctx = manager.getRecvContext(sid);
  assert.equal(ctx.peerId, "peer-b");
  assert.ok(ctx.ratchetState);
});

test("commit updates ratchet state", async (t) => {
  const crypto = makeProvider();
  const ratchet = new RatchetService({ crypto });
  const selfDh = crypto.dhGenerateKeyPair();
  const remoteDh = crypto.dhGenerateKeyPair();

  const manager = new MemorySessionManager({ ratchetService: ratchet, crypto });
  await manager.createInitiatorSession({
    peerId: "peer-c",
    sharedSecret: fixedSecret(),
    selfDhKeyPair: new RatchetKeyPair({ publicKey: selfDh.publicKey, privateKey: selfDh.privateKey }),
    remoteDhPublicKey: remoteDh.publicKey,
  });

  const send = manager.getSendContext("peer-c");
  const { newState } = await ratchet.nextSendingMessageKey(send.ratchetState);
  send.commit(newState);

  const next = manager.getSendContext("peer-c");
  assert.equal(next.ratchetState.sendingChain.messageIndex, newState.sendingChain.messageIndex);
});

test("unknown session errors", (t) => {
  const crypto = makeProvider();
  const ratchet = new RatchetService({ crypto });
  const manager = new MemorySessionManager({ ratchetService: ratchet, crypto });

  assert.throws(() => manager.getSendContext("missing"), NoSessionForPeerError);
  assert.throws(() => manager.getRecvContext(new Uint8Array(32)), UnknownSessionError);
});

test("includeDh cleared after commit by default", async (t) => {
  const crypto = makeProvider();
  const ratchet = new RatchetService({ crypto });
  const selfDh = crypto.dhGenerateKeyPair();
  const remoteDh = crypto.dhGenerateKeyPair();

  const manager = new MemorySessionManager({ ratchetService: ratchet, crypto });
  await manager.createInitiatorSession({
    peerId: "peer-d",
    sharedSecret: fixedSecret(),
    selfDhKeyPair: new RatchetKeyPair({ publicKey: selfDh.publicKey, privateKey: selfDh.privateKey }),
    remoteDhPublicKey: remoteDh.publicKey,
  });

  await manager.rotateDh("peer-d");
  const send = manager.getSendContext("peer-d");
  assert.equal(send.includeDh, true);

  const { newState } = await ratchet.nextSendingMessageKey(send.ratchetState);
  send.commit(newState);

  const next = manager.getSendContext("peer-d");
  assert.equal(next.includeDh, false);
});
