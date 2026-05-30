import test from "node:test";
import assert from "node:assert/strict";
import { RatchetService } from "../src/services/RatchetService.js";
import { RatchetKeyPair } from "../src/objects/ratchet/RatchetKeyPair.js";
import { FakeCryptoProvider } from "./support/FakeCryptoProvider.js";

function makeProvider() {
  return new FakeCryptoProvider();
}

function fixedSecret() {
  const bytes = new Uint8Array(32);
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = i;
  return bytes;
}

test("Ratchet initiator/responder stay in sync after step", async (t) => {
  const crypto = makeProvider();
  const initiatorDh = crypto.dhGenerateKeyPair();
  const responderDh = crypto.dhGenerateKeyPair();
  const sharedSecret = fixedSecret();

  const service = new RatchetService({ crypto });
  const initiatorState = service.initializeAsInitiator({
    sharedSecret,
    selfDhKeyPair: new RatchetKeyPair({ publicKey: initiatorDh.publicKey, privateKey: initiatorDh.privateKey }),
    remoteDhPublicKey: responderDh.publicKey,
  });
  const responderState = service.initializeAsResponder({
    sharedSecret,
    selfDhKeyPair: new RatchetKeyPair({ publicKey: responderDh.publicKey, privateKey: responderDh.privateKey }),
    remoteDhPublicKey: initiatorDh.publicKey,
  });

  const { newState: initiatorNext } = await service.ratchetStep(initiatorState, responderDh.publicKey);
  const { newState: responderNext } = await service.ratchetStep(responderState, initiatorDh.publicKey);

  assert.deepEqual(initiatorNext.rootKey, responderNext.rootKey);
  assert.deepEqual(initiatorNext.sendingChain.chainKey, responderNext.receivingChain.chainKey);
  assert.deepEqual(initiatorNext.receivingChain.chainKey, responderNext.sendingChain.chainKey);
});

test("Ratchet message key evolution", async (t) => {
  const crypto = makeProvider();
  const initiatorDh = crypto.dhGenerateKeyPair();
  const responderDh = crypto.dhGenerateKeyPair();
  const sharedSecret = fixedSecret();

  const service = new RatchetService({ crypto });
  const state = service.initializeAsInitiator({
    sharedSecret,
    selfDhKeyPair: new RatchetKeyPair({ publicKey: initiatorDh.publicKey, privateKey: initiatorDh.privateKey }),
    remoteDhPublicKey: responderDh.publicKey,
  });

  const first = await service.nextSendingMessageKey(state);
  const second = await service.nextSendingMessageKey(first.newState);

  assert.notDeepEqual(first.messageKey, second.messageKey);
  assert.notDeepEqual(first.newState.sendingChain.chainKey, second.newState.sendingChain.chainKey);
  assert.equal(first.newState.sendingChain.messageIndex, 1);
  assert.equal(second.newState.sendingChain.messageIndex, 2);
});

test("Ratchet step replaces chain keys", async (t) => {
  const crypto = makeProvider();
  const initiatorDh = crypto.dhGenerateKeyPair();
  const responderDh = crypto.dhGenerateKeyPair();
  const sharedSecret = fixedSecret();

  const service = new RatchetService({ crypto });
  const state = service.initializeAsInitiator({
    sharedSecret,
    selfDhKeyPair: new RatchetKeyPair({ publicKey: initiatorDh.publicKey, privateKey: initiatorDh.privateKey }),
    remoteDhPublicKey: responderDh.publicKey,
  });

  const before = await service.nextSendingMessageKey(state);
  const { newState } = await service.ratchetStep(before.newState, responderDh.publicKey);
  const after = await service.nextSendingMessageKey(newState);

  assert.notDeepEqual(before.messageKey, after.messageKey);
  assert.notDeepEqual(before.newState.sendingChain.chainKey, after.newState.sendingChain.chainKey);
});

test("Ratchet determinism for same inputs", async (t) => {
  const crypto = makeProvider();
  const initiatorDh = crypto.dhGenerateKeyPair();
  const responderDh = crypto.dhGenerateKeyPair();
  const sharedSecret = fixedSecret();

  const service = new RatchetService({ crypto });
  const stateA = service.initializeAsInitiator({
    sharedSecret,
    selfDhKeyPair: new RatchetKeyPair({ publicKey: initiatorDh.publicKey, privateKey: initiatorDh.privateKey }),
    remoteDhPublicKey: responderDh.publicKey,
  });
  const stateB = service.initializeAsInitiator({
    sharedSecret,
    selfDhKeyPair: new RatchetKeyPair({ publicKey: initiatorDh.publicKey, privateKey: initiatorDh.privateKey }),
    remoteDhPublicKey: responderDh.publicKey,
  });

  const { newState: nextA } = await service.ratchetStep(stateA, responderDh.publicKey);
  const { newState: nextB } = await service.ratchetStep(stateB, responderDh.publicKey);

  assert.deepEqual(nextA.rootKey, nextB.rootKey);
  assert.deepEqual(nextA.sendingChain.chainKey, nextB.sendingChain.chainKey);
  assert.deepEqual(nextA.receivingChain.chainKey, nextB.receivingChain.chainKey);
});
