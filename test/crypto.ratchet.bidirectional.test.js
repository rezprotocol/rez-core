// Regression: a DH ratchet step must establish ONLY the chain being created and
// PRESERVE the opposite chain. The responder's lazy first-send used to replace
// BOTH chains, clobbering its receiving chain (the initiator's still-active send
// chain). The initiator then kept sending on the original chain (e.g. a message
// sent while the responder was offline), and after the responder reloaded it
// could no longer decrypt it — the live group offline-catch-up failure
// (2026-06-04). See ratchetStep({ establish }).

import test from "node:test";
import assert from "node:assert/strict";
import { RatchetService } from "../src/services/RatchetService.js";
import { RatchetKeyPair } from "../src/objects/ratchet/RatchetKeyPair.js";
import { FakeCryptoProvider } from "./support/FakeCryptoProvider.js";

function kp(dh) {
  return new RatchetKeyPair({ publicKey: dh.publicKey, privateKey: dh.privateKey });
}

function fixedSecret() {
  const bytes = new Uint8Array(32);
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = (i * 7 + 3) & 0xff;
  return bytes;
}

test("responder lazy send-step preserves receiving chain; initiator's old-chain message still decrypts", async () => {
  const crypto = new FakeCryptoProvider();
  const initiatorDh = crypto.dhGenerateKeyPair(); // Bob (X3DH initiator)
  const responderDh = crypto.dhGenerateKeyPair(); // Alice (X3DH responder / inviter)
  const sharedSecret = fixedSecret();
  const service = new RatchetService({ crypto });

  const bob = service.initializeAsInitiator({
    sharedSecret,
    selfDhKeyPair: kp(initiatorDh),
    remoteDhPublicKey: responderDh.publicKey,
  });
  const alice = service.initializeAsResponder({
    sharedSecret,
    selfDhKeyPair: kp(responderDh),
    remoteDhPublicKey: initiatorDh.publicKey,
  });

  // Baseline: initiator's sending chain == responder's receiving chain.
  assert.deepEqual(bob.sendingChain.chainKey, alice.receivingChain.chainKey);

  // Responder sends first → establishes ONLY her sending chain.
  const { newState: aliceAfterSend } = await service.ratchetStep(
    alice, alice.remoteDhPublicKey, { establish: "sending" },
  );
  // Her receiving chain is PRESERVED — still aligned with the initiator's
  // still-active sending chain. (With the old "both" behavior this was clobbered.)
  assert.deepEqual(
    aliceAfterSend.receivingChain.chainKey, bob.sendingChain.chainKey,
    "responder receiving chain must survive its own lazy send-step",
  );
  assert.ok(aliceAfterSend.sendingChain, "responder now has a sending chain");

  // Initiator receives the responder's first message → establishes ONLY his
  // receiving chain; his sending chain is preserved (keeps sending on it).
  const { newState: bobAfterRecv } = await service.ratchetStep(
    bob, responderDh.publicKey, { establish: "receiving" },
  );
  assert.deepEqual(
    bobAfterRecv.sendingChain.chainKey, sharedSecret,
    "initiator sending chain must survive receiving the responder's step",
  );

  // The initiator's NEXT message on its (preserved) original chain must decrypt
  // on the responder's (preserved) receiving chain — this is the message that
  // was being lost.
  const bobMsg = await service.nextSendingMessageKey(bobAfterRecv);
  const aliceRecv = await service.nextReceivingMessageKey(aliceAfterSend);
  assert.deepEqual(
    bobMsg.messageKey, aliceRecv.messageKey,
    "initiator's post-step message decrypts on the responder's preserved chain",
  );

  // And the new responder→initiator direction is aligned too.
  assert.deepEqual(
    aliceAfterSend.sendingChain.chainKey, bobAfterRecv.receivingChain.chainKey,
    "responder sending chain == initiator receiving chain (new direction works)",
  );
});

test("ratchetStep establish:'both' (default) still replaces both chains", async () => {
  const crypto = new FakeCryptoProvider();
  const initiatorDh = crypto.dhGenerateKeyPair();
  const responderDh = crypto.dhGenerateKeyPair();
  const service = new RatchetService({ crypto });
  const alice = service.initializeAsResponder({
    sharedSecret: fixedSecret(),
    selfDhKeyPair: kp(responderDh),
    remoteDhPublicKey: initiatorDh.publicKey,
  });
  const { newState } = await service.ratchetStep(alice, alice.remoteDhPublicKey);
  // Legacy behavior: both chains installed fresh (messageIndex 0, new keys).
  assert.equal(newState.sendingChain.messageIndex, 0);
  assert.equal(newState.receivingChain.messageIndex, 0);
  assert.notDeepEqual(newState.receivingChain.chainKey, alice.receivingChain.chainKey);
});
