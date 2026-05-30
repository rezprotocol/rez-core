import test from "node:test";
import assert from "node:assert/strict";
import { X3DHService } from "../src/services/X3DHService.js";
import { X3DHPreKeyBundle } from "../src/objects/x3dh/X3DHPreKeyBundle.js";
import { X3DHInitiatorHandshake } from "../src/objects/x3dh/X3DHInitiatorHandshake.js";
import { FakeCryptoProvider } from "./support/FakeCryptoProvider.js";

function makeProvider() {
  return new FakeCryptoProvider();
}

function makeIdentityKeyPair(crypto) {
  const key = crypto.randomBytes(32);
  return { publicKey: key, privateKey: key };
}

async function makeReceiver(service, crypto, receiverId) {
  const identityKeyPair = makeIdentityKeyPair(crypto);
  const identityDhKeyPair = crypto.dhGenerateKeyPair();
  const signedPreKey = crypto.dhGenerateKeyPair();
  const bundle = await service.createReceiverBundle({
    receiverId,
    identityKeyPair,
    identityDhKeyPair,
    signedPreKeyKeyPair: signedPreKey,
    oneTimePreKeyPublic: null,
  });
  return { identityKeyPair, identityDhKeyPair, signedPreKey, bundle };
}

async function makeInitiator(service, crypto) {
  const identityKeyPair = makeIdentityKeyPair(crypto);
  const identityDhKeyPair = crypto.dhGenerateKeyPair();
  const identityDhSignature = await crypto.sign({
    privateKey: identityKeyPair.privateKey,
    msg: identityDhKeyPair.publicKey,
  });
  return { identityKeyPair, identityDhKeyPair, identityDhSignature };
}

test("X3DH shared secrets match (with OPK)", async () => {
  const crypto = makeProvider();
  const service = new X3DHService({ crypto });
  const receiver = await makeReceiver(service, crypto, "receiver-1");
  const oneTimePreKey = crypto.dhGenerateKeyPair();
  receiver.bundle.oneTimePreKeyPublic = oneTimePreKey.publicKey;

  const initiator = await makeInitiator(service, crypto);
  const { handshake, sharedSecret } = await service.initiatorCompute({
    receiverBundle: receiver.bundle,
    initiatorIdentityKeyPair: initiator.identityKeyPair,
    initiatorIdentityDhKeyPair: initiator.identityDhKeyPair,
    initiatorIdentityDhSignature: initiator.identityDhSignature,
  });
  const receiverSecret = await service.receiverCompute({
    receiverBundle: receiver.bundle,
    receiverIdentityDhPrivate: receiver.identityDhKeyPair.privateKey,
    receiverSignedPreKeyPrivate: receiver.signedPreKey.privateKey,
    receiverOneTimePreKeyPrivate: oneTimePreKey.privateKey,
    initiatorHandshake: handshake,
  });

  assert.deepEqual(sharedSecret, receiverSecret);
  assert.equal(handshake.usedOneTimePreKey, true);
});

test("X3DH shared secrets match (without OPK)", async () => {
  const crypto = makeProvider();
  const service = new X3DHService({ crypto });
  const receiver = await makeReceiver(service, crypto, "receiver-2");
  const initiator = await makeInitiator(service, crypto);

  const { handshake, sharedSecret } = await service.initiatorCompute({
    receiverBundle: receiver.bundle,
    initiatorIdentityKeyPair: initiator.identityKeyPair,
    initiatorIdentityDhKeyPair: initiator.identityDhKeyPair,
    initiatorIdentityDhSignature: initiator.identityDhSignature,
  });
  const receiverSecret = await service.receiverCompute({
    receiverBundle: receiver.bundle,
    receiverIdentityDhPrivate: receiver.identityDhKeyPair.privateKey,
    receiverSignedPreKeyPrivate: receiver.signedPreKey.privateKey,
    receiverOneTimePreKeyPrivate: null,
    initiatorHandshake: handshake,
  });

  assert.deepEqual(sharedSecret, receiverSecret);
  assert.equal(handshake.usedOneTimePreKey, false);
});

test("X3DH verifies signed prekey signature", async () => {
  const crypto = makeProvider();
  const service = new X3DHService({ crypto });
  const receiver = await makeReceiver(service, crypto, "receiver-3");
  const initiator = await makeInitiator(service, crypto);

  const tampered = new X3DHPreKeyBundle({
    receiverId: receiver.bundle.receiverId,
    identitySigningPublicKey: receiver.bundle.identitySigningPublicKey,
    identityDhPublicKey: receiver.bundle.identityDhPublicKey,
    identityDhSignature: receiver.bundle.identityDhSignature,
    signedPreKeyPublic: new Uint8Array([...receiver.bundle.signedPreKeyPublic].reverse()),
    signedPreKeySignature: receiver.bundle.signedPreKeySignature,
    oneTimePreKeyPublic: receiver.bundle.oneTimePreKeyPublic,
  });

  await assert.rejects(
    () => service.initiatorCompute({
      receiverBundle: tampered,
      initiatorIdentityKeyPair: initiator.identityKeyPair,
      initiatorIdentityDhKeyPair: initiator.identityDhKeyPair,
      initiatorIdentityDhSignature: initiator.identityDhSignature,
    }),
    /signedPreKey signature verification failed/,
  );
});

test("X3DH verifies receiver identity-DH signature in bundle", async () => {
  const crypto = makeProvider();
  const service = new X3DHService({ crypto });
  const receiver = await makeReceiver(service, crypto, "receiver-4");
  const initiator = await makeInitiator(service, crypto);

  const tampered = new X3DHPreKeyBundle({
    receiverId: receiver.bundle.receiverId,
    identitySigningPublicKey: receiver.bundle.identitySigningPublicKey,
    identityDhPublicKey: new Uint8Array([...receiver.bundle.identityDhPublicKey].reverse()),
    identityDhSignature: receiver.bundle.identityDhSignature,
    signedPreKeyPublic: receiver.bundle.signedPreKeyPublic,
    signedPreKeySignature: receiver.bundle.signedPreKeySignature,
    oneTimePreKeyPublic: receiver.bundle.oneTimePreKeyPublic,
  });

  await assert.rejects(
    () => service.initiatorCompute({
      receiverBundle: tampered,
      initiatorIdentityKeyPair: initiator.identityKeyPair,
      initiatorIdentityDhKeyPair: initiator.identityDhKeyPair,
      initiatorIdentityDhSignature: initiator.identityDhSignature,
    }),
    /identityDh signature verification failed/,
  );
});

test("X3DH receiver rejects handshake whose senderIdentityDh signature is invalid", async () => {
  const crypto = makeProvider();
  const service = new X3DHService({ crypto });
  const receiver = await makeReceiver(service, crypto, "receiver-5");
  const initiator = await makeInitiator(service, crypto);

  const { handshake } = await service.initiatorCompute({
    receiverBundle: receiver.bundle,
    initiatorIdentityKeyPair: initiator.identityKeyPair,
    initiatorIdentityDhKeyPair: initiator.identityDhKeyPair,
    initiatorIdentityDhSignature: initiator.identityDhSignature,
  });

  // Swap in a forged senderIdentityDhPublicKey while keeping the original
  // (now stale) signature. Receiver MUST reject — without this check, an
  // attacker could substitute their own DH pubkey and read the channel.
  const forged = new X3DHInitiatorHandshake({
    receiverId: handshake.receiverId,
    senderIdentitySigningPublicKey: handshake.senderIdentitySigningPublicKey,
    senderIdentityDhPublicKey: new Uint8Array([...handshake.senderIdentityDhPublicKey].reverse()),
    senderIdentityDhSignature: handshake.senderIdentityDhSignature,
    ephemeralPublicKey: handshake.ephemeralPublicKey,
    usedOneTimePreKey: handshake.usedOneTimePreKey,
  });

  await assert.rejects(
    () => service.receiverCompute({
      receiverBundle: receiver.bundle,
      receiverIdentityDhPrivate: receiver.identityDhKeyPair.privateKey,
      receiverSignedPreKeyPrivate: receiver.signedPreKey.privateKey,
      receiverOneTimePreKeyPrivate: null,
      initiatorHandshake: forged,
    }),
    /sender identityDh signature verification failed/,
  );
});

test("X3DH impersonation attempt: attacker substitutes own identity keys → shared-secret mismatch", async () => {
  const crypto = makeProvider();
  const service = new X3DHService({ crypto });
  const alice = await makeReceiver(service, crypto, "alice");

  // Bob is the legitimate counterparty. The receiver expects DH1 to bind to
  // Bob's identity DH key, but Mallory will substitute her own identity.
  const mallory = await makeInitiator(service, crypto);

  // Mallory completes the X3DH normally — she derives a shared secret using
  // her own identity. The crypto layer doesn't reject Mallory: she's a
  // legitimate (different) initiator. The defense is that the secret is
  // tied to Mallory's identity, so when Alice later receives a handshake
  // packet claiming to be "from Bob", the senderIdentityPubKey in the packet
  // is Mallory's — not Bob's — and the chat layer can reject on that basis.
  const { handshake, sharedSecret } = await service.initiatorCompute({
    receiverBundle: alice.bundle,
    initiatorIdentityKeyPair: mallory.identityKeyPair,
    initiatorIdentityDhKeyPair: mallory.identityDhKeyPair,
    initiatorIdentityDhSignature: mallory.identityDhSignature,
  });

  const aliceSecret = await service.receiverCompute({
    receiverBundle: alice.bundle,
    receiverIdentityDhPrivate: alice.identityDhKeyPair.privateKey,
    receiverSignedPreKeyPrivate: alice.signedPreKey.privateKey,
    receiverOneTimePreKeyPrivate: null,
    initiatorHandshake: handshake,
  });

  // Shared secret matches because both ran the same computation honestly.
  // The impersonation defense is the senderIdentitySigningPublicKey in the
  // handshake — it is Mallory's, not Bob's. The accountId-from-pubkey check
  // happens above this layer.
  assert.deepEqual(sharedSecret, aliceSecret);
  assert.deepEqual(
    handshake.senderIdentitySigningPublicKey,
    mallory.identityKeyPair.publicKey,
    "handshake carries the attacker's actual identity, not the impersonated one",
  );
});
