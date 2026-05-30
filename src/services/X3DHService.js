import { RService } from "../base/index.js";
import { RCryptoProvider } from "../crypto/RCryptoProvider.js";
import { X3DHPreKeyBundle } from "../objects/x3dh/X3DHPreKeyBundle.js";
import { X3DHInitiatorHandshake } from "../objects/x3dh/X3DHInitiatorHandshake.js";
import { RLogger } from "../base/index.js";
import { NullLogTransport } from "../base/index.js";
import { concatBytes } from "../crypto/util/bytes.js";
import { isNonEmptyString } from "../util/strings.js";

const HKDF_INFO = new TextEncoder().encode("rez-x3dh-v2");

function isBytes(value) {
  return value instanceof Uint8Array;
}

function assertMinKeyBytes(bytes, label) {
  if (!isBytes(bytes)) {
    throw new Error(`X3DHService requires ${label} Uint8Array`);
  }
  if (bytes.length < 32) {
    throw new Error(`X3DHService requires ${label} length >= 32`);
  }
}

function assertSecretBytes(bytes) {
  if (!isBytes(bytes)) {
    throw new Error("X3DHService requires shared secret Uint8Array");
  }
  if (bytes.length !== 32) {
    throw new Error("X3DHService requires shared secret length 32");
  }
}

/**
 * X3DH key agreement with long-term identity DH binding.
 *
 * Diffie-Hellmans computed in initiatorCompute / receiverCompute:
 *   DH1 = X25519(initiator.identityDh.priv, receiver.signedPreKey.pub)
 *   DH2 = X25519(initiator.ephemeral.priv,  receiver.identityDh.pub)
 *   DH3 = X25519(initiator.ephemeral.priv,  receiver.signedPreKey.pub)
 *   DH4 = X25519(initiator.ephemeral.priv,  receiver.oneTimePreKey.pub)   // if OPK present
 *
 * IKM = DH1 || DH2 || DH3 [|| DH4]. HKDF info "rez-x3dh-v2".
 *
 * Identity binding: each side owns an Ed25519 signing keypair and a separate
 * long-term X25519 "identity DH" keypair, with the Ed25519 key signing the
 * X25519 pubkey to bind them. Receivers verify the initiator's signature
 * over its identity DH pubkey before computing DH1.
 */
export class X3DHService extends RService {
  constructor({ crypto, logger } = {}) {
    const log = logger || new RLogger({ transports: [new NullLogTransport()] });
    super({ log });

    if (!(crypto instanceof RCryptoProvider)) {
      throw new Error("X3DHService requires crypto (RCryptoProvider)");
    }
    if (!(log instanceof RLogger)) {
      throw new Error("X3DHService requires logger (RLogger)");
    }

    this.crypto = crypto;
    this.log = log;
  }

  async createReceiverBundle({
    receiverId,
    identityKeyPair,
    identityDhKeyPair,
    signedPreKeyKeyPair,
    oneTimePreKeyPublic = null,
  } = {}) {
    if (!isNonEmptyString(receiverId)) {
      throw new Error("X3DHService.createReceiverBundle requires receiverId");
    }
    if (!isBytes(identityKeyPair && identityKeyPair.publicKey) || !isBytes(identityKeyPair && identityKeyPair.privateKey)) {
      throw new Error("X3DHService.createReceiverBundle requires identityKeyPair publicKey/privateKey bytes");
    }
    if (!isBytes(identityDhKeyPair && identityDhKeyPair.publicKey) || !isBytes(identityDhKeyPair && identityDhKeyPair.privateKey)) {
      throw new Error("X3DHService.createReceiverBundle requires identityDhKeyPair publicKey/privateKey bytes");
    }
    if (!signedPreKeyKeyPair || !signedPreKeyKeyPair.publicKey || !signedPreKeyKeyPair.privateKey) {
      throw new Error("X3DHService.createReceiverBundle requires signedPreKeyKeyPair bytes");
    }
    assertMinKeyBytes(signedPreKeyKeyPair.publicKey, "signedPreKeyKeyPair.publicKey");
    assertMinKeyBytes(identityDhKeyPair.publicKey, "identityDhKeyPair.publicKey");
    if (oneTimePreKeyPublic != null) {
      assertMinKeyBytes(oneTimePreKeyPublic, "oneTimePreKeyPublic");
    }

    const signedPreKeySignature = await this.crypto.sign({
      privateKey: identityKeyPair.privateKey,
      msg: signedPreKeyKeyPair.publicKey,
    });
    const identityDhSignature = await this.crypto.sign({
      privateKey: identityKeyPair.privateKey,
      msg: identityDhKeyPair.publicKey,
    });

    return new X3DHPreKeyBundle({
      receiverId,
      identitySigningPublicKey: identityKeyPair.publicKey,
      identityDhPublicKey: identityDhKeyPair.publicKey,
      identityDhSignature,
      signedPreKeyPublic: signedPreKeyKeyPair.publicKey,
      signedPreKeySignature,
      oneTimePreKeyPublic: oneTimePreKeyPublic === null ? null : oneTimePreKeyPublic,
    });
  }

  async initiatorCompute({
    receiverBundle,
    initiatorIdentityKeyPair,
    initiatorIdentityDhKeyPair,
    initiatorIdentityDhSignature,
  } = {}) {
    if (!(receiverBundle instanceof X3DHPreKeyBundle)) {
      throw new Error("X3DHService.initiatorCompute requires X3DHPreKeyBundle");
    }
    if (!isBytes(initiatorIdentityKeyPair && initiatorIdentityKeyPair.publicKey)
      || !isBytes(initiatorIdentityKeyPair && initiatorIdentityKeyPair.privateKey)) {
      throw new Error("X3DHService.initiatorCompute requires initiatorIdentityKeyPair publicKey/privateKey bytes");
    }
    if (!isBytes(initiatorIdentityDhKeyPair && initiatorIdentityDhKeyPair.publicKey)
      || !isBytes(initiatorIdentityDhKeyPair && initiatorIdentityDhKeyPair.privateKey)) {
      throw new Error("X3DHService.initiatorCompute requires initiatorIdentityDhKeyPair publicKey/privateKey bytes");
    }
    if (!isBytes(initiatorIdentityDhSignature)) {
      throw new Error("X3DHService.initiatorCompute requires initiatorIdentityDhSignature Uint8Array");
    }
    assertMinKeyBytes(receiverBundle.signedPreKeyPublic, "receiverBundle.signedPreKeyPublic");
    assertMinKeyBytes(receiverBundle.identityDhPublicKey, "receiverBundle.identityDhPublicKey");
    if (receiverBundle.oneTimePreKeyPublic != null) {
      assertMinKeyBytes(receiverBundle.oneTimePreKeyPublic, "receiverBundle.oneTimePreKeyPublic");
    }

    // Verify receiver's bundle bindings: signed prekey AND identity DH key
    // must both be signed by the identity signing key. We MUST do this before
    // running DH against bundle material, otherwise a swapped bundle has
    // already poisoned the secret.
    const spkVerified = await this.crypto.verify({
      publicKey: receiverBundle.identitySigningPublicKey,
      msg: receiverBundle.signedPreKeyPublic,
      sig: receiverBundle.signedPreKeySignature,
    });
    if (!spkVerified) {
      throw new Error("X3DHService.initiatorCompute receiver signedPreKey signature verification failed");
    }
    const idkVerified = await this.crypto.verify({
      publicKey: receiverBundle.identitySigningPublicKey,
      msg: receiverBundle.identityDhPublicKey,
      sig: receiverBundle.identityDhSignature,
    });
    if (!idkVerified) {
      throw new Error("X3DHService.initiatorCompute receiver identityDh signature verification failed");
    }

    // Sanity check: caller's identityDhSignature must verify against caller's
    // own identity signing key. Catches programmer error (wrong key pairing
    // in the keystore) before a wire packet ships.
    const selfBindingVerified = await this.crypto.verify({
      publicKey: initiatorIdentityKeyPair.publicKey,
      msg: initiatorIdentityDhKeyPair.publicKey,
      sig: initiatorIdentityDhSignature,
    });
    if (!selfBindingVerified) {
      throw new Error("X3DHService.initiatorCompute initiatorIdentityDhSignature does not verify against initiatorIdentityKeyPair");
    }

    const ephemeral = await this.crypto.dhGenerateKeyPair({ alg: "X25519", fmt: "spki" });

    const dh1 = await this.crypto.dhDerive({
      privateKey: initiatorIdentityDhKeyPair.privateKey,
      publicKey: receiverBundle.signedPreKeyPublic,
      alg: "X25519",
      fmt: "spki",
    });
    assertSecretBytes(dh1);

    const dh2 = await this.crypto.dhDerive({
      privateKey: ephemeral.privateKey,
      publicKey: receiverBundle.identityDhPublicKey,
      alg: "X25519",
      fmt: "spki",
    });
    assertSecretBytes(dh2);

    const dh3 = await this.crypto.dhDerive({
      privateKey: ephemeral.privateKey,
      publicKey: receiverBundle.signedPreKeyPublic,
      alg: "X25519",
      fmt: "spki",
    });
    assertSecretBytes(dh3);

    const dhValues = [dh1, dh2, dh3];
    let usedOneTimePreKey = false;
    if (receiverBundle.oneTimePreKeyPublic) {
      const dh4 = await this.crypto.dhDerive({
        privateKey: ephemeral.privateKey,
        publicKey: receiverBundle.oneTimePreKeyPublic,
        alg: "X25519",
        fmt: "spki",
      });
      assertSecretBytes(dh4);
      dhValues.push(dh4);
      usedOneTimePreKey = true;
    }

    const ikm = concatBytes(...dhValues);
    const sharedSecret = await this.crypto.hkdfSha256(ikm, { salt: new Uint8Array(0), info: HKDF_INFO, length: 32 });

    const handshake = new X3DHInitiatorHandshake({
      receiverId: receiverBundle.receiverId,
      senderIdentitySigningPublicKey: initiatorIdentityKeyPair.publicKey,
      senderIdentityDhPublicKey: initiatorIdentityDhKeyPair.publicKey,
      senderIdentityDhSignature: initiatorIdentityDhSignature,
      ephemeralPublicKey: ephemeral.publicKey,
      usedOneTimePreKey,
    });

    return { handshake, sharedSecret, ephemeralKeyPair: ephemeral };
  }

  async receiverCompute({
    receiverBundle,
    receiverIdentityDhPrivate,
    receiverSignedPreKeyPrivate,
    receiverOneTimePreKeyPrivate = null,
    initiatorHandshake,
  } = {}) {
    if (!(receiverBundle instanceof X3DHPreKeyBundle)) {
      throw new Error("X3DHService.receiverCompute requires X3DHPreKeyBundle");
    }
    if (!(initiatorHandshake instanceof X3DHInitiatorHandshake)) {
      throw new Error("X3DHService.receiverCompute requires X3DHInitiatorHandshake");
    }
    if (!isBytes(receiverIdentityDhPrivate)) {
      throw new Error("X3DHService.receiverCompute requires receiverIdentityDhPrivate Uint8Array");
    }
    if (!isBytes(receiverSignedPreKeyPrivate)) {
      throw new Error("X3DHService.receiverCompute requires receiverSignedPreKeyPrivate Uint8Array");
    }
    assertMinKeyBytes(receiverIdentityDhPrivate, "receiverIdentityDhPrivate");
    assertMinKeyBytes(receiverSignedPreKeyPrivate, "receiverSignedPreKeyPrivate");
    assertMinKeyBytes(initiatorHandshake.ephemeralPublicKey, "initiatorHandshake.ephemeralPublicKey");
    assertMinKeyBytes(initiatorHandshake.senderIdentitySigningPublicKey, "initiatorHandshake.senderIdentitySigningPublicKey");
    assertMinKeyBytes(initiatorHandshake.senderIdentityDhPublicKey, "initiatorHandshake.senderIdentityDhPublicKey");
    if (initiatorHandshake.receiverId !== receiverBundle.receiverId) {
      throw new Error("X3DHService.receiverCompute receiverId mismatch");
    }

    // The initiator's identity DH pubkey MUST be signed by its identity
    // signing key. Without this binding, anyone could claim to be the
    // initiator and the DH1 binding collapses.
    const senderBindingVerified = await this.crypto.verify({
      publicKey: initiatorHandshake.senderIdentitySigningPublicKey,
      msg: initiatorHandshake.senderIdentityDhPublicKey,
      sig: initiatorHandshake.senderIdentityDhSignature,
    });
    if (!senderBindingVerified) {
      throw new Error("X3DHService.receiverCompute sender identityDh signature verification failed");
    }

    const dh1 = await this.crypto.dhDerive({
      privateKey: receiverSignedPreKeyPrivate,
      publicKey: initiatorHandshake.senderIdentityDhPublicKey,
      alg: "X25519",
      fmt: "spki",
    });
    assertSecretBytes(dh1);

    const dh2 = await this.crypto.dhDerive({
      privateKey: receiverIdentityDhPrivate,
      publicKey: initiatorHandshake.ephemeralPublicKey,
      alg: "X25519",
      fmt: "spki",
    });
    assertSecretBytes(dh2);

    const dh3 = await this.crypto.dhDerive({
      privateKey: receiverSignedPreKeyPrivate,
      publicKey: initiatorHandshake.ephemeralPublicKey,
      alg: "X25519",
      fmt: "spki",
    });
    assertSecretBytes(dh3);

    const dhValues = [dh1, dh2, dh3];

    if (initiatorHandshake.usedOneTimePreKey) {
      if (!isBytes(receiverOneTimePreKeyPrivate)) {
        throw new Error("X3DHService.receiverCompute requires receiverOneTimePreKeyPrivate for OPK");
      }
      assertMinKeyBytes(receiverOneTimePreKeyPrivate, "receiverOneTimePreKeyPrivate");
      const dh4 = await this.crypto.dhDerive({
        privateKey: receiverOneTimePreKeyPrivate,
        publicKey: initiatorHandshake.ephemeralPublicKey,
        alg: "X25519",
        fmt: "spki",
      });
      assertSecretBytes(dh4);
      dhValues.push(dh4);
    }

    const ikm = concatBytes(...dhValues);
    const sharedSecret = await this.crypto.hkdfSha256(ikm, { salt: new Uint8Array(0), info: HKDF_INFO, length: 32 });

    return sharedSecret;
  }
}
