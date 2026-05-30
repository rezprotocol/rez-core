import {
  X3DHPreKeyBundle,
  bytesToBase64,
  base64ToBytes,
} from "../index.js";

/**
 * Handles embedding X3DH key material in invite bindings and extracting it
 * during invite acceptance. App-agnostic.
 *
 * Bundle wire shape includes the receiver's long-term identity-DH public key
 * and an Ed25519 signature over it by the receiver's identity signing key.
 * Without these, an attacker who learned only the receiver's signed prekey
 * could complete X3DH and impersonate any sender; see docs/SECURITY_AUDIT.md
 * CRITICAL-1.
 */
export class X3DHKeyExchange {
  #secureChannelManager;

  constructor({ secureChannelManager } = {}) {
    if (!secureChannelManager) {
      throw new Error("X3DHKeyExchange requires secureChannelManager");
    }
    this.#secureChannelManager = secureChannelManager;
  }

  /**
   * Called by invite creator to generate and embed X3DH bundle in invite binding.
   * @param {{
   *   accountId: string,
   *   identityKeyPair: { publicKey: Uint8Array, privateKey: Uint8Array },
   *   identityDhKeyPair: { publicKey: Uint8Array, privateKey: Uint8Array },
   *   existingBinding?: object,
   *   accountBinding?: object,
   * }} opts
   * @returns {{ binding: object, preKeyState: object }}
   */
  async prepareInviteBinding({
    accountId,
    identityKeyPair,
    identityDhKeyPair,
    existingBinding = {},
    accountBinding = null,
  } = {}) {
    const { bundle, signedPreKeyPair } = await this.#secureChannelManager.generatePreKeyBundle({
      accountId,
      identityKeyPair,
      identityDhKeyPair,
    });
    if (accountBinding && typeof accountBinding === "object") {
      bundle.accountIdentityPublicKeyB64 = accountBinding.accountIdentityPublicKeyB64 || null;
      bundle.accountBindingSigB64 = accountBinding.accountBindingSigB64 || null;
      bundle.accountBindingIssuedAtMs = accountBinding.issuedAtMs == null ? null : accountBinding.issuedAtMs;
      bundle.accountBindingExpiresAtMs = accountBinding.expiresAtMs == null ? null : accountBinding.expiresAtMs;
    }

    const serializedBundle = X3DHKeyExchange.serializeBundle(bundle);

    const binding = {
      ...existingBinding,
      x3dh: serializedBundle,
    };

    const preKeyState = {
      signedPreKeyPrivate: bytesToBase64(signedPreKeyPair.privateKey),
      signedPreKeyPublic: bytesToBase64(signedPreKeyPair.publicKey),
      bundleJson: serializedBundle,
    };

    return { binding, preKeyState };
  }

  /**
   * Called by invite acceptor to extract X3DH bundle and establish initiator session.
   * @param {{
   *   inviteBinding: object,
   *   peerId: string,
   *   initiatorIdentityKeyPair: { publicKey: Uint8Array, privateKey: Uint8Array },
   *   initiatorIdentityDhKeyPair: { publicKey: Uint8Array, privateKey: Uint8Array },
   *   initiatorIdentityDhSignature: Uint8Array,
   * }} opts
   * @returns {{ handshakeData: object, sid: Uint8Array }}
   */
  async processAcceptedInvite({
    inviteBinding,
    peerId,
    initiatorIdentityKeyPair,
    initiatorIdentityDhKeyPair,
    initiatorIdentityDhSignature,
  } = {}) {
    if (!inviteBinding || !inviteBinding.x3dh) {
      throw new Error("processAcceptedInvite requires inviteBinding with x3dh field");
    }
    if (!peerId || typeof peerId !== "string") {
      throw new Error("processAcceptedInvite requires peerId string");
    }

    const bundle = X3DHKeyExchange.deserializeBundle(inviteBinding.x3dh);

    const { sid, handshakeData } = await this.#secureChannelManager.establishInitiatorSession({
      peerId,
      receiverBundle: bundle,
      initiatorIdentityKeyPair,
      initiatorIdentityDhKeyPair,
      initiatorIdentityDhSignature,
    });

    return { handshakeData, sid };
  }

  /**
   * Called by invite creator when handshake message is received from acceptor.
   * @param {{
   *   preKeyState: object,
   *   identityDhPrivate: Uint8Array,
   *   handshakeData: object,
   *   peerId: string,
   * }} opts
   * @returns {{ sid: Uint8Array, senderIdentitySigningPublicKey: Uint8Array }}
   */
  async completeInviteHandshake({
    preKeyState,
    identityDhPrivate,
    handshakeData,
    peerId,
  } = {}) {
    if (!preKeyState) {
      throw new Error("completeInviteHandshake requires preKeyState");
    }
    if (!(identityDhPrivate instanceof Uint8Array)) {
      throw new Error("completeInviteHandshake requires identityDhPrivate Uint8Array");
    }
    if (!handshakeData) {
      throw new Error("completeInviteHandshake requires handshakeData");
    }
    if (!peerId || typeof peerId !== "string") {
      throw new Error("completeInviteHandshake requires peerId string");
    }

    const signedPreKeyPrivate = base64ToBytes(preKeyState.signedPreKeyPrivate);
    const receiverBundle = X3DHKeyExchange.deserializeBundle(preKeyState.bundleJson);

    const { sid, senderIdentitySigningPublicKey } = await this.#secureChannelManager.establishResponderSession({
      peerId,
      signedPreKeyPrivate,
      identityDhPrivate,
      receiverBundle,
      handshakeData,
    });

    return { sid, senderIdentitySigningPublicKey };
  }

  /**
   * Serialize an X3DHPreKeyBundle to a JSON-safe object with base64 strings.
   * @param {X3DHPreKeyBundle} bundle
   * @returns {object}
   */
  static serializeBundle(bundle) {
    if (!(bundle instanceof X3DHPreKeyBundle)) {
      throw new Error("serializeBundle requires X3DHPreKeyBundle");
    }
    return {
      receiverId: bundle.receiverId,
      identitySigningPublicKeyB64: bytesToBase64(bundle.identitySigningPublicKey),
      identityDhPublicKeyB64: bytesToBase64(bundle.identityDhPublicKey),
      identityDhSignatureB64: bytesToBase64(bundle.identityDhSignature),
      signedPreKeyPublicB64: bytesToBase64(bundle.signedPreKeyPublic),
      signedPreKeySignatureB64: bytesToBase64(bundle.signedPreKeySignature),
      accountIdentityPublicKeyB64: bundle.accountIdentityPublicKeyB64 || null,
      accountBindingSigB64: bundle.accountBindingSigB64 || null,
      accountBindingIssuedAtMs: Number(bundle.accountBindingIssuedAtMs) || null,
      accountBindingExpiresAtMs: Number(bundle.accountBindingExpiresAtMs) || null,
      oneTimePreKeyPublicB64: bundle.oneTimePreKeyPublic
        ? bytesToBase64(bundle.oneTimePreKeyPublic)
        : null,
    };
  }

  /**
   * Deserialize a JSON object to an X3DHPreKeyBundle.
   * @param {object} json
   * @returns {X3DHPreKeyBundle}
   */
  static deserializeBundle(json) {
    if (!json || typeof json !== "object") {
      throw new Error("deserializeBundle requires object");
    }
    const bundle = new X3DHPreKeyBundle({
      receiverId: json.receiverId,
      identitySigningPublicKey: base64ToBytes(json.identitySigningPublicKeyB64),
      identityDhPublicKey: base64ToBytes(json.identityDhPublicKeyB64),
      identityDhSignature: base64ToBytes(json.identityDhSignatureB64),
      signedPreKeyPublic: base64ToBytes(json.signedPreKeyPublicB64),
      signedPreKeySignature: base64ToBytes(json.signedPreKeySignatureB64),
      oneTimePreKeyPublic: json.oneTimePreKeyPublicB64
        ? base64ToBytes(json.oneTimePreKeyPublicB64)
        : null,
    });
    bundle.accountIdentityPublicKeyB64 = typeof json.accountIdentityPublicKeyB64 === "string" ? json.accountIdentityPublicKeyB64 : null;
    bundle.accountBindingSigB64 = typeof json.accountBindingSigB64 === "string" ? json.accountBindingSigB64 : null;
    bundle.accountBindingIssuedAtMs = Number(json.accountBindingIssuedAtMs) || null;
    bundle.accountBindingExpiresAtMs = Number(json.accountBindingExpiresAtMs) || null;
    return bundle;
  }

  /**
   * Serialize an X3DH handshake data object (already in JSON-friendly format).
   * @param {object} handshake
   * @returns {object}
   */
  static serializeHandshake(handshake) {
    if (!handshake || typeof handshake !== "object") {
      throw new Error("serializeHandshake requires object");
    }
    return { ...handshake };
  }

  /**
   * Deserialize handshake data (identity operation, data is already JSON-friendly).
   * @param {object} json
   * @returns {object}
   */
  static deserializeHandshake(json) {
    if (!json || typeof json !== "object") {
      throw new Error("deserializeHandshake requires object");
    }
    return { ...json };
  }
}
