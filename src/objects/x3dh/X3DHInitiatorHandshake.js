import { RObject } from "../../base/index.js";
import { isNonEmptyString } from "../../util/strings.js";

function isBytes(value) {
  return value instanceof Uint8Array;
}

/**
 * Initiator-side X3DH handshake record.
 *
 * Carries the initiator's long-term identity bindings (signing pubkey +
 * identity DH pubkey + identity-DH signature) so the receiver can verify
 * the initiator's identity before deriving the shared secret. The
 * identity DH pubkey participates in DH1 of the X3DH derivation.
 */
export class X3DHInitiatorHandshake extends RObject {
  static type = "X3DHInitiatorHandshake";

  constructor({
    receiverId,
    senderIdentitySigningPublicKey,
    senderIdentityDhPublicKey,
    senderIdentityDhSignature,
    ephemeralPublicKey,
    usedOneTimePreKey,
  } = {}) {
    super();

    this.assert(isNonEmptyString(receiverId), "X3DHInitiatorHandshake.receiverId must be a non-empty string", { receiverId });
    this.assert(isBytes(senderIdentitySigningPublicKey), "X3DHInitiatorHandshake.senderIdentitySigningPublicKey must be Uint8Array");
    this.assert(isBytes(senderIdentityDhPublicKey), "X3DHInitiatorHandshake.senderIdentityDhPublicKey must be Uint8Array");
    this.assert(isBytes(senderIdentityDhSignature), "X3DHInitiatorHandshake.senderIdentityDhSignature must be Uint8Array");
    this.assert(isBytes(ephemeralPublicKey), "X3DHInitiatorHandshake.ephemeralPublicKey must be Uint8Array", { ephemeralPublicKey });
    this.assert(typeof usedOneTimePreKey === "boolean", "X3DHInitiatorHandshake.usedOneTimePreKey must be boolean", { usedOneTimePreKey });

    this.receiverId = receiverId;
    this.senderIdentitySigningPublicKey = senderIdentitySigningPublicKey;
    this.senderIdentityDhPublicKey = senderIdentityDhPublicKey;
    this.senderIdentityDhSignature = senderIdentityDhSignature;
    this.ephemeralPublicKey = ephemeralPublicKey;
    this.usedOneTimePreKey = usedOneTimePreKey;
  }
}
