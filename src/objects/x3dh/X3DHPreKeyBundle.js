import { RObject } from "../../base/index.js";
import { isNonEmptyString } from "../../util/strings.js";

function isBytes(value) {
  return value instanceof Uint8Array;
}

/**
 * Receiver-side X3DH pre-key bundle.
 *
 * Contains both the long-term identity signing key (Ed25519) and a long-term
 * identity DH key (X25519) bound to it via signedPreKeySignature-style
 * attestation. Standard X3DH uses one identity key with curve conversion;
 * this implementation keeps the two curves separate and binds them with a
 * signature.
 */
export class X3DHPreKeyBundle extends RObject {
  static type = "X3DHPreKeyBundle";

  constructor({
    receiverId,
    identitySigningPublicKey,
    identityDhPublicKey,
    identityDhSignature,
    signedPreKeyPublic,
    signedPreKeySignature,
    oneTimePreKeyPublic = null,
  } = {}) {
    super();

    this.assert(isNonEmptyString(receiverId), "X3DHPreKeyBundle.receiverId must be a non-empty string", { receiverId });
    this.assert(isBytes(identitySigningPublicKey), "X3DHPreKeyBundle.identitySigningPublicKey must be Uint8Array", { identitySigningPublicKey });
    this.assert(isBytes(identityDhPublicKey), "X3DHPreKeyBundle.identityDhPublicKey must be Uint8Array", { identityDhPublicKey });
    this.assert(isBytes(identityDhSignature), "X3DHPreKeyBundle.identityDhSignature must be Uint8Array", { identityDhSignature });
    this.assert(isBytes(signedPreKeyPublic), "X3DHPreKeyBundle.signedPreKeyPublic must be Uint8Array", { signedPreKeyPublic });
    this.assert(isBytes(signedPreKeySignature), "X3DHPreKeyBundle.signedPreKeySignature must be Uint8Array", { signedPreKeySignature });
    if (oneTimePreKeyPublic != null) {
      this.assert(isBytes(oneTimePreKeyPublic), "X3DHPreKeyBundle.oneTimePreKeyPublic must be Uint8Array or null", { oneTimePreKeyPublic });
    }

    this.receiverId = receiverId;
    this.identitySigningPublicKey = identitySigningPublicKey;
    this.identityDhPublicKey = identityDhPublicKey;
    this.identityDhSignature = identityDhSignature;
    this.signedPreKeyPublic = signedPreKeyPublic;
    this.signedPreKeySignature = signedPreKeySignature;
    this.oneTimePreKeyPublic = oneTimePreKeyPublic === null ? null : oneTimePreKeyPublic;
  }
}
