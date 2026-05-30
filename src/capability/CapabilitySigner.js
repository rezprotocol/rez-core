import { RCapability } from "./RCapability.js";
import { RRecord } from "../base/index.js";

export class CapabilitySigner {
  #crypto;

  constructor({ crypto }) {
    if (!crypto) throw new Error("CapabilitySigner requires crypto (RCryptoProvider)");
    this.#crypto = crypto;
  }

  async createRootCapability({
    resource, actions, constraints = {},
    signerPublicKeyB64, granteePublicKeyB64 = null, privateKeyBytes,
  }) {
    const capId = RRecord.newId("cap", (len) => this.#crypto.randomBytes(len));

    const cap = new RCapability({
      capId,
      parentCapId: null,
      resource,
      actions,
      constraints,
      signerPublicKeyB64,
      granteePublicKeyB64,
      signatureB64: null,
    });

    return this.#signCapability(cap, privateKeyBytes);
  }

  async delegateCapability({
    parentCapability, actions, constraints = {},
    signerPublicKeyB64, granteePublicKeyB64 = null, privateKeyBytes,
  }) {
    const capId = RRecord.newId("cap", (len) => this.#crypto.randomBytes(len));

    const cap = new RCapability({
      capId,
      parentCapId: parentCapability.capId,
      resource: parentCapability.resource,
      actions,
      constraints,
      signerPublicKeyB64,
      granteePublicKeyB64,
      signatureB64: null,
    });

    return this.#signCapability(cap, privateKeyBytes);
  }

  async rotateCapability({ oldCapability, signerPublicKeyB64, privateKeyBytes, newConstraints }) {
    const capId = RRecord.newId("cap", (len) => this.#crypto.randomBytes(len));

    const cap = new RCapability({
      capId,
      parentCapId: oldCapability.parentCapId,
      resource: oldCapability.resource,
      actions: [...oldCapability.actions],
      constraints: newConstraints ?? { ...oldCapability.constraints },
      signerPublicKeyB64,
      granteePublicKeyB64: oldCapability.granteePublicKeyB64,
      signatureB64: null,
    });

    return this.#signCapability(cap, privateKeyBytes);
  }

  async #signCapability(unsignedCap, privateKeyBytes) {
    const payloadBytes = new TextEncoder().encode(unsignedCap._toSignablePayload());
    const sigBytes = await this.#crypto.sign({
      privateKey: privateKeyBytes,
      msg: payloadBytes,
    });
    const signatureB64 = _bytesToB64(sigBytes);

    return new RCapability({
      ...unsignedCap.toJSON(),
      signatureB64,
    });
  }
}

function _bytesToB64(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}
