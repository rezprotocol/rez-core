import { RResource } from "./RResource.js";

export class CapabilityValidator {
  #crypto;

  constructor({ crypto }) {
    if (!crypto) throw new Error("CapabilityValidator requires crypto (RCryptoProvider)");
    this.#crypto = crypto;
  }

  async verifySignature(capability) {
    if (!capability.signatureB64) {
      return { ok: false, reason: "capability has no signature" };
    }
    const publicKeyBytes = _b64ToBytes(capability.signerPublicKeyB64);
    const payloadBytes = new TextEncoder().encode(capability._toSignablePayload());
    const sigBytes = _b64ToBytes(capability.signatureB64);
    const valid = await this.#crypto.verify({
      publicKey: publicKeyBytes,
      msg: payloadBytes,
      sig: sigBytes,
    });
    return valid
      ? { ok: true }
      : { ok: false, reason: "signature verification failed" };
  }

  validateScopeNarrowing(child, parent) {
    if (child.resource !== parent.resource) {
      return { ok: false, reason: `resource mismatch: child="${child.resource}" parent="${parent.resource}"` };
    }

    for (const a of child.actions) {
      if (!parent.actions.includes(a)) {
        return { ok: false, reason: `child action "${a}" not in parent actions` };
      }
    }

    const cc = child.constraints;
    const pc = parent.constraints;

    if (pc.expiresAt != null) {
      if (cc.expiresAt == null) {
        return { ok: false, reason: "child must have expiresAt when parent does" };
      }
      if (cc.expiresAt > pc.expiresAt) {
        return { ok: false, reason: "child expiresAt must be <= parent expiresAt" };
      }
    }

    if (pc.maxUses != null) {
      if (cc.maxUses == null) {
        return { ok: false, reason: "child must have maxUses when parent does" };
      }
      if (cc.maxUses > pc.maxUses) {
        return { ok: false, reason: "child maxUses must be <= parent maxUses" };
      }
    }

    if (pc.maxDelegationDepth != null) {
      if (cc.maxDelegationDepth == null) {
        return { ok: false, reason: "child must have maxDelegationDepth when parent does" };
      }
      if (cc.maxDelegationDepth > pc.maxDelegationDepth) {
        return { ok: false, reason: "child maxDelegationDepth must be <= parent maxDelegationDepth" };
      }
    }

    return { ok: true };
  }

  /**
   * Validate a capability chain.
   *
   * Each cap carries its own `signerPublicKeyB64` — no external lookup needed.
   * For non-root caps, the cap's `signerPublicKeyB64` must equal the parent's
   * `granteePublicKeyB64` (delegation linkage on pubkey).
   *
   * If `presenterPublicKeyB64` is provided, the leaf's `granteePublicKeyB64`
   * (if non-null) must match it — i.e. the cap was issued to this presenter
   * specifically. If the leaf has no grantee, it's a bearer cap (no presenter
   * check).
   */
  async validateChain(capabilities, { presenterPublicKeyB64 = null } = {}) {
    if (!Array.isArray(capabilities) || capabilities.length === 0) {
      return { ok: false, reason: "empty capability chain" };
    }

    const root = capabilities[0];
    if (root.parentCapId !== null) {
      return { ok: false, reason: "first capability in chain must be a root (parentCapId === null)" };
    }

    for (let i = 0; i < capabilities.length; i++) {
      const cap = capabilities[i];

      const sigResult = await this.verifySignature(cap);
      if (!sigResult.ok) {
        return { ok: false, reason: `signature failed at index ${i}: ${sigResult.reason}`, failedAt: i };
      }

      if (i > 0) {
        const parent = capabilities[i - 1];
        if (cap.parentCapId !== parent.capId) {
          return { ok: false, reason: `parentCapId mismatch at index ${i}`, failedAt: i };
        }

        // Delegation linkage: child must be signed by the principal the parent
        // granted to. If parent has no grantee (bearer), no linkage to check.
        if (parent.granteePublicKeyB64 != null
          && cap.signerPublicKeyB64 !== parent.granteePublicKeyB64) {
          return {
            ok: false,
            reason: `child signer does not match parent grantee at index ${i}`,
            failedAt: i,
          };
        }

        const narrowing = this.validateScopeNarrowing(cap, parent);
        if (!narrowing.ok) {
          return { ok: false, reason: `scope violation at index ${i}: ${narrowing.reason}`, failedAt: i };
        }
      }
    }

    const leaf = capabilities[capabilities.length - 1];
    if (leaf.granteePublicKeyB64 != null
      && typeof presenterPublicKeyB64 === "string"
      && presenterPublicKeyB64.length > 0
      && leaf.granteePublicKeyB64 !== presenterPublicKeyB64) {
      return {
        ok: false,
        reason: "leaf grantee does not match presenter",
        failedAt: capabilities.length - 1,
      };
    }

    return { ok: true, leaf };
  }

  checkConstraints(capability, { nowMs, usageCount } = {}) {
    const c = capability.constraints;

    if (c.expiresAt != null && nowMs != null) {
      if (nowMs >= c.expiresAt) {
        return { ok: false, reason: "capability has expired" };
      }
    }

    if (c.maxUses != null && usageCount != null) {
      if (usageCount >= c.maxUses) {
        return { ok: false, reason: "capability has exceeded maxUses" };
      }
    }

    return { ok: true };
  }
}

function _b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
