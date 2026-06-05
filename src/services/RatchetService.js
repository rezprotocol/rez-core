import { RService } from "../base/index.js";
import { RCryptoProvider } from "../crypto/RCryptoProvider.js";
import { deriveMessageKey } from "../crypto/ratchet/KdfChain.js";
import { deriveRootKey } from "../crypto/ratchet/KdfRoot.js";
import { RatchetKeyPair } from "../objects/ratchet/RatchetKeyPair.js";
import { RatchetChainState } from "../objects/ratchet/RatchetChainState.js";
import { RatchetState } from "../objects/ratchet/RatchetState.js";
import { SkippedKeyStore } from "../objects/ratchet/SkippedKeyStore.js";
import { SkipLimitExceededError, SkippedKeyStoreLimitExceededError } from "./ratchet/errors.js";
import { bytesToHex } from "../util/bytes.js";

function isBytes(value) {
  return value instanceof Uint8Array;
}

function assertKeyBytes(bytes, label) {
  if (!isBytes(bytes)) {
    throw new Error(`RatchetService requires ${label} Uint8Array`);
  }
}

function compareBytes(a, b) {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i += 1) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

export class RatchetService extends RService {
  constructor({ crypto, dhAlg = "X25519" } = {}) {
    super();

    if (!(crypto instanceof RCryptoProvider)) {
      throw new Error("RatchetService requires crypto (RCryptoProvider)");
    }

    this.crypto = crypto;
    this.dhAlg = dhAlg;
  }

  initializeAsInitiator({ sharedSecret, selfDhKeyPair, remoteDhPublicKey } = {}) {
    assertKeyBytes(sharedSecret, "sharedSecret");
    if (!(selfDhKeyPair instanceof RatchetKeyPair)) {
      throw new Error("RatchetService.initializeAsInitiator requires selfDhKeyPair (RatchetKeyPair)");
    }
    assertKeyBytes(remoteDhPublicKey, "remoteDhPublicKey");

    const sendingChain = new RatchetChainState({ chainKey: sharedSecret, messageIndex: 0 });

    return new RatchetState({
      rootKey: sharedSecret,
      sendingChain,
      receivingChain: null,
      selfDhKeyPair,
      remoteDhPublicKey,
      skipped: new SkippedKeyStore(),
    });
  }

  initializeAsResponder({ sharedSecret, selfDhKeyPair, remoteDhPublicKey } = {}) {
    assertKeyBytes(sharedSecret, "sharedSecret");
    if (!(selfDhKeyPair instanceof RatchetKeyPair)) {
      throw new Error("RatchetService.initializeAsResponder requires selfDhKeyPair (RatchetKeyPair)");
    }
    assertKeyBytes(remoteDhPublicKey, "remoteDhPublicKey");

    const receivingChain = new RatchetChainState({ chainKey: sharedSecret, messageIndex: 0 });

    return new RatchetState({
      rootKey: sharedSecret,
      sendingChain: null,
      receivingChain,
      selfDhKeyPair,
      remoteDhPublicKey,
      skipped: new SkippedKeyStore(),
    });
  }

  async ratchetStep(state, newRemoteDhPublicKey, { establish = "both" } = {}) {
    if (!(state instanceof RatchetState)) {
      throw new Error("RatchetService.ratchetStep requires RatchetState");
    }
    assertKeyBytes(newRemoteDhPublicKey, "newRemoteDhPublicKey");

    const dhSecret = await this.crypto.dhDerive({
      privateKey: state.selfDhKeyPair.privateKey,
      publicKey: newRemoteDhPublicKey,
      alg: this.dhAlg,
      fmt: this._inferDhFormat(newRemoteDhPublicKey),
    });
    const { newRootKey, sendingChainKey, receivingChainKey } = await deriveRootKey(
      this.crypto,
      state.rootKey,
      dhSecret
    );

    const ordering = compareBytes(state.selfDhKeyPair.publicKey, newRemoteDhPublicKey);
    const sendKey = ordering < 0 ? sendingChainKey : receivingChainKey;
    const recvKey = ordering < 0 ? receivingChainKey : sendingChainKey;

    // A DH step derives BOTH direction chain keys from the new root, but it must
    // only INSTALL the one being established and PRESERVE the opposite chain:
    //   - "sending": establishing our sending chain (responder's lazy first
    //     send) — keep the existing receiving chain (the peer's still-active
    //     send chain). Clobbering it desynced the responder from the initiator's
    //     in-flight messages (root 9dde vs 4aec), which is the group offline
    //     catch-up decrypt failure (2026-06-04).
    //   - "receiving": establishing our receiving chain (initiator picking up
    //     the responder's new chain) — keep our existing sending chain.
    //   - "both": legacy full replace (used by direct unit callers).
    const installSending = establish !== "receiving";
    const installReceiving = establish !== "sending";
    const newState = new RatchetState({
      rootKey: newRootKey,
      sendingChain: installSending
        ? new RatchetChainState({ chainKey: sendKey, messageIndex: 0 })
        : state.sendingChain,
      receivingChain: installReceiving
        ? new RatchetChainState({ chainKey: recvKey, messageIndex: 0 })
        : state.receivingChain,
      selfDhKeyPair: state.selfDhKeyPair,
      remoteDhPublicKey: newRemoteDhPublicKey,
      skipped: state.skipped,
      maxSkip: state.maxSkip,
      maxSkippedKeys: state.maxSkippedKeys,
      maxSkippedBytes: state.maxSkippedBytes,
    });

    return { newState, skippedKeys: [] };
  }

  async nextSendingMessageKey(state) {
    if (!(state instanceof RatchetState)) {
      throw new Error("RatchetService.nextSendingMessageKey requires RatchetState");
    }
    if (!state.sendingChain) {
      throw new Error("RatchetService.nextSendingMessageKey requires sendingChain");
    }

    const { messageKey, nextChainKey } = await deriveMessageKey(this.crypto, state.sendingChain.chainKey);
    const newState = new RatchetState({
      rootKey: state.rootKey,
      sendingChain: new RatchetChainState({
        chainKey: nextChainKey,
        messageIndex: state.sendingChain.messageIndex + 1,
      }),
      receivingChain: state.receivingChain,
      selfDhKeyPair: state.selfDhKeyPair,
      remoteDhPublicKey: state.remoteDhPublicKey,
      skipped: state.skipped,
      maxSkip: state.maxSkip,
      maxSkippedKeys: state.maxSkippedKeys,
      maxSkippedBytes: state.maxSkippedBytes,
    });

    return { messageKey, newState };
  }

  async nextReceivingMessageKey(state) {
    if (!(state instanceof RatchetState)) {
      throw new Error("RatchetService.nextReceivingMessageKey requires RatchetState");
    }
    if (!state.receivingChain) {
      throw new Error("RatchetService.nextReceivingMessageKey requires receivingChain");
    }

    const { messageKey, nextChainKey } = await deriveMessageKey(this.crypto, state.receivingChain.chainKey);
    const newState = new RatchetState({
      rootKey: state.rootKey,
      sendingChain: state.sendingChain,
      receivingChain: new RatchetChainState({
        chainKey: nextChainKey,
        messageIndex: state.receivingChain.messageIndex + 1,
      }),
      selfDhKeyPair: state.selfDhKeyPair,
      remoteDhPublicKey: state.remoteDhPublicKey,
      skipped: state.skipped,
      maxSkip: state.maxSkip,
      maxSkippedKeys: state.maxSkippedKeys,
      maxSkippedBytes: state.maxSkippedBytes,
    });

    return { messageKey, newState };
  }

  async deriveReceivingKeyForHeader(state, header, { sid } = {}) {
    if (!(state instanceof RatchetState)) {
      throw new Error("RatchetService.deriveReceivingKeyForHeader requires RatchetState");
    }
    if (!header || typeof header !== "object") {
      throw new Error("RatchetService.deriveReceivingKeyForHeader requires header object");
    }
    if (!Number.isInteger(header.n) || header.n < 0) {
      throw new Error("RatchetService.deriveReceivingKeyForHeader requires header.n >= 0");
    }
    assertKeyBytes(sid, "sid");

    let workingState = state;
    if (header.dh != null) {
      assertKeyBytes(header.dh, "header.dh");
      if (!bytesEqual(header.dh, workingState.remoteDhPublicKey)) {
        // Establish ONLY our receiving chain from the peer's new DH; preserve
        // our sending chain so our own in-flight/old-chain messages to them
        // stay valid.
        const step = await this.ratchetStep(workingState, header.dh, { establish: "receiving" });
        workingState = step.newState;
      }
    }

    if (!workingState.receivingChain) {
      throw new Error("RatchetService.deriveReceivingKeyForHeader requires receivingChain");
    }

    const sidHex = bytesToHex(sid);
    const dhHashHex = bytesToHex(await this.crypto.hashSha256(workingState.remoteDhPublicKey));
    const lookupKey = (n) => `${sidHex}:${dhHashHex}:${n}`;
    const skipped = workingState.skipped;

    const existing = skipped.get(lookupKey(header.n));
    if (existing) {
      skipped.delete(lookupKey(header.n));
      return { messageKey: existing, nextState: workingState, usedSkipped: true };
    }

    if (header.n < workingState.receivingChain.messageIndex) {
      throw new Error("SkippedKeyNotFound");
    }

    const expected = workingState.receivingChain.messageIndex;
    const distance = header.n - expected;
    if (distance > workingState.maxSkip) {
      throw new SkipLimitExceededError(expected, header.n, workingState.maxSkip);
    }

    while (workingState.receivingChain.messageIndex < header.n) {
      const currentIndex = workingState.receivingChain.messageIndex;
      const { messageKey, newState } = await this.nextReceivingMessageKey(workingState);

      const nextCount = skipped.size() + 1;
      if (nextCount > workingState.maxSkippedKeys) {
        throw new SkippedKeyStoreLimitExceededError("maxSkippedKeys", workingState.maxSkippedKeys, nextCount);
      }
      const nextBytes = skipped.totalBytes + messageKey.length;
      if (nextBytes > workingState.maxSkippedBytes) {
        throw new SkippedKeyStoreLimitExceededError("maxSkippedBytes", workingState.maxSkippedBytes, nextBytes);
      }

      skipped.set(lookupKey(currentIndex), messageKey);
      workingState = newState;
    }

    const { messageKey, newState } = await this.nextReceivingMessageKey(workingState);
    return { messageKey, nextState: newState, usedSkipped: false };
  }

  _inferDhFormat(publicKeyBytes) {
    return publicKeyBytes.length === 32 ? "raw" : "spki";
  }
}
