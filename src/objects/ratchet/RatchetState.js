import { RSerializable } from "../../base/index.js";
import { RatchetChainState } from "./RatchetChainState.js";
import { RatchetKeyPair } from "./RatchetKeyPair.js";
import { SkippedKeyStore } from "./SkippedKeyStore.js";

const DEFAULT_MAX_SKIP = 200;
const DEFAULT_MAX_SKIPPED_KEYS = 500;
const DEFAULT_MAX_SKIPPED_BYTES = 64 * 1024;

function isBytes(value) {
  return value instanceof Uint8Array;
}

function toBytes(value, label) {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return new Uint8Array(value);
  throw new Error(`RatchetState.${label} must be Uint8Array`);
}

export class RatchetState extends RSerializable {
  static type = "RatchetState";

  constructor({
    rootKey,
    sendingChain,
    receivingChain,
    selfDhKeyPair,
    remoteDhPublicKey,
    skipped,
    maxSkip = DEFAULT_MAX_SKIP,
    maxSkippedKeys = DEFAULT_MAX_SKIPPED_KEYS,
    maxSkippedBytes = DEFAULT_MAX_SKIPPED_BYTES,
  } = {}) {
    super();

    this.assert(isBytes(rootKey), "RatchetState.rootKey must be Uint8Array", { rootKey });
    if (sendingChain != null) {
      this.assert(sendingChain instanceof RatchetChainState, "RatchetState.sendingChain must be RatchetChainState or null", { sendingChain });
    }
    if (receivingChain != null) {
      this.assert(receivingChain instanceof RatchetChainState, "RatchetState.receivingChain must be RatchetChainState or null", { receivingChain });
    }
    this.assert(selfDhKeyPair instanceof RatchetKeyPair, "RatchetState.selfDhKeyPair must be RatchetKeyPair", { selfDhKeyPair });
    this.assert(isBytes(remoteDhPublicKey), "RatchetState.remoteDhPublicKey must be Uint8Array", { remoteDhPublicKey });
    if (skipped != null) {
      this.assert(skipped instanceof SkippedKeyStore, "RatchetState.skipped must be SkippedKeyStore", { skipped });
    }
    this.assert(Number.isFinite(maxSkip) && maxSkip >= 0, "RatchetState.maxSkip must be number >= 0", { maxSkip });
    this.assert(Number.isFinite(maxSkippedKeys) && maxSkippedKeys >= 0, "RatchetState.maxSkippedKeys must be number >= 0", { maxSkippedKeys });
    this.assert(Number.isFinite(maxSkippedBytes) && maxSkippedBytes >= 0, "RatchetState.maxSkippedBytes must be number >= 0", { maxSkippedBytes });

    this.rootKey = rootKey;
    this.sendingChain = sendingChain ?? null;
    this.receivingChain = receivingChain ?? null;
    this.selfDhKeyPair = selfDhKeyPair;
    this.remoteDhPublicKey = remoteDhPublicKey;
    this.skipped = skipped ?? new SkippedKeyStore();
    this.maxSkip = maxSkip;
    this.maxSkippedKeys = maxSkippedKeys;
    this.maxSkippedBytes = maxSkippedBytes;
  }

  toJSON() {
    return {
      rootKey: Array.from(this.rootKey),
      sendingChain: this.sendingChain ? this.sendingChain.toJSON() : null,
      receivingChain: this.receivingChain ? this.receivingChain.toJSON() : null,
      selfDhKeyPair: this.selfDhKeyPair.toJSON(),
      remoteDhPublicKey: Array.from(this.remoteDhPublicKey),
      skipped: this.skipped.toJSON(),
      maxSkip: this.maxSkip,
      maxSkippedKeys: this.maxSkippedKeys,
      maxSkippedBytes: this.maxSkippedBytes,
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("RatchetState.fromJSON(json) requires object");
    }

    return new RatchetState({
      rootKey: toBytes(json.rootKey, "rootKey"),
      sendingChain: json.sendingChain ? RatchetChainState.fromJSON(json.sendingChain) : null,
      receivingChain: json.receivingChain ? RatchetChainState.fromJSON(json.receivingChain) : null,
      selfDhKeyPair: RatchetKeyPair.fromJSON(json.selfDhKeyPair),
      remoteDhPublicKey: toBytes(json.remoteDhPublicKey, "remoteDhPublicKey"),
      skipped: json.skipped ? SkippedKeyStore.fromJSON(json.skipped) : new SkippedKeyStore(),
      maxSkip: json.maxSkip ?? DEFAULT_MAX_SKIP,
      maxSkippedKeys: json.maxSkippedKeys ?? DEFAULT_MAX_SKIPPED_KEYS,
      maxSkippedBytes: json.maxSkippedBytes ?? DEFAULT_MAX_SKIPPED_BYTES,
    });
  }
}
