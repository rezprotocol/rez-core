import { RSerializable } from "../../base/index.js";
import { isBytes } from "../../util/bytes.js";

function toBytes(value, label) {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return new Uint8Array(value);
  throw new Error(`RatchetChainState.${label} must be Uint8Array`);
}

export class RatchetChainState extends RSerializable {
  static type = "RatchetChainState";

  constructor({ chainKey, messageIndex } = {}) {
    super();

    this.assert(isBytes(chainKey), "RatchetChainState.chainKey must be Uint8Array", { chainKey });
    this.assert(Number.isInteger(messageIndex) && messageIndex >= 0, "RatchetChainState.messageIndex must be >= 0", { messageIndex });

    this.chainKey = chainKey;
    this.messageIndex = messageIndex;
  }

  toJSON() {
    return {
      chainKey: Array.from(this.chainKey),
      messageIndex: this.messageIndex,
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("RatchetChainState.fromJSON(json) requires object");
    }

    return new RatchetChainState({
      chainKey: toBytes(json.chainKey, "chainKey"),
      messageIndex: json.messageIndex,
    });
  }
}
