import { RSerializable } from "../../base/index.js";
import { RatchetState } from "./RatchetState.js";
import { bytesToBase64, base64ToBytes } from "../../util/bytes.js";

function isBytes(value) {
  return value instanceof Uint8Array;
}

/**
 * Validated in-memory record for a Double Ratchet session.
 *
 * Every session stored in MemorySessionManager / PersistentSessionManager
 * MUST be a SecureSessionRecord. This guarantees shape correctness at
 * construction rather than hoping every consumer checks manually.
 */
export class SecureSessionRecord extends RSerializable {
  static type = "SecureSessionRecord";

  constructor({ sid, peerId, ratchetState, includeDh } = {}) {
    super();

    this.assert(isBytes(sid) && sid.length > 0, "SecureSessionRecord.sid must be non-empty Uint8Array", { sid });
    this.assert(typeof peerId === "string" && peerId.trim().length > 0, "SecureSessionRecord.peerId must be non-empty string", { peerId });
    this.assert(ratchetState instanceof RatchetState, "SecureSessionRecord.ratchetState must be RatchetState", { ratchetState });
    this.assert(typeof includeDh === "boolean", "SecureSessionRecord.includeDh must be boolean", { includeDh });

    this.sid = sid;
    this.peerId = peerId;
    this.ratchetState = ratchetState;
    this.includeDh = includeDh;
  }

  toJSON() {
    return {
      sid: bytesToBase64(this.sid),
      peerId: this.peerId,
      ratchetState: this.ratchetState.toJSON(),
      includeDh: this.includeDh,
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("SecureSessionRecord.fromJSON requires object");
    }
    return new SecureSessionRecord({
      sid: base64ToBytes(json.sid),
      peerId: json.peerId,
      ratchetState: RatchetState.fromJSON(json.ratchetState),
      includeDh: json.includeDh,
    });
  }
}
