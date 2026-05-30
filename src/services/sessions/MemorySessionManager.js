import { RSessionManager } from "./RSessionManager.js";
import { RatchetService } from "../RatchetService.js";
import { RatchetKeyPair } from "../../objects/ratchet/RatchetKeyPair.js";
import { RatchetState } from "../../objects/ratchet/RatchetState.js";
import { SecureSessionRecord } from "../../objects/ratchet/SecureSessionRecord.js";
import { RCryptoProvider } from "../../crypto/RCryptoProvider.js";
import { deriveSessionIdV1 } from "../../crypto/sessions/deriveSessionIdV1.js";
import { NoSessionForPeerError, UnknownSessionError } from "./errors.js";
import { bytesToHex, bytesToBase64, base64ToBytes } from "../../util/bytes.js";

function isBytes(value) {
  return value instanceof Uint8Array;
}

function toSidHex(sid) {
  return bytesToHex(sid);
}

const SESSION_SNAPSHOT_VERSION = 1;

export class MemorySessionManager extends RSessionManager {
  constructor({ ratchetService, crypto } = {}) {
    super();

    if (!(ratchetService instanceof RatchetService)) {
      throw new Error("MemorySessionManager requires ratchetService (RatchetService)");
    }
    if (!(crypto instanceof RCryptoProvider)) {
      throw new Error("MemorySessionManager requires crypto (RCryptoProvider)");
    }

    this.ratchet = ratchetService;
    this.crypto = crypto;
    this.bySidHex = new Map();
    this.byPeerId = new Map();
  }

  async createInitiatorSession({ peerId, sharedSecret, selfDhKeyPair, remoteDhPublicKey } = {}) {
    if (typeof peerId !== "string" || peerId.trim().length === 0) {
      throw new Error("MemorySessionManager.createInitiatorSession requires peerId");
    }
    if (!isBytes(sharedSecret)) {
      throw new Error("MemorySessionManager.createInitiatorSession requires sharedSecret Uint8Array");
    }
    if (!(selfDhKeyPair instanceof RatchetKeyPair)) {
      throw new Error("MemorySessionManager.createInitiatorSession requires selfDhKeyPair (RatchetKeyPair)");
    }
    if (!isBytes(remoteDhPublicKey)) {
      throw new Error("MemorySessionManager.createInitiatorSession requires remoteDhPublicKey Uint8Array");
    }

    const sid = await deriveSessionIdV1(this.crypto, sharedSecret);
    const ratchetState = this.ratchet.initializeAsInitiator({
      sharedSecret,
      selfDhKeyPair,
      remoteDhPublicKey,
    });

    const record = new SecureSessionRecord({ sid, peerId, ratchetState, includeDh: false });
    const sidHex = toSidHex(sid);
    this.bySidHex.set(sidHex, record);
    this.byPeerId.set(peerId, record);

    return sid;
  }

  async createResponderSession({ peerId, sharedSecret, selfDhKeyPair, remoteDhPublicKey } = {}) {
    if (typeof peerId !== "string" || peerId.trim().length === 0) {
      throw new Error("MemorySessionManager.createResponderSession requires peerId");
    }
    if (!isBytes(sharedSecret)) {
      throw new Error("MemorySessionManager.createResponderSession requires sharedSecret Uint8Array");
    }
    if (!(selfDhKeyPair instanceof RatchetKeyPair)) {
      throw new Error("MemorySessionManager.createResponderSession requires selfDhKeyPair (RatchetKeyPair)");
    }
    if (!isBytes(remoteDhPublicKey)) {
      throw new Error("MemorySessionManager.createResponderSession requires remoteDhPublicKey Uint8Array");
    }

    const sid = await deriveSessionIdV1(this.crypto, sharedSecret);
    const ratchetState = this.ratchet.initializeAsResponder({
      sharedSecret,
      selfDhKeyPair,
      remoteDhPublicKey,
    });

    const record = new SecureSessionRecord({ sid, peerId, ratchetState, includeDh: false });
    const sidHex = toSidHex(sid);
    this.bySidHex.set(sidHex, record);
    this.byPeerId.set(peerId, record);

    return sid;
  }

  getSendContext(peerId) {
    const record = this.byPeerId.get(peerId);
    if (!record) {
      throw new NoSessionForPeerError(peerId);
    }

    return {
      sid: record.sid,
      ratchetState: record.ratchetState,
      includeDh: record.includeDh,
      commit: (nextState, opts = {}) => {
        if (!(nextState instanceof RatchetState)) {
          throw new Error("commit(nextState) requires RatchetState");
        }
        record.ratchetState = nextState;
        if (!opts.keepIncludeDh) {
          record.includeDh = false;
        }
      },
    };
  }

  getRecvContext(sid) {
    if (!isBytes(sid)) {
      throw new Error("MemorySessionManager.getRecvContext requires sid Uint8Array");
    }
    const sidHex = toSidHex(sid);
    const record = this.bySidHex.get(sidHex);
    if (!record) {
      throw new UnknownSessionError(sidHex);
    }

    return {
      peerId: record.peerId,
      ratchetState: record.ratchetState,
      commit: (nextState) => {
        if (!(nextState instanceof RatchetState)) {
          throw new Error("commit(nextState) requires RatchetState");
        }
        record.ratchetState = nextState;
      },
    };
  }

  async rotateDh(peerId) {
    const record = this.byPeerId.get(peerId);
    if (!record) {
      throw new NoSessionForPeerError(peerId);
    }

    const keyPair = await this.crypto.dhGenerateKeyPair({ alg: "X25519", fmt: "spki" });
    const nextState = new RatchetState({
      rootKey: record.ratchetState.rootKey,
      sendingChain: record.ratchetState.sendingChain,
      receivingChain: record.ratchetState.receivingChain,
      selfDhKeyPair: new RatchetKeyPair({
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey,
      }),
      remoteDhPublicKey: record.ratchetState.remoteDhPublicKey,
      skipped: record.ratchetState.skipped,
      maxSkip: record.ratchetState.maxSkip,
      maxSkippedKeys: record.ratchetState.maxSkippedKeys,
      maxSkippedBytes: record.ratchetState.maxSkippedBytes,
    });

    record.ratchetState = nextState;
    record.includeDh = true;
  }

  exportSnapshot() {
    const sessions = [];
    const seenPeers = new Set();
    for (const [peerId, record] of this.byPeerId.entries()) {
      if (!record || seenPeers.has(peerId)) continue;
      seenPeers.add(peerId);
      sessions.push({
        peerId,
        sidB64: bytesToBase64(record.sid),
        ratchetState: record.ratchetState && typeof record.ratchetState.toJSON === "function" ? record.ratchetState.toJSON() : null,
        includeDh: record.includeDh === true,
      });
    }
    return {
      v: SESSION_SNAPSHOT_VERSION,
      sessions,
    };
  }

  importSnapshot(snapshot = {}) {
    const rows = snapshot && Array.isArray(snapshot.sessions) ? snapshot.sessions : [];
    this.bySidHex = new Map();
    this.byPeerId = new Map();
    for (const row of rows) {
      if (!row) continue;
      const peerId = typeof row.peerId === "string" ? row.peerId.trim() : "";
      if (!peerId) continue;
      const sidB64 = typeof row.sidB64 === "string" ? row.sidB64.trim() : "";
      if (!sidB64) continue;
      try {
        const sid = base64ToBytes(sidB64);
        const ratchetState = RatchetState.fromJSON(row && row.ratchetState ? row.ratchetState : {});
        const record = new SecureSessionRecord({
          sid,
          peerId,
          ratchetState,
          includeDh: row && row.includeDh === true,
        });
        this.byPeerId.set(peerId, record);
        this.bySidHex.set(toSidHex(sid), record);
      } catch {
        // Skip malformed rows and continue loading the rest.
      }
    }
  }
}
