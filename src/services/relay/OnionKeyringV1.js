import { isFiniteNumber } from "../../util/settlement.js";

export class OnionKeyNotUsableError extends Error {
  constructor(message = "Onion key not usable") {
    super(message);
    this.name = "OnionKeyNotUsableError";
  }
}

export class OnionKeyringV1 {
  constructor() {
    this.byId = new Map();
  }

  addKey({ onionKeyId, privateKeyBytes, notBefore, notAfter, status = "active" } = {}) {
    if (typeof onionKeyId !== "string" || onionKeyId.length === 0) {
      throw new Error("OnionKeyringV1.addKey requires onionKeyId");
    }
    if (!(privateKeyBytes instanceof Uint8Array)) {
      throw new Error("OnionKeyringV1.addKey requires privateKeyBytes Uint8Array");
    }
    if (!isFiniteNumber(notBefore) || !isFiniteNumber(notAfter)) {
      throw new Error("OnionKeyringV1.addKey requires notBefore/notAfter numbers");
    }
    if (notBefore > notAfter) {
      throw new Error("OnionKeyringV1.addKey requires notBefore <= notAfter");
    }
    if (!(["active", "draining", "revoked"].includes(status))) {
      throw new Error("OnionKeyringV1.addKey requires status active|draining|revoked");
    }

    this.byId.set(onionKeyId, { onionKeyId, privateKeyBytes, notBefore, notAfter, status });
  }

  getKeyForDecrypt(onionKeyId, nowMs) {
    if (typeof onionKeyId !== "string" || onionKeyId.length === 0) {
      throw new OnionKeyNotUsableError("onionKeyId required");
    }
    if (!isFiniteNumber(nowMs)) {
      throw new OnionKeyNotUsableError("nowMs required");
    }

    const record = this.byId.get(onionKeyId);
    if (!record) {
      throw new OnionKeyNotUsableError("onionKeyId not found");
    }
    if (record.status === "revoked") {
      throw new OnionKeyNotUsableError("onionKeyId revoked");
    }
    if (!(record.notBefore <= nowMs && nowMs < record.notAfter)) {
      throw new OnionKeyNotUsableError("onionKeyId not in valid time window");
    }
    if (record.status !== "active" && record.status !== "draining") {
      throw new OnionKeyNotUsableError("onionKeyId not usable");
    }

    return record.privateKeyBytes;
  }
}
