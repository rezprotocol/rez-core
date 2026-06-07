import { RelayDescriptorV1 } from "../objects/index.js";

function validateNodeMeta(node) {
  if (!node || typeof node !== "object" || Array.isArray(node)) {
    throw new Error("meta.node must be object");
  }
  const allowedNodeKeys = new Set([
    "nodeId",
    "routeBaseUrl",
    "ingressBaseUrl",
    "keyId",
    "publicKeyB64",
    "transports",
    "protocolVersion",
  ]);
  for (const key of Object.keys(node)) {
    if (!allowedNodeKeys.has(key)) {
      throw new Error("meta.node unknown fields");
    }
  }
  if (node.nodeId !== undefined) {
    const text = String(node.nodeId || "").trim();
    if (!text || text.length > 256) throw new Error("meta.node.nodeId invalid");
  }
  if (node.routeBaseUrl !== undefined) {
    const text = String(node.routeBaseUrl || "").trim();
    if (!text || text.length > 2048) throw new Error("meta.node.routeBaseUrl invalid");
  }
  if (node.ingressBaseUrl !== undefined) {
    const text = String(node.ingressBaseUrl || "").trim();
    if (!text || text.length > 2048) throw new Error("meta.node.ingressBaseUrl invalid");
  }
  if (node.keyId !== undefined) {
    const text = String(node.keyId || "").trim();
    if (!text || text.length > 256) throw new Error("meta.node.keyId invalid");
  }
  if (node.publicKeyB64 !== undefined) {
    const text = String(node.publicKeyB64 || "").trim();
    if (!text || text.length > 4096) throw new Error("meta.node.publicKeyB64 invalid");
  }
  if (node.transports !== undefined) {
    if (!Array.isArray(node.transports)) throw new Error("meta.node.transports must be array");
    if (node.transports.length > 8) throw new Error("meta.node.transports too long");
    const allowed = new Set(["http", "https", "tcp", "ws", "wss"]);
    const seen = new Set();
    for (const transport of node.transports) {
      if (typeof transport !== "string" || !allowed.has(transport)) throw new Error("meta.node.transports invalid");
      if (seen.has(transport)) throw new Error("meta.node.transports duplicate");
      seen.add(transport);
    }
  }
  if (node.protocolVersion !== undefined) {
    const version = Number(node.protocolVersion);
    if (!Number.isInteger(version) || version <= 0) throw new Error("meta.node.protocolVersion invalid");
  }
}

function validateSignature(sig, meta) {
  if (!sig || typeof sig !== "object" || Array.isArray(sig)) {
    throw new Error("sig must be object");
  }
  const allowedSigKeys = new Set(["scheme", "keyId", "sigB64"]);
  for (const key of Object.keys(sig)) {
    if (!allowedSigKeys.has(key)) {
      throw new Error("sig unknown fields");
    }
  }
  if (sig.scheme !== "ed25519") {
    throw new Error("sig.scheme invalid");
  }
  const keyId = String(sig.keyId || "").trim();
  if (!keyId || keyId.length > 256) {
    throw new Error("sig.keyId invalid");
  }
  const sigB64 = String(sig.sigB64 || "").trim();
  if (!sigB64 || sigB64.length > 4096) {
    throw new Error("sig.sigB64 invalid");
  }
  const metaKeyId = String(meta && meta.node && meta.node.keyId || "").trim();
  if (metaKeyId && metaKeyId !== keyId) {
    throw new Error("sig.keyId mismatch");
  }
}

export function validateRelayDescriptorV1(value, { nowMs } = {}) {
  try {
    if (value && value.meta !== undefined) {
      const meta = value.meta;
      if (!meta || typeof meta !== "object" || Array.isArray(meta)) {
        throw new Error("meta must be object");
      }
      if (meta.v !== 1) {
        throw new Error("meta.v must be 1");
      }
      const allowedMetaKeys = new Set(["v", "nickname", "capabilities", "node", "services"]);
      for (const key of Object.keys(meta)) {
        if (!allowedMetaKeys.has(key)) {
          throw new Error("meta has unknown fields");
        }
      }
      if (meta.nickname !== undefined) {
        if (typeof meta.nickname !== "string") throw new Error("meta.nickname must be string");
        const trimmed = meta.nickname.trim();
        if (trimmed.length < 1 || trimmed.length > 32) throw new Error("meta.nickname length");
        if (!/^[A-Za-z0-9 _.-]+$/.test(trimmed)) throw new Error("meta.nickname charset");
      }
      if (meta.capabilities !== undefined) {
        if (!meta.capabilities || typeof meta.capabilities !== "object" || Array.isArray(meta.capabilities)) {
          throw new Error("meta.capabilities must be object");
        }
        const allowedCaps = new Set(["transports", "storeAndForward"]);
        for (const key of Object.keys(meta.capabilities)) {
          if (!allowedCaps.has(key)) throw new Error("meta.capabilities unknown fields");
        }
        if (meta.capabilities.transports !== undefined) {
          if (!Array.isArray(meta.capabilities.transports)) throw new Error("meta.capabilities.transports must be array");
          if (meta.capabilities.transports.length > 5) throw new Error("meta.capabilities.transports too long");
          const allowed = new Set(["tcp", "http"]);
          const seen = new Set();
          for (const transport of meta.capabilities.transports) {
            if (typeof transport !== "string" || !allowed.has(transport)) throw new Error("meta.capabilities.transports invalid");
            if (seen.has(transport)) throw new Error("meta.capabilities.transports duplicate");
            seen.add(transport);
          }
        }
        if (meta.capabilities.storeAndForward !== undefined && typeof meta.capabilities.storeAndForward !== "boolean") {
          throw new Error("meta.capabilities.storeAndForward must be boolean");
        }
      }
      if (meta.node !== undefined) {
        validateNodeMeta(meta.node);
      }
    }
    if (value && value.sig !== undefined) {
      validateSignature(value.sig, value && value.meta);
    }
    const descriptor = value instanceof RelayDescriptorV1
      ? value
      : RelayDescriptorV1.fromJSON(value, { nowMs });
    return { ok: true, descriptor };
  } catch (err) {
    return { ok: false, reason: err && err.message || "invalid" };
  }
}
