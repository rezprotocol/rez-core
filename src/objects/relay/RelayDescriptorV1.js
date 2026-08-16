import { RSerializable } from "../../base/index.js";
import { OnionKeyRecordV1 } from "./OnionKeyRecordV1.js";
import { PRICING_UNITS, isFiniteNumber } from "../../util/settlement.js";
import { isNonEmptyString } from "../../util/strings.js";
import { validateRelayIdentityBinding } from "../../identity/relayIdentity.js";

/**
 * The ONE canonical transport-name vocabulary (ATLAS_PREREQUISITES P2.2).
 * Both meta.node.transports and meta.capabilities.transports validate against
 * this set — two divergent enums for the same concept caused silent drift.
 */
export const RELAY_TRANSPORT_NAMES = Object.freeze(["http", "https", "tcp", "ws", "wss"]);
const TRANSPORT_SET = new Set(RELAY_TRANSPORT_NAMES);

function validateTransportList(list, label, maxLen) {
  if (!Array.isArray(list)) {
    throw new Error(label + " must be array");
  }
  if (list.length > maxLen) {
    throw new Error(label + " too long");
  }
  const seen = new Set();
  for (const transport of list) {
    if (typeof transport !== "string" || !TRANSPORT_SET.has(transport)) {
      throw new Error(label + " invalid");
    }
    if (seen.has(transport)) {
      throw new Error(label + " must be unique");
    }
    seen.add(transport);
  }
}

function isEndpoint(value) {
  return value && typeof value === "object" && isNonEmptyString(value.host)
    && Number.isInteger(value.port) && value.port >= 0
    && (value.tls === undefined || typeof value.tls === "boolean");
}

function isPlainObject(value) {
  return value && typeof value === "object" && !Array.isArray(value);
}

function validateSignature(sig, meta) {
  if (!isPlainObject(sig)) {
    throw new Error("RelayDescriptorV1.sig must be an object");
  }
  const allowedSigKeys = new Set(["scheme", "keyId", "sigB64"]);
  for (const key of Object.keys(sig)) {
    if (!allowedSigKeys.has(key)) {
      throw new Error("RelayDescriptorV1.sig has unknown fields");
    }
  }
  if (sig.scheme !== "ed25519") {
    throw new Error("RelayDescriptorV1.sig.scheme must be ed25519");
  }
  const keyId = String(sig.keyId || "").trim();
  if (!keyId || keyId.length > 256) {
    throw new Error("RelayDescriptorV1.sig.keyId invalid");
  }
  const sigB64 = String(sig.sigB64 || "").trim();
  if (!sigB64 || sigB64.length > 4096) {
    throw new Error("RelayDescriptorV1.sig.sigB64 invalid");
  }
  const metaKeyId = String(meta && meta.node && meta.node.keyId || "").trim();
  if (metaKeyId && metaKeyId !== keyId) {
    throw new Error("RelayDescriptorV1.sig.keyId must match meta.node.keyId");
  }
}

function validateNodeMeta(node) {
  if (!isPlainObject(node)) {
    throw new Error("RelayDescriptorV1.meta.node must be an object");
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
      throw new Error("RelayDescriptorV1.meta.node has unknown fields");
    }
  }
  if (node.nodeId !== undefined) {
    const text = String(node.nodeId || "").trim();
    if (!text || text.length > 256) throw new Error("RelayDescriptorV1.meta.node.nodeId invalid");
  }
  if (node.routeBaseUrl !== undefined) {
    const text = String(node.routeBaseUrl || "").trim();
    if (!text || text.length > 2048) throw new Error("RelayDescriptorV1.meta.node.routeBaseUrl invalid");
  }
  if (node.ingressBaseUrl !== undefined) {
    const text = String(node.ingressBaseUrl || "").trim();
    if (!text || text.length > 2048) throw new Error("RelayDescriptorV1.meta.node.ingressBaseUrl invalid");
  }
  if (node.keyId !== undefined) {
    const text = String(node.keyId || "").trim();
    if (!text || text.length > 256) throw new Error("RelayDescriptorV1.meta.node.keyId invalid");
  }
  if (node.publicKeyB64 !== undefined) {
    const text = String(node.publicKeyB64 || "").trim();
    if (!text || text.length > 4096) throw new Error("RelayDescriptorV1.meta.node.publicKeyB64 invalid");
  }
  if (node.transports !== undefined) {
    validateTransportList(node.transports, "RelayDescriptorV1.meta.node.transports", 8);
  }
  if (node.protocolVersion !== undefined) {
    const value = Number(node.protocolVersion);
    if (!Number.isInteger(value) || value <= 0) {
      throw new Error("RelayDescriptorV1.meta.node.protocolVersion must be positive int");
    }
  }
}

function validateServices(services) {
  if (!isPlainObject(services)) {
    throw new Error("RelayDescriptorV1.meta.services must be an object");
  }
  const serviceIds = Object.keys(services);
  if (serviceIds.length > 50) {
    throw new Error("RelayDescriptorV1.meta.services too many entries");
  }
  const allowedServiceKeys = new Set(["costPerUnit", "unit", "currency", "description"]);
  for (const serviceId of serviceIds) {
    if (typeof serviceId !== "string" || serviceId.length === 0 || serviceId.length > 128) {
      throw new Error("RelayDescriptorV1.meta.services keys must be non-empty strings <= 128 chars");
    }
    const svc = services[serviceId];
    if (!isPlainObject(svc)) {
      throw new Error(`RelayDescriptorV1.meta.services.${serviceId} must be an object`);
    }
    for (const key of Object.keys(svc)) {
      if (!allowedServiceKeys.has(key)) {
        throw new Error(`RelayDescriptorV1.meta.services.${serviceId} has unknown field: ${key}`);
      }
    }
    if (!isFiniteNumber(svc.costPerUnit) || svc.costPerUnit <= 0) {
      throw new Error(`RelayDescriptorV1.meta.services.${serviceId}.costPerUnit must be positive number`);
    }
    if (!PRICING_UNITS.has(svc.unit)) {
      throw new Error(`RelayDescriptorV1.meta.services.${serviceId}.unit must be one of: ${[...PRICING_UNITS].join(", ")}`);
    }
    if (svc.currency !== undefined && (typeof svc.currency !== "string" || svc.currency.length === 0 || svc.currency.length > 16)) {
      throw new Error(`RelayDescriptorV1.meta.services.${serviceId}.currency invalid`);
    }
    if (svc.description !== undefined && (typeof svc.description !== "string" || svc.description.length > 256)) {
      throw new Error(`RelayDescriptorV1.meta.services.${serviceId}.description invalid`);
    }
  }
}

function validateMeta(meta) {
  if (!isPlainObject(meta)) {
    throw new Error("RelayDescriptorV1.meta must be an object");
  }
  if (meta.v !== 1) {
    throw new Error("RelayDescriptorV1.meta.v must be 1");
  }
  const allowedKeys = new Set(["v", "nickname", "capabilities", "node", "services"]);
  for (const key of Object.keys(meta)) {
    if (!allowedKeys.has(key)) {
      throw new Error("RelayDescriptorV1.meta has unknown fields");
    }
  }
  if (meta.nickname !== undefined) {
    if (typeof meta.nickname !== "string") {
      throw new Error("RelayDescriptorV1.meta.nickname must be a string");
    }
    const trimmed = meta.nickname.trim();
    if (trimmed.length < 1 || trimmed.length > 32) {
      throw new Error("RelayDescriptorV1.meta.nickname must be 1..32 chars");
    }
    if (!/^[A-Za-z0-9 _.-]+$/.test(trimmed)) {
      throw new Error("RelayDescriptorV1.meta.nickname has invalid characters");
    }
  }
  if (meta.capabilities !== undefined) {
    if (!isPlainObject(meta.capabilities)) {
      throw new Error("RelayDescriptorV1.meta.capabilities must be an object");
    }
    const allowedCapKeys = new Set(["transports", "storeAndForward"]);
    for (const key of Object.keys(meta.capabilities)) {
      if (!allowedCapKeys.has(key)) {
        throw new Error("RelayDescriptorV1.meta.capabilities has unknown fields");
      }
    }
    if (meta.capabilities.transports !== undefined) {
      validateTransportList(meta.capabilities.transports, "RelayDescriptorV1.meta.capabilities.transports", 5);
    }
    if (meta.capabilities.storeAndForward !== undefined && typeof meta.capabilities.storeAndForward !== "boolean") {
      throw new Error("RelayDescriptorV1.meta.capabilities.storeAndForward must be boolean");
    }
  }
  if (meta.node !== undefined) {
    validateNodeMeta(meta.node);
  }
  if (meta.services !== undefined) {
    validateServices(meta.services);
  }
}

export class RelayDescriptorV1 extends RSerializable {
  static type = "RelayDescriptorV1";

  constructor({
    v = 1,
    relayKeyId,
    endpoints,
    onionKeys,
    capabilities = undefined,
    expiresAt,
    sig = undefined,
    meta = undefined,
    nowMs = undefined,
  } = {}) {
    super();

    this.assert(v === 1, "RelayDescriptorV1.v must be 1", { v });
    this.assert(isNonEmptyString(relayKeyId), "RelayDescriptorV1.relayKeyId must be non-empty string", { relayKeyId });
    this.assert(Array.isArray(endpoints) && endpoints.length > 0, "RelayDescriptorV1.endpoints must be non-empty array", { endpoints });
    for (let i = 0; i < endpoints.length; i += 1) {
      this.assert(isEndpoint(endpoints[i]), "RelayDescriptorV1.endpoints entries must be {host,port[,tls]}", { endpoint: endpoints[i], i });
    }
    this.assert(Array.isArray(onionKeys) && onionKeys.length > 0, "RelayDescriptorV1.onionKeys must be non-empty array", { onionKeys });
    for (let i = 0; i < onionKeys.length; i += 1) {
      this.assert(onionKeys[i] instanceof OnionKeyRecordV1, "RelayDescriptorV1.onionKeys entries must be OnionKeyRecordV1", { onionKey: onionKeys[i], i });
    }
    if (capabilities !== undefined) {
      this.assert(capabilities && typeof capabilities === "object" && !Array.isArray(capabilities), "RelayDescriptorV1.capabilities must be plain object", { capabilities });
      // P2.2 (ATLAS_PREREQUISITES): top-level capabilities was a signed,
      // unbounded, gossiped, persisted blob with ZERO readers — pure
      // attacker-controlled surface. meta.capabilities is the one truth.
      // The field is reserved: only an empty object survives for wire compat.
      this.assert(Object.keys(capabilities).length === 0,
        "RelayDescriptorV1.capabilities is reserved and must be empty; use meta.capabilities", { capabilities });
    }
    if (meta !== undefined) {
      validateMeta(meta);
    }
    if (sig !== undefined) {
      validateSignature(sig, meta);
    }
    // ADR-RELAY-IDENTITY: when the descriptor carries node key material its
    // relayKeyId must be the self-certifying identity of that key. (Whether
    // key material is REQUIRED at all is admission policy, owned by rez-node.)
    const bindingNode = meta && meta.node ? meta.node : null;
    const bindingKeyB64 = bindingNode && typeof bindingNode.publicKeyB64 === "string"
      ? bindingNode.publicKeyB64.trim()
      : "";
    if (bindingKeyB64) {
      const binding = validateRelayIdentityBinding({
        relayKeyId: typeof relayKeyId === "string" ? relayKeyId.trim() : relayKeyId,
        nodeKeyId: bindingNode && typeof bindingNode.keyId === "string" ? bindingNode.keyId.trim() : "",
        nodePublicKeyB64: bindingKeyB64,
      });
      this.assert(binding.ok === true,
        "RelayDescriptorV1 relay identity binding invalid: " + binding.reason,
        { relayKeyId, reason: binding.reason });
    }
    this.assert(isFiniteNumber(expiresAt), "RelayDescriptorV1.expiresAt must be number", { expiresAt });
    if (Number.isFinite(nowMs)) {
      this.assert(expiresAt > nowMs, "RelayDescriptorV1.expiresAt must be in the future", { expiresAt, nowMs });
    }

    this.v = 1;
    this.relayKeyId = relayKeyId;
    this.endpoints = endpoints;
    this.onionKeys = onionKeys;
    this.capabilities = capabilities;
    this.expiresAt = expiresAt;
    this.sig = sig;
    this.meta = meta;
  }

  toJSON() {
    return {
      v: 1,
      relayKeyId: this.relayKeyId,
      endpoints: this.endpoints,
      onionKeys: this.onionKeys.map((key) => key.toJSON()),
      capabilities: this.capabilities,
      expiresAt: this.expiresAt,
      sig: this.sig,
      meta: this.meta,
    };
  }

  static fromJSON(json, { nowMs } = {}) {
    if (!json || typeof json !== "object") {
      throw new Error("RelayDescriptorV1.fromJSON(json) requires object");
    }

    const onionKeys = Array.isArray(json.onionKeys)
      ? json.onionKeys.map((key) => (key instanceof OnionKeyRecordV1 ? key : OnionKeyRecordV1.fromJSON(key)))
      : json.onionKeys;

    return new RelayDescriptorV1({
      v: json.v ?? 1,
      relayKeyId: json.relayKeyId,
      endpoints: json.endpoints,
      onionKeys,
      capabilities: json.capabilities,
      expiresAt: json.expiresAt,
      sig: json.sig,
      meta: json.meta,
      nowMs,
    });
  }
}
