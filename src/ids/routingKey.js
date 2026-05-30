import { base64ToBytes, bytesToBase64 } from "../util/bytes.js";

const ROUTING_KEY_PREFIX = "th_";
const ROUTING_KEY_BYTES = 16;

export function newRoutingKey() {
  const bytes = randomBytes(ROUTING_KEY_BYTES);
  return bytesToRoutingKey(bytes);
}

export function routingKeyToBytes(routingKey) {
  if (typeof routingKey !== "string" || !routingKey.startsWith(ROUTING_KEY_PREFIX)) {
    throw new Error("routingKeyToBytes(routingKey) requires th_ prefix");
  }
  const encoded = routingKey.slice(ROUTING_KEY_PREFIX.length);
  const bytes = base64UrlToBytes(encoded);
  if (bytes.length !== ROUTING_KEY_BYTES) {
    throw new Error("routingKeyToBytes(routingKey) requires 16-byte id");
  }
  return bytes;
}

export function bytesToRoutingKey(bytes16) {
  if (!(bytes16 instanceof Uint8Array) || bytes16.length !== ROUTING_KEY_BYTES) {
    throw new Error("bytesToRoutingKey(bytes16) requires Uint8Array(16)");
  }
  return `${ROUTING_KEY_PREFIX}${bytesToBase64Url(bytes16)}`;
}

export function isRoutingKey(value) {
  if (typeof value !== "string") return false;
  if (!value.startsWith(ROUTING_KEY_PREFIX)) return false;
  try {
    return routingKeyToBytes(value).length === ROUTING_KEY_BYTES;
  } catch {
    return false;
  }
}

function randomBytes(size) {
  const bytes = new Uint8Array(size);
  if (!globalThis.crypto || typeof globalThis.crypto.getRandomValues !== "function") {
    throw new Error("newRoutingKey() requires globalThis.crypto.getRandomValues");
  }
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

function bytesToBase64Url(bytes) {
  const b64 = bytesToBase64(bytes);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(base64url) {
  if (typeof base64url !== "string" || base64url.length === 0) {
    throw new Error("base64UrlToBytes(base64url) requires string");
  }
  if (!/^[A-Za-z0-9\-_]+$/.test(base64url)) {
    throw new Error("base64UrlToBytes(base64url) invalid characters");
  }
  const padded = `${base64url}${"=".repeat((4 - (base64url.length % 4)) % 4)}`
    .replace(/-/g, "+")
    .replace(/_/g, "/");
  return base64ToBytes(padded);
}
