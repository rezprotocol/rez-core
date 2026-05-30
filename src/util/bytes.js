const HEX_ALPHABET = "0123456789abcdef";
const B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Check if a value is a Uint8Array.
 * @param {*} value
 * @returns {boolean}
 */
export function isBytes(value) {
  return value instanceof Uint8Array;
}

function assertBytes(value, label) {
  if (!(value instanceof Uint8Array)) {
    throw new Error(`${label} requires Uint8Array`);
  }
}

/**
 * Normalize bytes-like input to Uint8Array.
 * Accepts Uint8Array, ArrayBuffer, or ArrayBuffer views.
 */
export function toUint8Array(input) {
  if (input instanceof Uint8Array) return input;
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  throw new Error("Expected bytes (Uint8Array/ArrayBuffer or view)");
}

export function cloneNonEmptyBytes(bytes, label) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
    throw new Error(`${label} must be a non-empty Uint8Array`);
  }
  return new Uint8Array(bytes);
}

export function bytesToHex(bytes) {
  assertBytes(bytes, "bytesToHex(bytes)");
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    const v = bytes[i];
    out += HEX_ALPHABET[v >>> 4];
    out += HEX_ALPHABET[v & 0x0f];
  }
  return out;
}

export function hexToBytes(hex) {
  if (typeof hex !== "string" || hex.length % 2 !== 0) {
    throw new Error("hexToBytes(hex) requires even-length string");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    const hi = HEX_ALPHABET.indexOf(hex[i].toLowerCase());
    const lo = HEX_ALPHABET.indexOf(hex[i + 1].toLowerCase());
    if (hi < 0 || lo < 0) {
      throw new Error("hexToBytes(hex) invalid hex");
    }
    out[i / 2] = (hi << 4) | lo;
  }
  return out;
}

export function bytesToBase64(bytes) {
  assertBytes(bytes, "bytesToBase64(bytes)");
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;

    const triple = (b0 << 16) | (b1 << 8) | b2;
    out += B64_ALPHABET[(triple >>> 18) & 0x3f];
    out += B64_ALPHABET[(triple >>> 12) & 0x3f];
    out += i + 1 < bytes.length ? B64_ALPHABET[(triple >>> 6) & 0x3f] : "=";
    out += i + 2 < bytes.length ? B64_ALPHABET[triple & 0x3f] : "=";
  }
  return out;
}

export function base64ToBytes(base64) {
  if (typeof base64 !== "string") {
    throw new Error("base64ToBytes(base64) requires string");
  }
  const cleaned = base64.replace(/\s+/g, "");
  if (cleaned.length % 4 !== 0) {
    throw new Error("base64ToBytes(base64) invalid length");
  }

  const pad = cleaned.endsWith("==") ? 2 : cleaned.endsWith("=") ? 1 : 0;
  const outLen = (cleaned.length / 4) * 3 - pad;
  const out = new Uint8Array(outLen);
  let outIndex = 0;

  for (let i = 0; i < cleaned.length; i += 4) {
    const c0 = cleaned[i];
    const c1 = cleaned[i + 1];
    const c2 = cleaned[i + 2];
    const c3 = cleaned[i + 3];

    const v0 = B64_ALPHABET.indexOf(c0);
    const v1 = B64_ALPHABET.indexOf(c1);
    const v2 = c2 === "=" ? 0 : B64_ALPHABET.indexOf(c2);
    const v3 = c3 === "=" ? 0 : B64_ALPHABET.indexOf(c3);
    if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0) {
      throw new Error("base64ToBytes(base64) invalid base64");
    }

    const triple = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
    if (outIndex < outLen) out[outIndex++] = (triple >>> 16) & 0xff;
    if (outIndex < outLen) out[outIndex++] = (triple >>> 8) & 0xff;
    if (outIndex < outLen) out[outIndex++] = triple & 0xff;
  }
  return out;
}
