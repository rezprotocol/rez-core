import { toUint8Array } from "./bytes.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * Encode a plain object to UTF-8 bytes (JSON.stringify + TextEncoder).
 * For typed Envelope + codec pipeline use RezRuntime.encodeEnvelope.
 */
export function objectToBytes(obj) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
    throw new Error("objectToBytes(obj) requires a plain object");
  }
  return encoder.encode(JSON.stringify(obj));
}

/**
 * Decode UTF-8 bytes to a plain object (TextDecoder + JSON.parse).
 * For typed Envelope use RezRuntime.decodeEnvelope.
 */
export function bytesToObject(bytes) {
  const parsed = JSON.parse(decoder.decode(toUint8Array(bytes)));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("bytesToObject(bytes) produced a non-object");
  }
  return parsed;
}
