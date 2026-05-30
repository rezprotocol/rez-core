const decoder = new TextDecoder();

export function parseOnionPlaintextV2(plaintextBytes) {
  if (!(plaintextBytes instanceof Uint8Array)) {
    throw new Error("parseOnionPlaintextV2 requires Uint8Array");
  }
  const json = decoder.decode(plaintextBytes);
  const obj = JSON.parse(json);
  if (!obj || typeof obj !== "object") {
    throw new Error("parseOnionPlaintextV2 requires object");
  }
  if (!Number.isInteger(obj.ttl) || obj.ttl < 0) {
    throw new Error("parseOnionPlaintextV2 requires ttl >= 0");
  }
  return obj;
}
