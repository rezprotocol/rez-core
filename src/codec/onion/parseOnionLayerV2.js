const decoder = new TextDecoder();

function trimTrailingZeros(bytes) {
  let end = bytes.length;
  while (end > 0 && bytes[end - 1] === 0) end -= 1;
  return bytes.subarray(0, end);
}

export function parseOnionLayerV2(payloadBytes) {
  if (!(payloadBytes instanceof Uint8Array)) {
    throw new Error("parseOnionLayerV2 requires payloadBytes Uint8Array");
  }
  const trimmed = trimTrailingZeros(payloadBytes);
  if (trimmed.length === 0) {
    throw new Error("parseOnionLayerV2 requires non-empty payload");
  }
  const json = decoder.decode(trimmed);
  const obj = JSON.parse(json);
  if (!obj || typeof obj !== "object") {
    throw new Error("parseOnionLayerV2 requires object");
  }
  if (!Number.isSafeInteger(obj.hopIndex) || obj.hopIndex < 0) {
    throw new Error("parseOnionLayerV2 requires hopIndex >= 0");
  }
  if (!Number.isInteger(obj.ttl) || obj.ttl < 0) {
    throw new Error("parseOnionLayerV2 requires ttl >= 0");
  }
  return obj;
}
