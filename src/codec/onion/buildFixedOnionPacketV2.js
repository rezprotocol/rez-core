import { OnionPacketV2, ONION_V2_SIZE_CLASSES } from "../../objects/onion/OnionPacketV2.js";

export function buildFixedOnionPacketV2(blobBytes, sizeClass) {
  if (!(blobBytes instanceof Uint8Array)) {
    throw new Error("buildFixedOnionPacketV2 requires blobBytes Uint8Array");
  }

  let chosen = sizeClass;
  if (chosen == null) {
    chosen = ONION_V2_SIZE_CLASSES.find((s) => s >= blobBytes.length);
  }

  if (!Number.isInteger(chosen) || chosen <= 0) {
    throw new Error("buildFixedOnionPacketV2 requires valid sizeClass");
  }
  if (blobBytes.length > chosen) {
    throw new Error("buildFixedOnionPacketV2 blob exceeds sizeClass");
  }

  const payload = new Uint8Array(chosen);
  payload.set(blobBytes, 0);
  return new OnionPacketV2({ v: 2, sizeClass: chosen, payload });
}
