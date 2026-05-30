const VERSION = 0x02;
const HEADER_LEN = 1;

export function encodeOuterPacket({ bodyBytes } = {}) {
  if (!(bodyBytes instanceof Uint8Array)) {
    throw new Error("encodeOuterPacket requires Uint8Array bodyBytes");
  }
  const out = new Uint8Array(HEADER_LEN + bodyBytes.length);
  out[0] = VERSION;
  out.set(bodyBytes, HEADER_LEN);
  return out;
}

export function decodeOuterPacket(packetBytes) {
  if (!(packetBytes instanceof Uint8Array)) {
    throw new Error("decodeOuterPacket requires Uint8Array");
  }
  if (packetBytes.length < HEADER_LEN) {
    throw new Error("OuterPacket packet too short");
  }

  const version = packetBytes[0];
  if (version !== VERSION) {
    throw new Error("OuterPacket invalid version: " + version);
  }

  return {
    version,
    bodyOffset: HEADER_LEN,
    bodyBytesView: packetBytes.subarray(HEADER_LEN),
  };
}
