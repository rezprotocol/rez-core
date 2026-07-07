const BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

export function bytesToBase32(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new Error("bytesToBase32(bytes) requires Uint8Array");
  let out = "";
  let bits = 0;
  let buffer = 0;
  for (let i = 0; i < bytes.length; i += 1) {
    buffer = (buffer << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      const idx = (buffer >>> (bits - 5)) & 31;
      out += BASE32_ALPHABET[idx];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(buffer << (5 - bits)) & 31];
  }
  return out;
}

// Strict decoder for the encoding above (no padding). Rejects characters
// outside the alphabet, lengths that cannot come from whole bytes, and
// non-canonical trailing bits (any input must round-trip byte-for-byte
// through bytesToBase32 — a forgiving decoder would let two different
// strings decode to the same secret).
export function base32ToBytes(text) {
  if (typeof text !== "string") throw new Error("base32ToBytes(text) requires a string");
  const byteLength = Math.floor((text.length * 5) / 8);
  // A whole-byte encoding has length ceil(byteLength*8/5); anything else has
  // a dangling character that cannot carry data.
  const expectedLength = Math.ceil((byteLength * 8) / 5);
  if (text.length !== expectedLength) {
    throw new Error("base32ToBytes: non-canonical length");
  }
  const out = new Uint8Array(byteLength);
  let bits = 0;
  let buffer = 0;
  let outIndex = 0;
  for (let i = 0; i < text.length; i += 1) {
    const idx = BASE32_ALPHABET.indexOf(text[i]);
    if (idx < 0) throw new Error("base32ToBytes: invalid character");
    buffer = (buffer << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out[outIndex] = (buffer >>> (bits - 8)) & 0xff;
      outIndex += 1;
      bits -= 8;
    }
  }
  // Canonical trailing bits: the final partial group must be zero-padded
  // exactly the way the encoder emits it.
  if (bits > 0 && (buffer & ((1 << bits) - 1)) !== 0) {
    throw new Error("base32ToBytes: non-canonical trailing bits");
  }
  return out;
}
