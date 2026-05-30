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
