export const Ids = Object.freeze({
  isHex(s) {
    if (typeof s !== "string" || s.length === 0) return false;
    return /^[0-9a-fA-F]+$/.test(s);
  },

  toHex(bytes) {
    if (!(bytes instanceof Uint8Array)) {
      throw new Error("Ids.toHex requires Uint8Array");
    }
    let out = "";
    for (const b of bytes) {
      out += b.toString(16).padStart(2, "0");
    }
    return out;
  }
});
