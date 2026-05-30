export const StringsCore = Object.freeze({
  safeTrim(s) {
    if (s == null) return "";
    return String(s).trim();
  },

  upperFirst(s) {
    if (s == null) return "";
    const str = String(s);
    if (str.length === 0) return "";
    return str[0].toUpperCase() + str.slice(1);
  },

  normalizeWhitespace(s) {
    if (s == null) return "";
    return String(s).replace(/\s+/g, " ").trim();
  }
});
