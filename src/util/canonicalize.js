function isPlainObject(v) {
  return v != null && typeof v === "object" && !Array.isArray(v);
}

export function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }

  if (isPlainObject(value)) {
    const out = {};
    const keys = Object.keys(value).sort();
    for (const k of keys) {
      out[k] = canonicalize(value[k]);
    }
    return out;
  }

  // primitives, null, etc.
  return value;
}

export function canonicalJSONStringify(value) {
  return JSON.stringify(canonicalize(value));
}
