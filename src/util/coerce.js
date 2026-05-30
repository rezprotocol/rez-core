export function asInt(value, fallback = 0) {
  const parsed = Number.parseInt(String(value), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function nonEmpty(value) {
  const text = String(value || "").trim();
  return text || null;
}

export function requireId(value, name) {
  const id = nonEmpty(value);
  if (!id) throw new Error(`missing required id: ${name}`);
  return id;
}
