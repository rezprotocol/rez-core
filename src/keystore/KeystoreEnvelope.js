export const KEYSTORE_ENVELOPE_VERSION = 1;

export function normalizeKdfParams(input = {}) {
  const src = input && typeof input === "object" ? input : {};
  const type = String(src.type || "pbkdf2-sha256").trim().toLowerCase();

  if (type === "scrypt") {
    const N = Number(src.N);
    const r = Number(src.r);
    const p = Number(src.p);
    const keyLength = Number(src.keyLength);
    if (!Number.isInteger(N) || N < 1024 || (N & (N - 1)) !== 0) {
      throw new Error(`Invalid scrypt N (must be power-of-two >= 1024): ${String(src.N ?? "")}`);
    }
    if (!Number.isInteger(r) || r < 1) {
      throw new Error(`Invalid scrypt r: ${String(src.r ?? "")}`);
    }
    if (!Number.isInteger(p) || p < 1) {
      throw new Error(`Invalid scrypt p: ${String(src.p ?? "")}`);
    }
    if (!Number.isInteger(keyLength) || keyLength < 16 || keyLength > 64) {
      throw new Error(`Invalid keystore KDF keyLength: ${String(src.keyLength ?? "")}`);
    }
    return { type, N, r, p, keyLength };
  }

  if (type !== "pbkdf2-sha256") {
    throw new Error(`Unsupported keystore KDF type: ${type || "(empty)"}`);
  }

  const iterations = Number(src.iterations);
  const keyLength = Number(src.keyLength);
  if (!Number.isInteger(iterations) || iterations < 100000) {
    throw new Error(`Invalid keystore KDF iterations: ${String(src.iterations || "")}`);
  }
  if (!Number.isInteger(keyLength) || keyLength < 16 || keyLength > 64) {
    throw new Error(`Invalid keystore KDF keyLength: ${String(src.keyLength || "")}`);
  }

  return { type, iterations, keyLength };
}

export function assertKeystoreEnvelope(value) {
  if (!value || typeof value !== "object") throw new Error("Keystore envelope must be an object");

  const version = Number(value.version);
  if (version !== KEYSTORE_ENVELOPE_VERSION) {
    throw new Error(`Unsupported keystore envelope version: ${String(value.version || "")}`);
  }

  const saltB64 = String(value.saltB64 || "").trim();
  if (!saltB64) throw new Error("Keystore envelope saltB64 is required");

  const ciphertextB64 = String(value.ciphertextB64 || "").trim();
  if (!ciphertextB64) throw new Error("Keystore envelope ciphertextB64 is required");

  const createdAtMs = Number(value.createdAtMs);
  const updatedAtMs = Number(value.updatedAtMs);
  if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) {
    throw new Error("Keystore envelope createdAtMs must be a positive number");
  }
  if (!Number.isFinite(updatedAtMs) || updatedAtMs <= 0) {
    throw new Error("Keystore envelope updatedAtMs must be a positive number");
  }

  return {
    version,
    kdfParams: normalizeKdfParams(value.kdfParams),
    saltB64,
    ciphertextB64,
    createdAtMs,
    updatedAtMs,
  };
}

export function createKeystoreEnvelope({
  kdfParams,
  saltB64,
  ciphertextB64,
  createdAtMs = Date.now(),
  updatedAtMs = Date.now(),
} = {}) {
  return assertKeystoreEnvelope({
    version: KEYSTORE_ENVELOPE_VERSION,
    kdfParams: normalizeKdfParams(kdfParams),
    saltB64: String(saltB64 || ""),
    ciphertextB64: String(ciphertextB64 || ""),
    createdAtMs: Number(createdAtMs),
    updatedAtMs: Number(updatedAtMs),
  });
}
