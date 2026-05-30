import { assertKeystoreEnvelope, normalizeKdfParams } from "./KeystoreEnvelope.js";
import { bytesToBase64, base64ToBytes } from "../util/bytes.js";

const DEFAULT_KDF_PARAMS = Object.freeze({
  type: "pbkdf2-sha256",
  iterations: 210000,
  keyLength: 32,
});

// OWASP minimum recommendation for interactive logins.
// N=2^17 requires ~128 MiB memory; the Node.js IPC bridge must set maxmem to ≥2× that.
const DEFAULT_SCRYPT_KDF_PARAMS = Object.freeze({
  type: "scrypt",
  N: 131072, // 2^17
  r: 8,
  p: 1,
  keyLength: 32,
});

function resolveCrypto(cryptoProvider = null) {
  const direct = cryptoProvider && typeof cryptoProvider === "object" ? cryptoProvider : null;
  const cryptoObj = direct?.crypto || direct || globalThis.crypto;
  const subtle = direct?.subtle || cryptoObj?.subtle;
  const getRandomValues = direct?.getRandomValues || cryptoObj?.getRandomValues;
  if (!subtle || typeof subtle.importKey !== "function") {
    throw new Error("WebCrypto subtle API is required for keystore operations");
  }
  if (typeof getRandomValues !== "function") {
    throw new Error("WebCrypto getRandomValues API is required for keystore operations");
  }
  return { subtle, getRandomValues: getRandomValues.bind(cryptoObj) };
}

/**
 * Returns the default KDF params for a new keystore.
 * If cryptoProvider supplies a native scrypt bridge, returns scrypt params (Electron only).
 * Otherwise returns PBKDF2 params (browser / server).
 */
export function getDefaultKdfParams(cryptoProvider = null) {
  if (cryptoProvider && typeof cryptoProvider.scrypt === "function") {
    return { ...DEFAULT_SCRYPT_KDF_PARAMS };
  }
  return { ...DEFAULT_KDF_PARAMS };
}

export function toBase64(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new Error("toBase64 requires Uint8Array");
  return bytesToBase64(bytes);
}

export function fromBase64(value) {
  const normalized = String(value || "").trim();
  if (!normalized) return new Uint8Array(0);
  return base64ToBytes(normalized);
}

export function randomBytes(length, cryptoProvider = null) {
  const size = Number(length);
  if (!Number.isInteger(size) || size <= 0) throw new Error("randomBytes length must be positive integer");
  const { getRandomValues } = resolveCrypto(cryptoProvider);
  const out = new Uint8Array(size);
  getRandomValues(out);
  return out;
}

export async function deriveUnlockKey({
  password = "",
  saltBytes,
  kdfParams = DEFAULT_KDF_PARAMS,
  cryptoProvider = null,
} = {}) {
  const pwd = String(password || "");
  if (!pwd) throw new Error("Password is required");
  if (!(saltBytes instanceof Uint8Array) || saltBytes.length < 16) {
    throw new Error("saltBytes must be a Uint8Array with at least 16 bytes");
  }
  const params = normalizeKdfParams(kdfParams);

  // scrypt dispatch: native Node.js bridge required (only available in Electron).
  // Existing PBKDF2 keystores always decrypt via PBKDF2 regardless of runtime.
  if (params.type === "scrypt") {
    const scryptFn = cryptoProvider && typeof cryptoProvider.scrypt === "function" ? cryptoProvider.scrypt : null;
    if (!scryptFn) {
      throw new Error(
        "scrypt KDF requires a native scrypt bridge (cryptoProvider.scrypt); not available in browser",
      );
    }
    const result = await scryptFn({
      password: pwd,
      salt: saltBytes,
      N: params.N,
      r: params.r,
      p: params.p,
      keyLen: params.keyLength,
    });
    if (result instanceof Uint8Array) return result;
    return new Uint8Array(result);
  }

  // PBKDF2 path (browser + server; also used for all existing keystores)
  const { subtle } = resolveCrypto(cryptoProvider);

  // Encode password to Uint8Array; zero it in finally to minimize exposure window.
  // (JS strings are immutable and cannot be zeroed, but the encoded buffer can.)
  const pwdBytes = new TextEncoder().encode(pwd);
  try {
    const baseKey = await subtle.importKey(
      "raw",
      pwdBytes,
      { name: "PBKDF2" },
      false,
      ["deriveBits"],
    );

    const bits = await subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: saltBytes,
        iterations: params.iterations,
        hash: "SHA-256",
      },
      baseKey,
      params.keyLength * 8,
    );

    return new Uint8Array(bits);
  } finally {
    pwdBytes.fill(0);
  }
}

async function importAesGcmKey(unlockKeyBytes, subtle) {
  if (!(unlockKeyBytes instanceof Uint8Array) || unlockKeyBytes.length < 16) {
    throw new Error("unlockKeyBytes must be Uint8Array with at least 16 bytes");
  }
  return subtle.importKey("raw", unlockKeyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function encryptKeystore({
  unlockKeyBytes,
  plaintextJsonBytes,
  cryptoProvider = null,
} = {}) {
  if (!(plaintextJsonBytes instanceof Uint8Array) || plaintextJsonBytes.length === 0) {
    throw new Error("plaintextJsonBytes must be a non-empty Uint8Array");
  }

  const { subtle } = resolveCrypto(cryptoProvider);
  const key = await importAesGcmKey(unlockKeyBytes, subtle);
  const iv = randomBytes(12, cryptoProvider);

  const encrypted = await subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plaintextJsonBytes,
  );

  const encryptedBytes = new Uint8Array(encrypted);
  const ciphertextBytes = new Uint8Array(iv.length + encryptedBytes.length);
  ciphertextBytes.set(iv, 0);
  ciphertextBytes.set(encryptedBytes, iv.length);

  return { ciphertextBytes };
}

export async function decryptKeystore({
  unlockKeyBytes,
  envelope,
  cryptoProvider = null,
} = {}) {
  const normalizedEnvelope = assertKeystoreEnvelope(envelope);
  const { subtle } = resolveCrypto(cryptoProvider);
  const key = await importAesGcmKey(unlockKeyBytes, subtle);

  const payloadBytes = fromBase64(normalizedEnvelope.ciphertextB64);
  if (payloadBytes.length <= 12) {
    throw new Error("Keystore ciphertext is invalid");
  }

  const iv = payloadBytes.slice(0, 12);
  const encryptedBody = payloadBytes.slice(12);

  const decrypted = await subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    encryptedBody,
  );

  return new Uint8Array(decrypted);
}
