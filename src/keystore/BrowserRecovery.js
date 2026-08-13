import { Identity } from "../identity/index.js";
import { createKeystoreEnvelope } from "./KeystoreEnvelope.js";
import {
  decryptKeystore,
  deriveUnlockKey,
  encryptKeystore,
  fromBase64,
  getDefaultKdfParams,
  randomBytes,
  toBase64,
} from "./keystoreCrypto.js";
import { BIP39_ENGLISH } from "../crypto/bip39Wordlist.js";

const VALID_WORD_COUNTS = Object.freeze([12, 15, 18, 21, 24]);
const BITS_PER_WORD = 11;
const HKDF_SALT = new TextEncoder().encode("rez-v1");
const ED25519_PKCS8_PREFIX = hexBytes("302e020100300506032b657004220420");
const ED25519_SPKI_PREFIX = hexBytes("302a300506032b6570032100");
const X25519_PKCS8_PREFIX = hexBytes("302e020100300506032b656e04220420");
const X25519_SPKI_PREFIX = hexBytes("302a300506032b656e032100");

export const BROWSER_ACCOUNT_SEED_LABEL = "rez/identity/desktop-account/v1";
export const BROWSER_ACCOUNT_DH_SEED_LABEL = "rez/identity/x3dh-dh/v1";

function cryptoApi() {
  const crypto = globalThis.crypto;
  if (!crypto || !crypto.subtle || typeof crypto.getRandomValues !== "function") {
    throw new Error("Browser recovery requires WebCrypto");
  }
  return crypto;
}

function hexBytes(value) {
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function concatBytes(left, right) {
  const out = new Uint8Array(left.length + right.length);
  out.set(left, 0);
  out.set(right, left.length);
  return out;
}

function bytesToBits(bytes) {
  let bits = "";
  for (const value of bytes) bits += value.toString(2).padStart(8, "0");
  return bits;
}

function bitsToBytes(bits) {
  const out = new Uint8Array(bits.length / 8);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  return out;
}

function normalizeMnemonic(value) {
  return String(value == null ? "" : value).normalize("NFKD").trim().toLowerCase().replace(/\s+/g, " ");
}

async function sha256(bytes) {
  return new Uint8Array(await cryptoApi().subtle.digest("SHA-256", bytes));
}

async function checksumBits(entropy) {
  const digest = await sha256(entropy);
  return bytesToBits(digest).slice(0, (entropy.length * 8) / 32);
}

function base64UrlToBytes(value) {
  const normalized = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  return fromBase64(padded);
}

async function deriveBytes(seed, label, length = 32) {
  const subtle = cryptoApi().subtle;
  const key = await subtle.importKey("raw", seed, "HKDF", false, ["deriveBits"]);
  const bits = await subtle.deriveBits({
    name: "HKDF",
    hash: "SHA-256",
    salt: HKDF_SALT,
    info: new TextEncoder().encode(label),
  }, key, length * 8);
  return new Uint8Array(bits);
}

async function deriveOkp(seed, label, algorithm, privatePrefix, publicPrefix) {
  const rawPrivate = await deriveBytes(seed, label, 32);
  const privateKeyBytes = concatBytes(privatePrefix, rawPrivate);
  try {
    const usages = algorithm === "Ed25519" ? ["sign"] : ["deriveBits"];
    const privateKey = await cryptoApi().subtle.importKey("pkcs8", privateKeyBytes, algorithm, true, usages);
    const jwk = await cryptoApi().subtle.exportKey("jwk", privateKey);
    const rawPublic = base64UrlToBytes(jwk.x);
    return {
      publicKeyB64: toBase64(concatBytes(publicPrefix, rawPublic)),
      privateKeyB64: toBase64(privateKeyBytes),
    };
  } finally {
    rawPrivate.fill(0);
    privateKeyBytes.fill(0);
  }
}

export async function generateBrowserMnemonic({ words = 24 } = {}) {
  if (!VALID_WORD_COUNTS.includes(words)) {
    throw new Error("Mnemonic words must be one of " + VALID_WORD_COUNTS.join(", "));
  }
  const entropy = randomBytes((words * BITS_PER_WORD * 32) / (33 * 8));
  try {
    const bits = bytesToBits(entropy) + await checksumBits(entropy);
    const result = [];
    for (let i = 0; i < bits.length; i += BITS_PER_WORD) {
      result.push(BIP39_ENGLISH[parseInt(bits.slice(i, i + BITS_PER_WORD), 2)]);
    }
    return result.join(" ");
  } finally {
    entropy.fill(0);
  }
}

export async function validateBrowserMnemonic(value) {
  const mnemonic = normalizeMnemonic(value);
  const words = mnemonic ? mnemonic.split(" ") : [];
  if (!VALID_WORD_COUNTS.includes(words.length)) return false;
  let bits = "";
  for (const word of words) {
    const index = BIP39_ENGLISH.indexOf(word);
    if (index < 0) return false;
    bits += index.toString(2).padStart(BITS_PER_WORD, "0");
  }
  const checksumLength = (words.length * BITS_PER_WORD) / 33;
  const entropy = bitsToBytes(bits.slice(0, bits.length - checksumLength));
  try {
    const expected = await checksumBits(entropy);
    return expected === bits.slice(bits.length - checksumLength);
  } finally {
    entropy.fill(0);
  }
}

export async function browserMnemonicToSeed(value) {
  const mnemonic = normalizeMnemonic(value);
  if (!(await validateBrowserMnemonic(mnemonic))) throw new Error("Recovery phrase is invalid");
  const subtle = cryptoApi().subtle;
  const passwordBytes = new TextEncoder().encode(mnemonic);
  const saltBytes = new TextEncoder().encode("mnemonic");
  try {
    const baseKey = await subtle.importKey("raw", passwordBytes, "PBKDF2", false, ["deriveBits"]);
    const bits = await subtle.deriveBits({ name: "PBKDF2", salt: saltBytes, iterations: 2048, hash: "SHA-512" }, baseKey, 512);
    return new Uint8Array(bits);
  } finally {
    passwordBytes.fill(0);
    saltBytes.fill(0);
  }
}

export async function deriveBrowserAccountRecovery(value) {
  const seed = await browserMnemonicToSeed(value);
  try {
    const identityKeyPair = await deriveOkp(seed, BROWSER_ACCOUNT_SEED_LABEL, "Ed25519", ED25519_PKCS8_PREFIX, ED25519_SPKI_PREFIX);
    const accountIdentityDhKeyPair = await deriveOkp(seed, BROWSER_ACCOUNT_DH_SEED_LABEL, "X25519", X25519_PKCS8_PREFIX, X25519_SPKI_PREFIX);
    return {
      identity: Identity.fromObject(identityKeyPair),
      identityKeyPair,
      accountIdentityDhKeyPair,
    };
  } finally {
    seed.fill(0);
  }
}

export async function sealBrowserRecoveryMnemonic({ mnemonic, password, cryptoProvider = null } = {}) {
  if (!(await validateBrowserMnemonic(mnemonic))) throw new Error("Recovery phrase is invalid");
  const nowMs = Date.now();
  const saltBytes = randomBytes(16, cryptoProvider);
  const kdfParams = getDefaultKdfParams(cryptoProvider);
  const unlockKeyBytes = await deriveUnlockKey({ password, saltBytes, kdfParams, cryptoProvider });
  try {
    const plaintext = new TextEncoder().encode(JSON.stringify({ mnemonic: normalizeMnemonic(mnemonic) }));
    try {
      const encrypted = await encryptKeystore({ unlockKeyBytes, plaintextJsonBytes: plaintext, cryptoProvider });
      return createKeystoreEnvelope({
        kdfParams,
        saltB64: toBase64(saltBytes),
        ciphertextB64: toBase64(encrypted.ciphertextBytes),
        createdAtMs: nowMs,
        updatedAtMs: nowMs,
      });
    } finally {
      plaintext.fill(0);
    }
  } finally {
    unlockKeyBytes.fill(0);
    saltBytes.fill(0);
  }
}

export async function openBrowserRecoveryMnemonic({ envelope, password, cryptoProvider = null } = {}) {
  const saltBytes = fromBase64(envelope && envelope.saltB64);
  const unlockKeyBytes = await deriveUnlockKey({
    password,
    saltBytes,
    kdfParams: envelope && envelope.kdfParams,
    cryptoProvider,
  });
  try {
    const plaintext = await decryptKeystore({ unlockKeyBytes, envelope, cryptoProvider });
    try {
      const parsed = JSON.parse(new TextDecoder().decode(plaintext));
      const mnemonic = normalizeMnemonic(parsed && parsed.mnemonic);
      if (!(await validateBrowserMnemonic(mnemonic))) throw new Error("Stored recovery phrase is invalid");
      return mnemonic;
    } finally {
      plaintext.fill(0);
    }
  } finally {
    unlockKeyBytes.fill(0);
    saltBytes.fill(0);
  }
}
