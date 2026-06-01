import { randomBytes, createHash, pbkdf2 } from "node:crypto";
import { promisify } from "node:util";
import { BIP39_ENGLISH } from "./bip39Wordlist.js";

const pbkdf2Async = promisify(pbkdf2);

const WORDLIST_SIZE = 2048;
const BITS_PER_WORD = 11;
const VALID_WORD_COUNTS = Object.freeze([12, 15, 18, 21, 24]);

const WORD_INDEX = new Map();
for (let i = 0; i < BIP39_ENGLISH.length; i += 1) {
  WORD_INDEX.set(BIP39_ENGLISH[i], i);
}

function assertWordlistShape() {
  if (BIP39_ENGLISH.length !== WORDLIST_SIZE) {
    throw new Error(`Bip39: wordlist length ${BIP39_ENGLISH.length} != 2048`);
  }
}

function normalizeMnemonicText(text) {
  const raw = String(text == null ? "" : text);
  return raw.normalize("NFKD").trim().toLowerCase().replace(/\s+/g, " ");
}

function entropyBytesForWordCount(wordCount) {
  // BIP39: ENT (entropy bits) + CS (checksum bits) = wordCount * 11,
  //        CS = ENT / 32, so ENT = wordCount * 11 * 32 / 33.
  if (!VALID_WORD_COUNTS.includes(wordCount)) {
    throw new Error(`Bip39: wordCount must be one of ${VALID_WORD_COUNTS.join(", ")}`);
  }
  return (wordCount * BITS_PER_WORD * 32) / (33 * 8);
}

function bytesToBitString(bytes) {
  let bits = "";
  for (let i = 0; i < bytes.length; i += 1) {
    bits += bytes[i].toString(2).padStart(8, "0");
  }
  return bits;
}

function bitsToBytes(bits) {
  if (bits.length % 8 !== 0) {
    throw new Error("Bip39: bit string length must be a multiple of 8");
  }
  const out = new Uint8Array(bits.length / 8);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  }
  return out;
}

function entropyToChecksumBits(entropy) {
  const hash = createHash("sha256").update(entropy).digest();
  const checksumLength = (entropy.length * 8) / 32;
  return bytesToBitString(hash).slice(0, checksumLength);
}

export class Bip39 {
  static get WORDLIST() {
    return BIP39_ENGLISH;
  }

  static generateMnemonic({ words = 24 } = {}) {
    assertWordlistShape();
    const entropyBytes = entropyBytesForWordCount(words);
    const entropy = randomBytes(entropyBytes);
    return Bip39.entropyToMnemonic(entropy);
  }

  static entropyToMnemonic(entropyBytes) {
    assertWordlistShape();
    if (!(entropyBytes instanceof Uint8Array) && !Buffer.isBuffer(entropyBytes)) {
      throw new Error("Bip39.entropyToMnemonic: entropy must be Uint8Array or Buffer");
    }
    const bytes = entropyBytes instanceof Uint8Array ? entropyBytes : new Uint8Array(entropyBytes);
    if (bytes.length < 16 || bytes.length > 32 || bytes.length % 4 !== 0) {
      throw new Error(`Bip39.entropyToMnemonic: entropy length must be 16/20/24/28/32 bytes, got ${bytes.length}`);
    }
    const bits = bytesToBitString(bytes) + entropyToChecksumBits(bytes);
    const words = [];
    for (let i = 0; i < bits.length; i += BITS_PER_WORD) {
      const index = parseInt(bits.slice(i, i + BITS_PER_WORD), 2);
      words.push(BIP39_ENGLISH[index]);
    }
    return words.join(" ");
  }

  /**
   * Validate a mnemonic against the English wordlist and checksum.
   * Returns { ok: boolean, entropyBytes?: Uint8Array, error?: string }.
   * Never throws on bad input — caller decides how to surface failures.
   */
  static validateMnemonic(text) {
    assertWordlistShape();
    const normalized = normalizeMnemonicText(text);
    if (!normalized) {
      return { ok: false, error: "empty" };
    }
    const wordsArray = normalized.split(" ");
    if (!VALID_WORD_COUNTS.includes(wordsArray.length)) {
      return { ok: false, error: `wordCount=${wordsArray.length} not in [${VALID_WORD_COUNTS.join(", ")}]` };
    }
    const indices = new Array(wordsArray.length);
    for (let i = 0; i < wordsArray.length; i += 1) {
      const idx = WORD_INDEX.get(wordsArray[i]);
      if (typeof idx !== "number") {
        return { ok: false, error: `word #${i + 1} "${wordsArray[i]}" not in wordlist` };
      }
      indices[i] = idx;
    }
    let bits = "";
    for (let i = 0; i < indices.length; i += 1) {
      bits += indices[i].toString(2).padStart(BITS_PER_WORD, "0");
    }
    const checksumLength = (wordsArray.length * BITS_PER_WORD) / 33;
    const entropyBits = bits.slice(0, bits.length - checksumLength);
    const checksumBits = bits.slice(bits.length - checksumLength);
    const entropyBytes = bitsToBytes(entropyBits);
    const expectedChecksum = entropyToChecksumBits(entropyBytes);
    if (expectedChecksum !== checksumBits) {
      return { ok: false, error: "checksum mismatch" };
    }
    return { ok: true, entropyBytes };
  }

  /**
   * Derive a 64-byte seed per BIP39:
   *   PBKDF2-HMAC-SHA512(NFKD(mnemonic), "mnemonic" + NFKD(passphrase), 2048, 64)
   * Does NOT enforce checksum validity — call validateMnemonic() first if you want to reject bad inputs.
   * Returns a Buffer of length 64.
   */
  static async mnemonicToSeed(text, passphrase = "") {
    const mnemonicNorm = normalizeMnemonicText(text);
    if (!mnemonicNorm) {
      throw new Error("Bip39.mnemonicToSeed: mnemonic is empty");
    }
    const passNorm = String(passphrase == null ? "" : passphrase).normalize("NFKD");
    const password = Buffer.from(mnemonicNorm, "utf8");
    const salt = Buffer.from("mnemonic" + passNorm, "utf8");
    return pbkdf2Async(password, salt, 2048, 64, "sha512");
  }
}
