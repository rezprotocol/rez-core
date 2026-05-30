import { RCryptoProvider } from "../../src/crypto/RCryptoProvider.js";

function isBytes(value) {
  return value instanceof Uint8Array;
}

function concatBytes(...parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function fakeHash(bytes) {
  if (!isBytes(bytes)) {
    throw new Error("fakeHash requires Uint8Array");
  }
  const out = new Uint8Array(32);
  let acc = 0x811c9dc5;
  for (let i = 0; i < bytes.length; i += 1) {
    acc ^= bytes[i];
    acc = Math.imul(acc, 0x01000193) >>> 0;
  }
  for (let i = 0; i < out.length; i += 1) {
    acc ^= (bytes.length + i) & 0xff;
    acc = Math.imul(acc, 0x01000193) >>> 0;
    out[i] = acc & 0xff;
  }
  return out;
}

export class FakeCryptoProvider extends RCryptoProvider {
  constructor({ seed = 1 } = {}) {
    super();
    this._state = seed >>> 0;
  }

  _nextByte() {
    this._state = (Math.imul(this._state, 1664525) + 1013904223) >>> 0;
    return this._state & 0xff;
  }

  randomBytes(len) {
    if (!Number.isInteger(len) || len <= 0) {
      throw new Error("FakeCryptoProvider.randomBytes(len) requires positive integer");
    }
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i += 1) out[i] = this._nextByte();
    return out;
  }

  hashSha256(bytes) {
    return fakeHash(bytes);
  }

  hkdfSha256(ikm, { salt = new Uint8Array(0), info = new Uint8Array(0), length = 32 } = {}) {
    if (!isBytes(ikm) || !isBytes(salt) || !isBytes(info)) {
      throw new Error("FakeCryptoProvider.hkdfSha256 requires Uint8Array inputs");
    }
    if (!Number.isInteger(length) || length <= 0) {
      throw new Error("FakeCryptoProvider.hkdfSha256 length must be positive integer");
    }

    const seed = concatBytes(salt, ikm, info);
    const out = new Uint8Array(length);
    let offset = 0;
    let counter = 0;
    while (offset < length) {
      const block = fakeHash(concatBytes(seed, new Uint8Array([counter & 0xff])));
      const chunk = block.subarray(0, Math.min(block.length, length - offset));
      out.set(chunk, offset);
      offset += chunk.length;
      counter += 1;
    }
    return out;
  }

  aeadEncrypt({ key, nonce, plaintext, aad } = {}) {
    if (!isBytes(key) || !isBytes(nonce) || !isBytes(plaintext) || !isBytes(aad)) {
      throw new Error("FakeCryptoProvider.aeadEncrypt requires Uint8Array inputs");
    }
    const mac = fakeHash(concatBytes(key, nonce, aad, plaintext));
    return concatBytes(mac, plaintext);
  }

  aeadDecrypt({ key, nonce, ciphertext, aad } = {}) {
    if (!isBytes(key) || !isBytes(nonce) || !isBytes(ciphertext) || !isBytes(aad)) {
      throw new Error("FakeCryptoProvider.aeadDecrypt requires Uint8Array inputs");
    }
    if (ciphertext.length < 32) {
      throw new Error("FakeCryptoProvider.aeadDecrypt requires mac+plaintext");
    }
    const mac = ciphertext.subarray(0, 32);
    const plaintext = ciphertext.subarray(32);
    const expected = fakeHash(concatBytes(key, nonce, aad, plaintext));
    if (!bytesEqual(mac, expected)) {
      throw new Error("FakeCryptoProvider.aeadDecrypt integrity check failed");
    }
    return plaintext;
  }

  sign({ privateKey, msg } = {}) {
    if (!isBytes(privateKey) || !isBytes(msg)) {
      throw new Error("FakeCryptoProvider.sign requires Uint8Array inputs");
    }
    return fakeHash(concatBytes(privateKey, msg));
  }

  verify({ publicKey, msg, sig } = {}) {
    if (!isBytes(publicKey) || !isBytes(msg) || !isBytes(sig)) {
      throw new Error("FakeCryptoProvider.verify requires Uint8Array inputs");
    }
    const expected = fakeHash(concatBytes(publicKey, msg));
    return bytesEqual(expected, sig);
  }

  dhGenerateKeyPair() {
    const privateKey = this.randomBytes(32);
    const publicKey = privateKey.slice();
    return { publicKey, privateKey };
  }

  dhDerive({ privateKey, publicKey } = {}) {
    if (!isBytes(privateKey) || !isBytes(publicKey)) {
      throw new Error("FakeCryptoProvider.dhDerive requires Uint8Array keys");
    }
    const selfPublic = privateKey;
    const otherPublic = publicKey;
    const order = bytesEqual(selfPublic, otherPublic) ? 0 : compareBytes(selfPublic, otherPublic);
    const left = order <= 0 ? selfPublic : otherPublic;
    const right = order <= 0 ? otherPublic : selfPublic;
    return fakeHash(concatBytes(left, right));
  }
}

function compareBytes(a, b) {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i += 1) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}
