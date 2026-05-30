import { RCryptoProvider } from "../RCryptoProvider.js";
import { concatBytes } from "../util/bytes.js";
import { isBytes } from "../../util/bytes.js";

const INFO_LABEL = new TextEncoder().encode("rez-aead-v1");

function u32be(value) {
  const out = new Uint8Array(4);
  const view = new DataView(out.buffer);
  view.setUint32(0, value >>> 0, false);
  return out;
}

export async function deriveAeadKeyNonceV1(crypto, messageKey, sid, pn, n, dh) {
  if (!(crypto instanceof RCryptoProvider)) {
    throw new Error("deriveAeadKeyNonceV1 requires crypto (RCryptoProvider)");
  }
  if (!isBytes(messageKey)) {
    throw new Error("deriveAeadKeyNonceV1 requires messageKey Uint8Array");
  }
  if (!isBytes(sid)) {
    throw new Error("deriveAeadKeyNonceV1 requires sid Uint8Array");
  }
  if (!Number.isInteger(pn) || pn < 0 || !Number.isInteger(n) || n < 0) {
    throw new Error("deriveAeadKeyNonceV1 requires pn/n >= 0");
  }
  if (dh != null && !isBytes(dh)) {
    throw new Error("deriveAeadKeyNonceV1 requires dh Uint8Array or null");
  }

  const dhHash = dh ? await crypto.hashSha256(dh) : new Uint8Array(32);
  const info = concatBytes(INFO_LABEL, sid, u32be(pn), u32be(n), dhHash);
  const out = await crypto.hkdfSha256(messageKey, { salt: new Uint8Array(0), info, length: 44 });
  return { aeadKey: out.subarray(0, 32), nonce: out.subarray(32, 44) };
}
