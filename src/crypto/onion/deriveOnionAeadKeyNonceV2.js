import { RCryptoProvider } from "../RCryptoProvider.js";
import { concatBytes } from "../util/bytes.js";
import { isBytes } from "../../util/bytes.js";

const INFO_LABEL = new TextEncoder().encode("rez-onion-v2");

function u32be(value) {
  const out = new Uint8Array(4);
  const view = new DataView(out.buffer);
  view.setUint32(0, value >>> 0, false);
  return out;
}

export async function deriveOnionAeadKeyNonceV2(crypto, sharedSecret, hopIndex) {
  if (!(crypto instanceof RCryptoProvider)) {
    throw new Error("deriveOnionAeadKeyNonceV2 requires crypto (RCryptoProvider)");
  }
  if (!isBytes(sharedSecret)) {
    throw new Error("deriveOnionAeadKeyNonceV2 requires sharedSecret Uint8Array");
  }
  if (!Number.isInteger(hopIndex) || hopIndex < 0) {
    throw new Error("deriveOnionAeadKeyNonceV2 requires hopIndex >= 0");
  }

  const info = concatBytes(INFO_LABEL, u32be(hopIndex));
  const out = await crypto.hkdfSha256(sharedSecret, { salt: new Uint8Array(0), info, length: 44 });
  return { aeadKey: out.subarray(0, 32), nonce: out.subarray(32, 44) };
}
