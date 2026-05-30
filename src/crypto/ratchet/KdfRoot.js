import { RCryptoProvider } from "../RCryptoProvider.js";
import { isBytes } from "../../util/bytes.js";

const INFO = new TextEncoder().encode("rez-ratchet-root-v1");

export async function deriveRootKey(crypto, rootKey, dhSecret) {
  if (!(crypto instanceof RCryptoProvider)) {
    throw new Error("deriveRootKey requires crypto (RCryptoProvider)");
  }
  if (!isBytes(rootKey) || !isBytes(dhSecret)) {
    throw new Error("deriveRootKey(rootKey, dhSecret) requires Uint8Array inputs");
  }

  const out = await crypto.hkdfSha256(dhSecret, { salt: rootKey, info: INFO, length: 96 });
  const newRootKey = out.subarray(0, 32);
  const sendingChainKey = out.subarray(32, 64);
  const receivingChainKey = out.subarray(64, 96);

  return { newRootKey, sendingChainKey, receivingChainKey };
}
