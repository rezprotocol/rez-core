import { RCryptoProvider } from "../RCryptoProvider.js";
import { isBytes } from "../../util/bytes.js";

const INFO = new TextEncoder().encode("rez-ratchet-chain-v1");

export async function deriveMessageKey(crypto, chainKey) {
  if (!(crypto instanceof RCryptoProvider)) {
    throw new Error("deriveMessageKey requires crypto (RCryptoProvider)");
  }
  if (!isBytes(chainKey)) {
    throw new Error("deriveMessageKey(chainKey) requires Uint8Array");
  }

  const out = await crypto.hkdfSha256(chainKey, { salt: new Uint8Array(0), info: INFO, length: 64 });
  const messageKey = out.subarray(0, 32);
  const nextChainKey = out.subarray(32, 64);

  return { messageKey, nextChainKey };
}
