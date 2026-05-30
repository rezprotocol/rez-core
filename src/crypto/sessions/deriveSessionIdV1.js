import { RCryptoProvider } from "../RCryptoProvider.js";
import { isBytes } from "../../util/bytes.js";

export async function deriveSessionIdV1(crypto, sharedSecret) {
  if (!(crypto instanceof RCryptoProvider)) {
    throw new Error("deriveSessionIdV1 requires crypto (RCryptoProvider)");
  }
  if (!isBytes(sharedSecret)) {
    throw new Error("deriveSessionIdV1(sharedSecret) requires Uint8Array");
  }
  return crypto.hashSha256(sharedSecret);
}
