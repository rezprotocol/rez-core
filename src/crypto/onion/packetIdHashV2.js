import { RCryptoProvider } from "../RCryptoProvider.js";
import { isBytes } from "../../util/bytes.js";

export async function packetIdHashV2(crypto, payloadBytes) {
  if (!(crypto instanceof RCryptoProvider)) {
    throw new Error("packetIdHashV2 requires crypto (RCryptoProvider)");
  }
  if (!isBytes(payloadBytes)) {
    throw new Error("packetIdHashV2 requires Uint8Array");
  }
  return crypto.hashSha256(payloadBytes);
}
