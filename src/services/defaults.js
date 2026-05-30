import { CodecChain } from "../codec/CodecChain.js";
import { CanonicalizeCodec } from "../codec/CanonicalizeCodec.js";
import { JsonCodec } from "../codec/JsonCodec.js";

export function createDefaultCodecChain() {
  return new CodecChain([new CanonicalizeCodec(), new JsonCodec()]);
}
