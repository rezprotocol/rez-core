import { RCodec } from "../base/index.js";
import { Envelope } from "../objects/Envelope.js";

function isPlainObject(v) {
  return v != null && typeof v === "object" && !Array.isArray(v);
}

function assertEnvelope(ctx) {
  if (!isPlainObject(ctx)) {
    throw new Error("CodecChain.encode(ctx) requires an object context");
  }
  if (!(ctx.envelope instanceof Envelope)) {
    throw new Error("CodecChain.encode(ctx) requires ctx.envelope (Envelope)");
  }
}

function assertBytes(ctx) {
  if (!isPlainObject(ctx)) {
    throw new Error("CodecChain.decode(ctx) requires an object context");
  }
  if (!(ctx.bytes instanceof Uint8Array)) {
    throw new Error("CodecChain.decode(ctx) requires ctx.bytes (Uint8Array)");
  }
}

export class CodecChain extends RCodec {
  constructor(codecs = []) {
    super();

    if (!Array.isArray(codecs)) {
      throw new Error("CodecChain requires an array of codecs");
    }

    for (const codec of codecs) {
      if (!(codec instanceof RCodec)) {
        throw new Error("CodecChain codecs must extend RCodec");
      }
    }

    this.codecs = Object.freeze([...codecs]);
  }

  encode(ctx) {
    assertEnvelope(ctx);

    for (const codec of this.codecs) {
      ctx = codec.encode(ctx) || ctx;
    }

    if (!(ctx.bytes instanceof Uint8Array)) {
      throw new Error("CodecChain.encode(ctx) must produce ctx.bytes (Uint8Array)");
    }

    return ctx;
  }

  decode(ctx) {
    assertBytes(ctx);

    for (let i = this.codecs.length - 1; i >= 0; i--) {
      const codec = this.codecs[i];
      ctx = codec.decode(ctx) || ctx;
    }

    if (!(ctx.envelope instanceof Envelope)) {
      throw new Error("CodecChain.decode(ctx) must produce ctx.envelope (Envelope)");
    }

    return ctx;
  }
}
