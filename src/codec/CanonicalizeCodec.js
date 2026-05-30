import { RCodec } from "../base/index.js";
import { Envelope } from "../objects/Envelope.js";
import { canonicalize } from "../util/canonicalize.js";

function isPlainObject(v) {
  return v != null && typeof v === "object" && !Array.isArray(v);
}

export class CanonicalizeCodec extends RCodec {
  encode(ctx) {
    if (!isPlainObject(ctx)) {
      throw new Error("CanonicalizeCodec.encode(ctx) requires an object context");
    }
    if (!(ctx.envelope instanceof Envelope)) {
      throw new Error("CanonicalizeCodec.encode(ctx) requires ctx.envelope (Envelope)");
    }

    const json = ctx.envelope.toJSON();
    const canonical = canonicalize(json);
    ctx.envelope = Envelope.fromJSON(canonical);
    return ctx;
  }

  decode(ctx) {
    if (ctx == null || typeof ctx !== "object") {
      throw new Error("CanonicalizeCodec.decode(ctx) requires an object context");
    }
    return ctx;
  }
}
