import { RCodec } from "../base/index.js";
import { Envelope } from "../objects/Envelope.js";

function isPlainObject(v) {
  return v != null && typeof v === "object" && !Array.isArray(v);
}

export class JsonCodec extends RCodec {
  encode(ctx) {
    if (!isPlainObject(ctx)) {
      throw new Error("JsonCodec.encode(ctx) requires an object context");
    }
    if (!(ctx.envelope instanceof Envelope)) {
      throw new Error("JsonCodec.encode(ctx) requires ctx.envelope (Envelope)");
    }

    const json = ctx.envelope.toJSON();
    const text = JSON.stringify(json);
    ctx.bytes = new TextEncoder().encode(text);
    return ctx;
  }

  decode(ctx) {
    if (!isPlainObject(ctx)) {
      throw new Error("JsonCodec.decode(ctx) requires an object context");
    }
    if (!(ctx.bytes instanceof Uint8Array)) {
      throw new Error("JsonCodec.decode(ctx) requires ctx.bytes (Uint8Array)");
    }

    const text = new TextDecoder().decode(ctx.bytes);
    const json = JSON.parse(text);
    ctx.envelope = Envelope.fromJSON(json);
    return ctx;
  }
}
