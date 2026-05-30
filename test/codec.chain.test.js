import test from "node:test";
import assert from "node:assert/strict";
import { Header } from "../src/objects/Header.js";
import { Envelope } from "../src/objects/Envelope.js";
import { RCodec } from "@rezprotocol/core";
import { canonicalize } from "../src/util/canonicalize.js";
import { CodecChain } from "../src/codec/CodecChain.js";
import { JsonCodec } from "../src/codec/JsonCodec.js";
import { CanonicalizeCodec } from "../src/codec/CanonicalizeCodec.js";

function makeEnvelope() {
  const header = new Header({ id: "1", type: "message", createdAt: 1 });
  return new Envelope({
    header,
    body: { z: 1, a: { b: 2, a: 1 } },
  });
}

class StepCodecA extends RCodec {
  encode(ctx) {
    ctx.meta.steps.push("A");
    return ctx;
  }

  decode(ctx) {
    ctx.meta.steps.push("A");
    return ctx;
  }
}

class StepCodecB extends RCodec {
  encode(ctx) {
    ctx.meta.steps.push("B");
    return ctx;
  }

  decode(ctx) {
    ctx.meta.steps.push("B");
    return ctx;
  }
}

test("CodecChain round-trip with canonicalization", () => {
  const envelope = makeEnvelope();
  const chain = new CodecChain([new CanonicalizeCodec(), new JsonCodec()]);

  const encoded = chain.encode({ envelope });
  const decoded = chain.decode({ bytes: encoded.bytes });

  const expected = canonicalize(envelope.toJSON());
  assert.deepEqual(decoded.envelope.toJSON(), expected);
});

test("CodecChain enforces codec order", () => {
  const envelope = makeEnvelope();
  const chain = new CodecChain([new StepCodecA(), new StepCodecB(), new JsonCodec()]);

  const metaEncode = { steps: [] };
  const encoded = chain.encode({ envelope, meta: metaEncode });
  assert.deepEqual(metaEncode.steps, ["A", "B"]);

  const metaDecode = { steps: [] };
  const decoded = chain.decode({ bytes: encoded.bytes, meta: metaDecode });
  assert.deepEqual(metaDecode.steps, ["B", "A"]);
  assert.equal(decoded.envelope instanceof Envelope, true);
});

test("CodecChain validates context", () => {
  const chain = new CodecChain([new JsonCodec()]);
  assert.throws(() => chain.encode({}), /requires ctx\.envelope/);
  assert.throws(() => chain.decode({}), /requires ctx\.bytes/);
  assert.throws(() => chain.encode({ envelope: {} }), /Envelope/);
  assert.throws(() => chain.decode({ bytes: "nope" }), /Uint8Array/);
});
