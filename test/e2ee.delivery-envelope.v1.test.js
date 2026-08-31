import test from "node:test";
import assert from "node:assert/strict";

import {
  E2eeDeliveryEnvelopeV1,
  E2EE_DELIVERY_ENVELOPE_KIND,
  E2EE_DELIVERY_ENVELOPE_PURPOSE,
  E2EE_DELIVERY_ENVELOPE_VERSION,
  SUPPORTED_E2EE_DELIVERY_ENVELOPE_VERSIONS,
  e2eeDeliveryEnvelopeVersionOf,
  isSupportedE2eeDeliveryEnvelopeVersion,
} from "../src/e2ee/index.js";

const GOLDEN_JSON = "{\"createdAtMs\":1750000000000,\"deliveryId\":\"dlv_0123456789abcdef\",\"expiresAtMs\":1750000060000,\"kind\":\"rez.e2ee.delivery-envelope.v1\",\"payloadB64\":\"aGVsbG8sIHJleg==\",\"purpose\":\"rez:e2ee-delivery-envelope:v1\",\"v\":1}";

function goldenInput() {
  return {
    kind: E2EE_DELIVERY_ENVELOPE_KIND,
    v: E2EE_DELIVERY_ENVELOPE_VERSION,
    purpose: E2EE_DELIVERY_ENVELOPE_PURPOSE,
    deliveryId: "dlv_0123456789abcdef",
    createdAtMs: 1750000000000,
    expiresAtMs: 1750000060000,
    payloadB64: "aGVsbG8sIHJleg==",
  };
}

test("E2eeDeliveryEnvelopeV1 canonical bytes match the frozen golden", () => {
  const record = new E2eeDeliveryEnvelopeV1(goldenInput());
  assert.equal(new TextDecoder().decode(record.toBytes()), GOLDEN_JSON);
  assert.equal(new TextDecoder().decode(record.payloadBytes()), "hello, rez");
});

test("E2eeDeliveryEnvelopeV1 round-trips independently of input key order", () => {
  const input = goldenInput();
  const reordered = {
    payloadB64: input.payloadB64,
    expiresAtMs: input.expiresAtMs,
    createdAtMs: input.createdAtMs,
    deliveryId: input.deliveryId,
    purpose: input.purpose,
    v: input.v,
    kind: input.kind,
  };
  const decoded = E2eeDeliveryEnvelopeV1.fromBytes(
    new E2eeDeliveryEnvelopeV1(reordered).toBytes(),
  );
  assert.deepEqual(decoded.toJSON(), input);
  assert.equal(new TextDecoder().decode(decoded.toBytes()), GOLDEN_JSON);
});

test("E2eeDeliveryEnvelopeV1 version negotiation is explicit and legacy bytes are not misclassified", () => {
  assert.deepEqual(SUPPORTED_E2EE_DELIVERY_ENVELOPE_VERSIONS, [1]);
  assert.equal(isSupportedE2eeDeliveryEnvelopeVersion(1), true);
  assert.equal(isSupportedE2eeDeliveryEnvelopeVersion(2), false);
  assert.equal(e2eeDeliveryEnvelopeVersionOf(goldenInput()), 1);
  assert.equal(e2eeDeliveryEnvelopeVersionOf({ kind: "rez.chat.message.v1", messageId: "m1" }), null);
  assert.throws(
    () => E2eeDeliveryEnvelopeV1.fromBytes(new TextEncoder().encode('{"kind":"rez.chat.message.v1"}')),
    /unknown field|kind must be/,
  );
});

test("E2eeDeliveryEnvelopeV1 rejects invalid identity, time, payload, version, and schema drift", () => {
  assert.throws(() => new E2eeDeliveryEnvelopeV1({ ...goldenInput(), deliveryId: "bad id" }), /deliveryId/);
  assert.throws(() => new E2eeDeliveryEnvelopeV1({ ...goldenInput(), expiresAtMs: 1750000000000 }), /expiresAtMs/);
  assert.throws(() => new E2eeDeliveryEnvelopeV1({ ...goldenInput(), payloadB64: "aGVsbG8" }), /base64/);
  assert.throws(() => new E2eeDeliveryEnvelopeV1({ ...goldenInput(), v: 2 }), /v must be 1/);
  assert.throws(() => new E2eeDeliveryEnvelopeV1({ ...goldenInput(), carrierId: "smtp" }), /unknown field/);
});

test("E2eeDeliveryEnvelopeV1 rejects prototype-poisoning keys at the byte boundary", () => {
  const hostile = GOLDEN_JSON.slice(0, -1) + ',"__proto__":{"admin":true}}';
  assert.throws(
    () => E2eeDeliveryEnvelopeV1.fromBytes(new TextEncoder().encode(hostile)),
    (err) => err && err.code === "UNSAFE_JSON_KEY",
  );
});
