import test from "node:test";
import assert from "node:assert/strict";

import {
  decodeOuterPacket,
  encodeOuterPacket,
} from "../src/index.js";

test("OuterPacket encode/decode roundtrip carries only body bytes", () => {
  const bodyBytes = new Uint8Array([10, 20, 30, 40, 50]);
  const packet = encodeOuterPacket({ bodyBytes });
  const decoded = decodeOuterPacket(packet);

  assert.equal(decoded.version, 2);
  assert.equal(decoded.bodyOffset, 1);
  assert.deepEqual(Array.from(decoded.bodyBytesView), [10, 20, 30, 40, 50]);
  assert.equal(Object.hasOwn(decoded, "routingKey"), false);
  assert.equal(Object.hasOwn(decoded, "routingKeyBytes16"), false);
});

test("OuterPacket decode rejects invalid version", () => {
  const packet = encodeOuterPacket({ bodyBytes: new Uint8Array([1]) });
  packet[0] = 0x01;
  assert.throws(() => decodeOuterPacket(packet), /invalid version/);
});

test("OuterPacket decode rejects truncated packets", () => {
  assert.throws(() => decodeOuterPacket(new Uint8Array([])), /too short/);
});

test("OuterPacket decode bodyBytesView shares backing memory", () => {
  const packet = encodeOuterPacket({
    bodyBytes: new Uint8Array([1, 2, 3]),
  });
  const decoded = decodeOuterPacket(packet);
  packet[decoded.bodyOffset] = 44;
  assert.equal(decoded.bodyBytesView[0], 44);
});
