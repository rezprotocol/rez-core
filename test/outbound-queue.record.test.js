import test from "node:test";
import assert from "node:assert/strict";
import { RRecord, OutboundQueueEntryV1 } from "../src/node.js";

function entry(innerBytes = new Uint8Array([1, 2, 3]), attempts = 0) {
  return new OutboundQueueEntryV1({ queueId: "q1", deliverInboxId: "inbox:test", innerBytes,
    createdAtMs: 1000, attempts, lastAttemptMs: 0, nextRetryMs: 1000 });
}

test("outbound queue entries are sealed RRecords and preserve the existing persisted schema", () => {
  const record = entry();
  assert.ok(record instanceof RRecord);
  record._assertSealed();
  assert.ok(Object.isFrozen(record));
  assert.deepEqual(record.toJSON(), { queueId: "q1", deliverInboxId: "inbox:test", innerBytesB64: "AQID",
    createdAtMs: 1000, attempts: 0, lastAttemptMs: 0, nextRetryMs: 1000,
    receiptInboxId: null, ownerPublicKeyB64: null });
  assert.deepEqual(OutboundQueueEntryV1.fromJSON(record.toJSON()).toJSON(), record.toJSON());
});

test("queued ciphertext cannot be modified through input or output byte aliases", () => {
  const bytes = new Uint8Array([1, 2, 3]);
  const record = entry(bytes);
  bytes[0] = 99;
  record.innerBytes[1] = 99;
  assert.deepEqual(record.innerBytes, new Uint8Array([1, 2, 3]));
});

test("queue records reject non-finite, fractional and negative attempt state", () => {
  for (const attempts of [NaN, Infinity, -1, 0.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => entry(new Uint8Array([1]), attempts));
  }
});
