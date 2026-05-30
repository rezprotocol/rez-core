import test from "node:test";
import assert from "node:assert/strict";
import { descriptorHasUsableOnionKey, OnionKeyRecordV1 } from "../src/index.js";

test("descriptorHasUsableOnionKey returns false for missing descriptor", () => {
  assert.equal(descriptorHasUsableOnionKey(null, 1000), false);
  assert.equal(descriptorHasUsableOnionKey(undefined, 1000), false);
});

test("descriptorHasUsableOnionKey returns false for missing or empty onionKeys", () => {
  assert.equal(descriptorHasUsableOnionKey({}, 1000), false);
  assert.equal(descriptorHasUsableOnionKey({ onionKeys: [] }, 1000), false);
  assert.equal(descriptorHasUsableOnionKey({ onionKeys: null }, 1000), false);
});

test("descriptorHasUsableOnionKey returns false when nowMs is not finite", () => {
  const descriptor = {
    onionKeys: [
      { notBefore: 0, notAfter: 2000, status: "active" },
    ],
  };
  assert.equal(descriptorHasUsableOnionKey(descriptor, NaN), false);
  assert.equal(descriptorHasUsableOnionKey(descriptor, undefined), false);
});

test("descriptorHasUsableOnionKey returns false when all keys are expired", () => {
  const nowMs = 5000;
  const descriptor = {
    onionKeys: [
      { notBefore: 0, notAfter: 1000, status: "active" },
      { notBefore: 1000, notAfter: 2000, status: "active" },
    ],
  };
  assert.equal(descriptorHasUsableOnionKey(descriptor, nowMs), false);
});

test("descriptorHasUsableOnionKey returns false when all keys are revoked", () => {
  const nowMs = 1500;
  const descriptor = {
    onionKeys: [
      { notBefore: 0, notAfter: 2000, status: "revoked" },
    ],
  };
  assert.equal(descriptorHasUsableOnionKey(descriptor, nowMs), false);
});

test("descriptorHasUsableOnionKey returns true when one key is active and in window", () => {
  const nowMs = 1500;
  const descriptor = {
    onionKeys: [
      { notBefore: 0, notAfter: 1000, status: "active" },
      { notBefore: 1000, notAfter: 2000, status: "active" },
    ],
  };
  assert.equal(descriptorHasUsableOnionKey(descriptor, nowMs), true);
});

test("descriptorHasUsableOnionKey returns true when one key is draining and in window", () => {
  const nowMs = 1500;
  const descriptor = {
    onionKeys: [
      { notBefore: 1000, notAfter: 2000, status: "draining" },
    ],
  };
  assert.equal(descriptorHasUsableOnionKey(descriptor, nowMs), true);
});

test("descriptorHasUsableOnionKey returns false when only usable key is revoked", () => {
  const nowMs = 1500;
  const descriptor = {
    onionKeys: [
      { notBefore: 1000, notAfter: 2000, status: "revoked" },
      { notBefore: 2000, notAfter: 3000, status: "active" },
    ],
  };
  assert.equal(descriptorHasUsableOnionKey(descriptor, nowMs), false);
});

test("descriptorHasUsableOnionKey works with OnionKeyRecordV1 instances", () => {
  const nowMs = 1500;
  const key = new OnionKeyRecordV1({
    onionKeyId: "k1",
    publicKeyBytes: new Uint8Array(32),
    format: "raw",
    createdAt: nowMs - 1000,
    notBefore: 1000,
    notAfter: 2000,
    status: "active",
  });
  const descriptor = { onionKeys: [key] };
  assert.equal(descriptorHasUsableOnionKey(descriptor, nowMs), true);
});

test("descriptorHasUsableOnionKey returns false at exact notAfter", () => {
  const nowMs = 2000;
  const descriptor = {
    onionKeys: [
      { notBefore: 1000, notAfter: 2000, status: "active" },
    ],
  };
  assert.equal(descriptorHasUsableOnionKey(descriptor, nowMs), false);
});

test("descriptorHasUsableOnionKey returns true at notBefore", () => {
  const nowMs = 1000;
  const descriptor = {
    onionKeys: [
      { notBefore: 1000, notAfter: 2000, status: "active" },
    ],
  };
  assert.equal(descriptorHasUsableOnionKey(descriptor, nowMs), true);
});
