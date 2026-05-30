import test from "node:test";
import assert from "node:assert/strict";
import { MemoryStorageProvider } from "../src/storage/memory/MemoryStorageProvider.js";
import { createDefaultCodecChain } from "../src/services/defaults.js";
import { RezRuntime } from "../src/services/RezRuntime.js";

function makeRuntime() {
  return new RezRuntime({
    codecChain: createDefaultCodecChain(),
    storageProvider: new MemoryStorageProvider(),
  });
}

test("RezRuntime validation", () => {
  const runtime = makeRuntime();

  assert.throws(() => runtime.encodeEnvelope({}), /Envelope/);
  assert.throws(() => runtime.decodeEnvelope("nope"), /Uint8Array/);
  assert.throws(() => runtime.loadEnvelope(""), /non-empty/);
  assert.throws(() => runtime.depositToMailbox("", "id"), /mailboxId/);
  assert.throws(() => runtime.depositToMailbox("mb", ""), /envelopeId/);
  assert.throws(() => runtime.listMailbox(""), /non-empty/);
});
