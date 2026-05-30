import test from "node:test";
import assert from "node:assert/strict";
import { Header } from "../src/objects/Header.js";
import { Envelope } from "../src/objects/Envelope.js";
import { MemoryStorageProvider } from "../src/storage/memory/MemoryStorageProvider.js";
import { createDefaultCodecChain } from "../src/services/defaults.js";
import { RezRuntime } from "../src/services/RezRuntime.js";

function makeEnvelope(id) {
  const header = new Header({ id, type: "message", createdAt: 1 });
  return new Envelope({ header, body: { ok: true } });
}

test("RezRuntime save/load envelope", () => {
  const runtime = new RezRuntime({
    codecChain: createDefaultCodecChain(),
    storageProvider: new MemoryStorageProvider(),
  });

  const envelope = makeEnvelope("env-2");
  const id = runtime.saveEnvelope(envelope);
  const loaded = runtime.loadEnvelope(id);

  assert.deepEqual(loaded?.toJSON(), envelope.toJSON());
});

test("RezRuntime mailbox deposit/list", () => {
  const runtime = new RezRuntime({
    codecChain: createDefaultCodecChain(),
    storageProvider: new MemoryStorageProvider(),
  });

  const envelope = makeEnvelope("env-3");
  const id = runtime.saveEnvelope(envelope);

  runtime.depositToMailbox("mb-1", id);
  runtime.depositToMailbox("mb-1", id);

  assert.deepEqual(runtime.listMailbox("mb-1"), [id, id]);
});
