import test from "node:test";
import assert from "node:assert/strict";
import { Header } from "../src/objects/Header.js";
import { Envelope } from "../src/objects/Envelope.js";
import { MemoryStorageProvider } from "../src/storage/memory/MemoryStorageProvider.js";
import { createDefaultCodecChain } from "../src/services/defaults.js";
import { RezRuntime } from "../src/services/RezRuntime.js";
import { canonicalize } from "../src/util/canonicalize.js";

function makeEnvelope() {
  const header = new Header({ id: "env-1", type: "message", createdAt: 1 });
  return new Envelope({
    header,
    body: { z: 1, a: { b: 2, a: 1 } },
  });
}

test("RezRuntime encode/decode round-trip", () => {
  const runtime = new RezRuntime({
    codecChain: createDefaultCodecChain(),
    storageProvider: new MemoryStorageProvider(),
  });

  const envelope = makeEnvelope();
  const bytes = runtime.encodeEnvelope(envelope);
  const decoded = runtime.decodeEnvelope(bytes);

  const expected = Envelope.fromJSON(canonicalize(envelope.toJSON()));
  assert.deepEqual(decoded.toJSON(), expected.toJSON());
});
