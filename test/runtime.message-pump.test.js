import test from "node:test";
import assert from "node:assert/strict";
import { MemoryNetwork } from "../src/network/memory/MemoryNetwork.js";
import { MemoryTransport } from "../src/network/memory/MemoryTransport.js";
import { WirePacket } from "../src/network/WirePacket.js";
import { Header } from "../src/objects/Header.js";
import { Envelope } from "../src/objects/Envelope.js";
import { createDefaultCodecChain } from "../src/services/defaults.js";
import { MemoryStorageProvider } from "../src/storage/memory/MemoryStorageProvider.js";
import { RezRuntime } from "../src/services/RezRuntime.js";
import { InboxDispatcher } from "../src/services/InboxDispatcher.js";
import { canonicalize } from "../src/util/canonicalize.js";

function makeRuntime() {
  return new RezRuntime({
    codecChain: createDefaultCodecChain(),
    storageProvider: new MemoryStorageProvider(),
  });
}

test("InboxDispatcher processes packets with mailbox deposit", async () => {
  const network = new MemoryNetwork();
  const transportA = new MemoryTransport({ endpointId: "A", network });
  const transportB = new MemoryTransport({ endpointId: "B", network });

  const runtime = makeRuntime();
  const dispatcher = new InboxDispatcher({ transport: transportB, runtime });

  transportA.start();
  transportB.start();
  await dispatcher.start();

  const header = new Header({ id: "m1", type: "message", createdAt: 1 });
  const envelope = new Envelope({ header, body: { z: 1, a: 2 } });
  const bytes = runtime.encodeEnvelope(envelope);

  const packet = new WirePacket({
    bytes,
    to: "B",
    from: "A",
    meta: { depositMailboxId: "mb1" },
  });

  const originalReceive = runtime.receivePacket.bind(runtime);
  const delivered = new Promise((resolve) => {
    runtime.receivePacket = async (pkt) => {
      const result = await originalReceive(pkt);
      resolve(result);
      return result;
    };
  });

  transportA.send(packet);
  await delivered;
  runtime.receivePacket = originalReceive;

  const loaded = runtime.loadEnvelope("m1");
  const expected = Envelope.fromJSON(canonicalize(envelope.toJSON()));
  assert.deepEqual(loaded?.toJSON(), expected.toJSON());

  const items = runtime.listMailbox("mb1");
  assert.deepEqual(items, ["m1"]);

  await dispatcher.stop();
  transportA.stop();
  transportB.stop();
});

test("InboxDispatcher rejects invalid packet bytes", async () => {
  const network = new MemoryNetwork();
  const transportA = new MemoryTransport({ endpointId: "A", network });
  const transportB = new MemoryTransport({ endpointId: "B", network });
  const runtime = makeRuntime();
  const dispatcher = new InboxDispatcher({ transport: transportB, runtime });

  transportA.start();
  transportB.start();
  await dispatcher.start();

  assert.throws(() => {
    transportA.send({ bytes: "nope", to: "B" });
  }, /bytes/);

  await dispatcher.stop();
  transportA.stop();
  transportB.stop();
});

test("receivePacket without mailbox does not deposit", async () => {
  const network = new MemoryNetwork();
  const transportA = new MemoryTransport({ endpointId: "A", network });
  const transportB = new MemoryTransport({ endpointId: "B", network });

  const runtime = makeRuntime();
  const dispatcher = new InboxDispatcher({ transport: transportB, runtime });

  transportA.start();
  transportB.start();
  await dispatcher.start();

  const header = new Header({ id: "m2", type: "message", createdAt: 1 });
  const envelope = new Envelope({ header, body: { hello: "world" } });
  const bytes = runtime.encodeEnvelope(envelope);

  const packet = new WirePacket({ bytes, to: "B", from: "A" });
  const originalReceive = runtime.receivePacket.bind(runtime);
  const delivered = new Promise((resolve) => {
    runtime.receivePacket = async (pkt) => {
      const result = await originalReceive(pkt);
      resolve(result);
      return result;
    };
  });

  transportA.send(packet);
  await delivered;
  runtime.receivePacket = originalReceive;

  const loaded = runtime.loadEnvelope("m2");
  assert.ok(loaded);
  assert.deepEqual(runtime.listMailbox("mb1"), []);

  await dispatcher.stop();
  transportA.stop();
  transportB.stop();
});
