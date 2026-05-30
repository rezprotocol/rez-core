import test from "node:test";
import assert from "node:assert/strict";
import { MemoryNetwork } from "../src/network/memory/MemoryNetwork.js";
import { MemoryTransport } from "../src/network/memory/MemoryTransport.js";


test("MemoryTransport send/receive", () => {
  const network = new MemoryNetwork();
  const a = new MemoryTransport({ endpointId: "A", network });
  const b = new MemoryTransport({ endpointId: "B", network });

  a.start();
  b.start();

  const received = [];
  b.onPacket((packet) => received.push(packet));

  const bytes = new Uint8Array([1, 2, 3]);
  a.send({ bytes, to: "B", from: "A" });

  assert.equal(received.length, 1);
  assert.deepEqual(received[0].bytes, bytes);
  assert.equal(received[0].to, "B");
  assert.equal(received[0].from, "A");
});

test("MemoryTransport unsubscribe", () => {
  const network = new MemoryNetwork();
  const a = new MemoryTransport({ endpointId: "A", network });
  const b = new MemoryTransport({ endpointId: "B", network });

  a.start();
  b.start();

  const received = [];
  const unsub = b.onPacket((packet) => received.push(packet));
  unsub();

  a.send({ bytes: new Uint8Array([9]), to: "B" });
  assert.equal(received.length, 0);
});

test("MemoryTransport stop prevents delivery", () => {
  const network = new MemoryNetwork();
  const a = new MemoryTransport({ endpointId: "A", network });
  const b = new MemoryTransport({ endpointId: "B", network });

  a.start();
  b.start();
  b.stop();

  assert.throws(() => {
    a.send({ bytes: new Uint8Array([7]), to: "B" });
  }, (err) => err && err.code === "REZ_UNDELIVERABLE");
});
