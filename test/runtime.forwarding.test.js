import test from "node:test";
import assert from "node:assert/strict";
import { MemoryNetwork } from "../src/network/memory/MemoryNetwork.js";
import { MemoryTransport } from "../src/network/memory/MemoryTransport.js";
import { WirePacket } from "../src/network/WirePacket.js";
import { SimpleRoutingTable } from "../src/runtime/routing/SimpleRoutingTable.js";
import { DefaultRoutingPolicy } from "../src/runtime/policy/DefaultRoutingPolicy.js";
import { ForwardingDispatcher } from "../src/services/ForwardingDispatcher.js";

function makePacket(bytes, to, from, meta) {
  return new WirePacket({ bytes, to, from, meta });
}

test("ForwardingDispatcher LOCAL delivery", async () => {
  const network = new MemoryNetwork();
  const transportA = new MemoryTransport({ endpointId: "A", network });
  const transportB = new MemoryTransport({ endpointId: "B", network });

  const routingTable = new SimpleRoutingTable({ localIds: ["B"], routes: new Map() });
  const policy = new DefaultRoutingPolicy();
  let localCalls = 0;
  const dispatcher = new ForwardingDispatcher({
    transport: transportB,
    routingTable,
    policy,
    localHandler: () => { localCalls += 1; },
  });

  transportA.start();
  transportB.start();
  await dispatcher.start();

  const bytes = new Uint8Array([1, 2, 3]);
  transportA.send(makePacket(bytes, "B", "A"));

  assert.equal(localCalls, 1);

  await dispatcher.stop();
  transportA.stop();
  transportB.stop();
});

test("ForwardingDispatcher FORWARD to upstream", async () => {
  const network = new MemoryNetwork();
  const transportA = new MemoryTransport({ endpointId: "A", network });
  const transportB = new MemoryTransport({ endpointId: "B", network });
  const transportC = new MemoryTransport({ endpointId: "C", network });

  const routingTable = new SimpleRoutingTable({
    localIds: [],
    routes: new Map(),
    defaultUpstream: "C",
  });
  const policy = new DefaultRoutingPolicy();

  const received = [];
  transportC.onPacket((packet) => received.push(packet));

  const dispatcher = new ForwardingDispatcher({
    transport: transportB,
    routingTable,
    policy,
    localHandler: () => {},
  });

  transportA.start();
  transportB.start();
  transportC.start();
  await dispatcher.start();

  const bytes = new Uint8Array([9, 9, 9]);
  transportA.send(makePacket(bytes, "B", "A"));

  assert.equal(received.length, 1);
  assert.deepEqual(received[0].bytes, bytes);
  assert.equal(received[0].to, "C");
  assert.equal(received[0].meta.finalTo, "B");

  await dispatcher.stop();
  transportA.stop();
  transportB.stop();
  transportC.stop();
});

test("ForwardingDispatcher DROP", async () => {
  const network = new MemoryNetwork();
  const transportA = new MemoryTransport({ endpointId: "A", network });
  const transportB = new MemoryTransport({ endpointId: "B", network });

  const routingTable = new SimpleRoutingTable({ localIds: [], routes: new Map() });
  const policy = new DefaultRoutingPolicy();
  let localCalls = 0;
  const dispatcher = new ForwardingDispatcher({
    transport: transportB,
    routingTable,
    policy,
    localHandler: () => { localCalls += 1; },
  });

  transportA.start();
  transportB.start();
  await dispatcher.start();

  const bytes = new Uint8Array([4]);
  transportA.send(makePacket(bytes, "B", "A"));

  assert.equal(localCalls, 0);

  await dispatcher.stop();
  transportA.stop();
  transportB.stop();
});
