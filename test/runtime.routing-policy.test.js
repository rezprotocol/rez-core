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

test("DefaultRoutingPolicy mirrors routing table", () => {
  const policy = new DefaultRoutingPolicy();

  assert.deepEqual(
    policy.decide({ bytes: new Uint8Array([1]), to: "A" }, { disposition: "LOCAL" }),
    { disposition: "LOCAL", nextHop: null }
  );

  assert.deepEqual(
    policy.decide({ bytes: new Uint8Array([1]), to: "B" }, { disposition: "FORWARD", nextHop: "C" }),
    { disposition: "FORWARD", nextHop: "C" }
  );

  assert.deepEqual(
    policy.decide({ bytes: new Uint8Array([1]), to: "X" }, { disposition: "DROP" }),
    { disposition: "DROP", nextHop: null }
  );
});

test("DefaultRoutingPolicy drops oversize", async () => {
  const policy = new DefaultRoutingPolicy({ maxPacketBytes: 2 });
  const routingTable = new SimpleRoutingTable({ localIds: [], routes: new Map(), defaultUpstream: "C" });
  const network = new MemoryNetwork();
  const transportB = new MemoryTransport({ endpointId: "B", network });
  const transportC = new MemoryTransport({ endpointId: "C", network });

  let forwarded = 0;
  transportC.onPacket(() => forwarded++);

  const dispatcher = new ForwardingDispatcher({
    transport: transportB,
    routingTable,
    policy,
    localHandler: () => {},
  });

  transportB.start();
  transportC.start();
  await dispatcher.start();

  const bytes = new Uint8Array([1, 2, 3]);
  dispatcher.handlePacket(makePacket(bytes, "B", "A"));

  assert.equal(forwarded, 0);

  await dispatcher.stop();
  transportB.stop();
  transportC.stop();
});

test("DefaultRoutingPolicy drops invalid to", async () => {
  const policy = new DefaultRoutingPolicy();
  const routingTable = new SimpleRoutingTable({ localIds: [], routes: new Map(), defaultUpstream: "C" });
  const network = new MemoryNetwork();
  const transportB = new MemoryTransport({ endpointId: "B", network });
  const transportC = new MemoryTransport({ endpointId: "C", network });

  let forwarded = 0;
  transportC.onPacket(() => forwarded++);

  const dispatcher = new ForwardingDispatcher({
    transport: transportB,
    routingTable,
    policy,
    localHandler: () => {},
  });

  transportB.start();
  transportC.start();
  await dispatcher.start();

  const badPacket = { bytes: new Uint8Array([1]), to: "" };
  dispatcher.handlePacket(badPacket);

  assert.equal(forwarded, 0);

  await dispatcher.stop();
  transportB.stop();
  transportC.stop();
});
