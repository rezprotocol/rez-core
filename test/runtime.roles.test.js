import test from "node:test";
import assert from "node:assert/strict";
import { RTransport } from "../src/network/RTransport.js";
import { RezRuntime } from "../src/services/RezRuntime.js";
import { createDefaultCodecChain } from "../src/services/defaults.js";
import { MemoryStorageProvider } from "../src/storage/memory/MemoryStorageProvider.js";
import { GatewayRole } from "../src/runtime/roles/GatewayRole.js";
import { RelayRole } from "../src/runtime/roles/RelayRole.js";

class TestTransport extends RTransport {
  constructor(order) {
    super();
    this.order = order;
  }

  start() {
    this.order.push("transport:start");
  }

  stop() {
    this.order.push("transport:stop");
  }
}

class TestRuntime extends RezRuntime {
  constructor(order) {
    super({
      codecChain: createDefaultCodecChain(),
      storageProvider: new MemoryStorageProvider(),
    });
    this.order = order;
  }

  async start() {
    this.order.push("runtime:start");
    await super.start();
  }

  async stop() {
    this.order.push("runtime:stop");
    await super.stop();
  }
}

function makeRole(RoleClass, id) {
  const order = [];
  const transport = new TestTransport(order);
  const runtime = new TestRuntime(order);
  return { order, role: new RoleClass({ id, transport, runtime }) };
}

test("GatewayRole construction validation", () => {
  const order = [];
  const transport = new TestTransport(order);
  const runtime = new TestRuntime(order);

  assert.doesNotThrow(() => new GatewayRole({ id: "gw1", transport, runtime }));
  assert.throws(() => new GatewayRole({ transport, runtime }), /id/);
  assert.throws(() => new GatewayRole({ id: "gw1", runtime }), /transport/);
  assert.throws(() => new GatewayRole({ id: "gw1", transport }), /runtime/);
});

test("GatewayRole lifecycle order", async () => {
  const { order, role } = makeRole(GatewayRole, "gw1");

  await role.start();
  await role.stop();

  assert.deepEqual(order, [
    "transport:start",
    "runtime:start",
    "runtime:stop",
    "transport:stop",
  ]);
});

test("RelayRole construction validation", () => {
  const order = [];
  const transport = new TestTransport(order);
  const runtime = new TestRuntime(order);

  assert.doesNotThrow(() => new RelayRole({ id: "r1", transport, runtime }));
  assert.throws(() => new RelayRole({ transport, runtime }), /id/);
  assert.throws(() => new RelayRole({ id: "r1", runtime }), /transport/);
  assert.throws(() => new RelayRole({ id: "r1", transport }), /runtime/);
});

test("RelayRole lifecycle order", async () => {
  const { order, role } = makeRole(RelayRole, "r1");

  await role.start();
  await role.stop();

  assert.deepEqual(order, [
    "transport:start",
    "runtime:start",
    "runtime:stop",
    "transport:stop",
  ]);
});
