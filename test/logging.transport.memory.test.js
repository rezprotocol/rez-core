import test from "node:test";
import assert from "node:assert/strict";
import { MemoryLogTransport } from "@rezprotocol/core";
import { RLogger } from "@rezprotocol/core";


test("MemoryLogTransport captures events", () => {
  const transport = new MemoryLogTransport();
  const logger = new RLogger({ transports: [transport] });

  logger.info("hello", { ok: true });
  const events = transport.getEvents();

  assert.equal(events.length, 1);
  assert.equal(events[0].message, "hello");
});

test("MemoryLogTransport returns copy", () => {
  const transport = new MemoryLogTransport();
  const logger = new RLogger({ transports: [transport] });

  logger.info("one");
  const events = transport.getEvents();
  events.push({ message: "mutate" });

  assert.equal(transport.getEvents().length, 1);
});
