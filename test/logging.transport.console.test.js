import test from "node:test";
import assert from "node:assert/strict";
import { ConsoleLogTransport } from "@rezprotocol/core";
import { RLogger } from "@rezprotocol/core";


test("ConsoleLogTransport routes by level", () => {
  const calls = { debug: 0, info: 0, warn: 0, error: 0, log: 0 };
  const fakeConsole = {
    debug() { calls.debug += 1; },
    info() { calls.info += 1; },
    warn() { calls.warn += 1; },
    error() { calls.error += 1; },
    log() { calls.log += 1; },
  };

  const transport = new ConsoleLogTransport(fakeConsole);
  const logger = new RLogger({ transports: [transport] });

  logger.debug("d");
  logger.info("i");
  logger.warn("w");
  logger.error("e");

  assert.equal(calls.debug, 1);
  assert.equal(calls.info, 1);
  assert.equal(calls.warn, 1);
  assert.equal(calls.error, 1);
  assert.equal(calls.log, 0);
});

test("ConsoleLogTransport does not throw without level method", () => {
  const calls = { log: 0 };
  const fakeConsole = {
    log() { calls.log += 1; },
  };

  const transport = new ConsoleLogTransport(fakeConsole);
  const logger = new RLogger({ transports: [transport] });

  logger.info("hello");
  assert.equal(calls.log, 1);
});
