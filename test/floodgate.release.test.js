import test from "node:test";
import assert from "node:assert/strict";
import { FloodGate } from "../src/network/FloodGate.js";

// Audit R4 F3-remediation round-8 finding 4: FloodGate kept one token bucket per unique
// connKey forever, so reconnect churn (each session uses a fresh connKey) grew process memory
// unbounded even after every session closed. release(connKey) drops the bucket on close.

test("FloodGate.release drops a connection's bucket so a reconnect gets a fresh one", () => {
  // High global limits so only the per-connection bucket gates; fixed clock so no refill.
  const gate = new FloodGate({ perConnRate: 1, perConnBurst: 2, globalRate: 1e9, globalBurst: 1e9 });
  const key = "conn-1";
  const now = 1000;

  assert.equal(gate.allow(key, now), true);
  assert.equal(gate.allow(key, now), true);
  assert.equal(gate.allow(key, now), false, "per-connection burst is exhausted");

  gate.release(key);

  // A fresh bucket after release ⇒ the old (exhausted) bucket was dropped, not leaked.
  assert.equal(gate.allow(key, now), true, "a released connKey gets a FRESH bucket");
  assert.equal(gate.allow(key, now), true);
  assert.equal(gate.allow(key, now), false, "and the fresh bucket enforces the same limit");
});

test("FloodGate.release of an unknown / empty connKey is a harmless no-op", () => {
  const gate = new FloodGate({ perConnRate: 1, perConnBurst: 1, globalRate: 1e9, globalBurst: 1e9 });
  gate.release("never-seen");
  gate.release("");
  gate.release(null);
  assert.equal(gate.allow("fresh", 1000), true, "still functions after releasing unknown keys");
});
