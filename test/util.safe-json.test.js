import test from "node:test";
import assert from "node:assert/strict";
import {
  UNSAFE_JSON_KEY,
  isDangerousJsonKey,
  assertSafeJsonKeys,
  parseUntrustedJson,
} from "../src/util/safeJson.js";

// CORE-2 / SDK-1 boundary hardening. These pin the CLAIM, not just the code:
// the reason this guard exists is that a parsed payload is one `Object.assign`
// away from re-parenting whatever it is copied into. The first test proves that
// language behaviour directly, so a future reader can see the guard is load-
// bearing rather than superstition.

test("the hazard is real: Object.assign copies a parsed __proto__ into the target's prototype", () => {
  const parsed = JSON.parse(String.raw`{"__proto__":{"isAdmin":true}}`);
  // Rest/spread is SAFE — it defines rather than sets, so the key survives as
  // an ordinary own property and the prototype is untouched.
  const spread = { ...parsed };
  assert.equal(Object.getPrototypeOf(spread), Object.prototype);
  assert.deepEqual(Object.getOwnPropertyNames(spread), ["__proto__"]);

  // Object.assign is NOT safe — it assigns, which walks the __proto__ setter.
  const assigned = Object.assign({}, parsed);
  assert.notEqual(Object.getPrototypeOf(assigned), Object.prototype);
  assert.equal(assigned.isAdmin, true, "the copy inherited a field the peer chose");

  // Global prototypes are untouched either way: this is per-object contamination,
  // not process-wide pollution. Stating it so the severity is not overstated.
  assert.equal({}.isAdmin, undefined);
});

test("assertSafeJsonKeys rejects each dangerous key and names where it found it", () => {
  for (const key of ["__proto__", "constructor", "prototype"]) {
    assert.equal(isDangerousJsonKey(key), true);
    const value = JSON.parse(`{"a":{"b":{${JSON.stringify(key)}:{}}}}`);
    assert.throws(
      () => assertSafeJsonKeys(value, "root"),
      (err) => {
        assert.equal(err.code, UNSAFE_JSON_KEY);
        assert.equal(err.key, key);
        assert.equal(err.path, "root.a.b", "the error points at the containing object");
        return true;
      },
      key + " must be rejected",
    );
  }
});

test("assertSafeJsonKeys finds dangerous keys nested inside arrays", () => {
  const value = JSON.parse(String.raw`{"items":[{"ok":1},{"__proto__":{"x":1}}]}`);
  assert.throws(() => assertSafeJsonKeys(value, "root"), (err) => {
    assert.equal(err.code, UNSAFE_JSON_KEY);
    assert.equal(err.path, "root.items[1]");
    return true;
  });
});

test("assertSafeJsonKeys returns ordinary data unchanged, including empty and falsy leaves", () => {
  const value = { a: 1, b: [null, 0, "", false], c: { d: {} }, e: null };
  assert.equal(assertSafeJsonKeys(value), value, "returns the same reference, does not clone");
  assert.doesNotThrow(() => assertSafeJsonKeys(null));
  assert.doesNotThrow(() => assertSafeJsonKeys("a string"));
  assert.doesNotThrow(() => assertSafeJsonKeys(7));
});

test("assertSafeJsonKeys terminates on a cyclic caller-supplied object", () => {
  // JSON.parse output cannot cycle, but this function is also called on objects
  // a caller assembled. Without the seen-set this walk would never return.
  const a = { name: "a" };
  a.self = a;
  a.list = [a, { back: a }];
  assert.doesNotThrow(() => assertSafeJsonKeys(a));
});

test("assertSafeJsonKeys catches a NON-enumerable dangerous key", () => {
  // Object.keys would miss this; getOwnPropertyNames does not. A copy made with
  // getOwnPropertyDescriptors would carry it, so missing it is not academic.
  const hidden = {};
  Object.defineProperty(hidden, "__proto__", { value: { x: 1 }, enumerable: false, configurable: true });
  assert.deepEqual(Object.keys(hidden), [], "invisible to Object.keys");
  assert.throws(() => assertSafeJsonKeys(hidden), (err) => err.code === UNSAFE_JSON_KEY);
});

test("assertSafeJsonKeys does not invoke getters while walking", () => {
  // Running attacker-supplied code to inspect a payload would be the very thing
  // this guard exists to prevent.
  let invoked = 0;
  const trap = { get boom() { invoked += 1; return { __proto__: { x: 1 } }; } };
  assert.doesNotThrow(() => assertSafeJsonKeys(trap));
  assert.equal(invoked, 0);
});

test("parseUntrustedJson distinguishes 'not JSON' from 'hostile JSON'", () => {
  assert.deepEqual(parseUntrustedJson('{"ok":1}'), { ok: 1 });

  // Malformed input surfaces as the SyntaxError JSON.parse threw — NOT as an
  // UNSAFE_JSON_KEY. Callers branch on these differently: one is a broken peer,
  // the other is a hostile one.
  assert.throws(() => parseUntrustedJson("{not json"), (err) => {
    assert.equal(err instanceof SyntaxError, true);
    assert.equal(err.code, undefined);
    return true;
  });

  assert.throws(() => parseUntrustedJson(String.raw`{"__proto__":{"x":1}}`), (err) => {
    assert.equal(err.code, UNSAFE_JSON_KEY);
    return true;
  });
});
