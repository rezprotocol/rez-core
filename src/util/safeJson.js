/**
 * Untrusted-JSON hardening — ONE rule, applied at every boundary that turns
 * bytes from a remote party into JavaScript objects (CORE-2 / SDK-1).
 *
 * `JSON.parse` is not itself the danger: it creates `__proto__` as an ordinary
 * own data property rather than walking the setter. The danger is the NEXT
 * step. `Object.assign(target, parsed)` and `{ ...parsed }` copy by [[Set]],
 * which DOES walk `Object.prototype.__proto__`'s setter — so the copy silently
 * inherits from whatever the peer sent:
 *
 *     const parsed = JSON.parse('{"__proto__":{"isAdmin":true}}');
 *     const copy = Object.assign({}, parsed);
 *     copy.isAdmin;                       // true — inherited from the payload
 *
 * That is one merge away from any parsed payload, which is why the check
 * belongs at the parse boundary rather than in each consumer.
 *
 * REJECT, never strip. Nothing in this protocol legitimately sends `__proto__`,
 * `constructor`, or `prototype`, so a payload carrying one is not a payload
 * with a stray field. Quietly dropping it would hand the caller a value that
 * differs from what the peer actually sent, with nothing recording the
 * difference — the caller would validate a payload that never existed.
 *
 * Scope: JSON data (objects, arrays, primitives). Not for class instances,
 * typed arrays, or Dates.
 */

export const UNSAFE_JSON_KEY = "UNSAFE_JSON_KEY";

const DANGEROUS_KEYS = Object.freeze(["__proto__", "constructor", "prototype"]);

export function isDangerousJsonKey(key) {
  return DANGEROUS_KEYS.includes(key);
}

/**
 * Throw if `value` contains a prototype-poisoning key anywhere in its tree.
 *
 * Iterative with an explicit stack, not recursive: the input is attacker-shaped,
 * and a recursive walk would turn a deeply nested payload into a stack overflow
 * — trading one denial of service for another. A `WeakSet` guards cycles, which
 * `JSON.parse` output cannot contain but a caller-supplied object can.
 *
 * Own NON-enumerable keys are checked too (`getOwnPropertyNames`, not `keys`):
 * a hand-built object can hide one from `Object.keys` while `Object.assign`
 * skips it — but a later `getOwnPropertyDescriptors` copy would not.
 *
 * @param {*} value parsed JSON data
 * @param {string} label what to call the root in the error path
 * @returns {*} the same value, unchanged, when it is safe
 */
export function assertSafeJsonKeys(value, label = "value") {
  const seen = new WeakSet();
  const stack = [{ node: value, path: label }];
  while (stack.length > 0) {
    const current = stack.pop();
    const node = current.node;
    if (node === null || typeof node !== "object") continue;
    if (seen.has(node)) continue;
    seen.add(node);

    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i += 1) {
        stack.push({ node: node[i], path: current.path + "[" + i + "]" });
      }
      continue;
    }

    for (const key of Object.getOwnPropertyNames(node)) {
      if (isDangerousJsonKey(key)) {
        const err = new Error(
          "unsafe JSON key '" + key + "' at " + current.path
          + " — refusing a payload that can poison object prototypes",
        );
        err.code = UNSAFE_JSON_KEY;
        err.key = key;
        err.path = current.path;
        throw err;
      }
      const descriptor = Object.getOwnPropertyDescriptor(node, key);
      // Getter-only properties are not read: invoking attacker-supplied code to
      // inspect it would be the very thing this guard exists to prevent.
      if (descriptor && "value" in descriptor) {
        stack.push({ node: descriptor.value, path: current.path + "." + key });
      }
    }
  }
  return value;
}

/**
 * `JSON.parse` for untrusted bytes: parses, then refuses the result if it
 * carries a prototype-poisoning key. Parse failures surface as the SyntaxError
 * `JSON.parse` threw; unsafe keys surface with `code === UNSAFE_JSON_KEY`, so a
 * caller can tell "not JSON" from "hostile JSON".
 *
 * @param {string} text
 * @param {string} label what to call the root in the error path
 */
export function parseUntrustedJson(text, label = "json") {
  return assertSafeJsonKeys(JSON.parse(text), label);
}
