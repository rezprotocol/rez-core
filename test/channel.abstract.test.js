import test from "node:test";
import assert from "node:assert/strict";

import { RChannel } from "../src/channel/RChannel.js";

test("RChannel — type is set", () => {
  const ch = new RChannel();
  assert.equal(ch.type, "RChannel");
});

test("RChannel — all methods are abstract", () => {
  const ch = new RChannel();
  const methods = ["open", "close", "send", "onData", "onClose"];

  for (const m of methods) {
    assert.throws(
      () => ch[m]("id"),
      (err) => err.name === "RezAbstractError" && err.message.includes(m),
      `${m}() should throw RezAbstractError`
    );
  }
});
