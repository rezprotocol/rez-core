import test from "node:test";
import assert from "node:assert/strict";
import { ProfilePayloadV1 } from "../src/objects/profile/ProfilePayloadV1.js";

test("ProfilePayloadV1 constructor validates displayName", () => {
  assert.throws(() => new ProfilePayloadV1({ displayName: "", updatedAtMs: 1000 }), /non-empty/);
  assert.throws(() => new ProfilePayloadV1({ displayName: 42, updatedAtMs: 1000 }), /non-empty/);
  assert.throws(() => new ProfilePayloadV1({ displayName: null, updatedAtMs: 1000 }), /non-empty/);
});

test("ProfilePayloadV1 constructor validates updatedAtMs", () => {
  assert.throws(() => new ProfilePayloadV1({ displayName: "Alice", updatedAtMs: -1 }), /positive/);
  assert.throws(() => new ProfilePayloadV1({ displayName: "Alice", updatedAtMs: 0 }), /positive/);
  assert.throws(() => new ProfilePayloadV1({ displayName: "Alice", updatedAtMs: "abc" }), /positive/);
});

test("ProfilePayloadV1 enforces max displayName length", () => {
  const longName = "x".repeat(65);
  assert.throws(() => new ProfilePayloadV1({ displayName: longName, updatedAtMs: 1000 }), /64 chars/);
  assert.doesNotThrow(() => new ProfilePayloadV1({ displayName: "x".repeat(64), updatedAtMs: 1000 }));
});

test("ProfilePayloadV1 round-trip via toJSON/fromJSON", () => {
  const payload = new ProfilePayloadV1({ displayName: "Alice", updatedAtMs: 1710900000000 });
  const json = payload.toJSON();
  assert.equal(json.kind, "rez.profile.v1");
  assert.equal(json.displayName, "Alice");
  assert.equal(json.updatedAtMs, 1710900000000);

  const restored = ProfilePayloadV1.fromJSON(json);
  assert.equal(restored.kind, "rez.profile.v1");
  assert.equal(restored.displayName, "Alice");
  assert.equal(restored.updatedAtMs, 1710900000000);
});

test("ProfilePayloadV1 round-trip via toBytes/fromBytes", () => {
  const payload = new ProfilePayloadV1({ displayName: "Bob", updatedAtMs: 5000 });
  const bytes = payload.toBytes();
  assert.ok(bytes instanceof Uint8Array);
  const restored = ProfilePayloadV1.fromBytes(bytes);
  assert.equal(restored.displayName, "Bob");
  assert.equal(restored.updatedAtMs, 5000);
  assert.equal(restored.kind, "rez.profile.v1");
});

test("ProfilePayloadV1 preserves extras on round-trip", () => {
  const hash = "a".repeat(64);
  const payload = new ProfilePayloadV1({
    displayName: "Carol",
    updatedAtMs: 7000,
    avatarFileHash: hash,
    statusText: "Online",
  });
  assert.equal(payload.avatarFileHash, hash);
  assert.equal(payload.extras.statusText, "Online");
  assert.equal(payload.extras.avatarFileHash, undefined);

  const json = payload.toJSON();
  assert.equal(json.avatarFileHash, hash);
  assert.equal(json.statusText, "Online");

  const restored = ProfilePayloadV1.fromJSON(json);
  assert.equal(restored.avatarFileHash, hash);
  assert.equal(restored.extras.statusText, "Online");
  assert.equal(restored.displayName, "Carol");
});

test("ProfilePayloadV1 avatarFileHash defaults to empty string when omitted", () => {
  const payload = new ProfilePayloadV1({ displayName: "Alice", updatedAtMs: 1000 });
  assert.equal(payload.avatarFileHash, "");
  const json = payload.toJSON();
  assert.equal(json.avatarFileHash, undefined);
});

test("ProfilePayloadV1 rejects non-hex avatarFileHash", () => {
  assert.throws(
    () => new ProfilePayloadV1({ displayName: "Alice", updatedAtMs: 1000, avatarFileHash: "not-a-hash" }),
    /64-char hex/,
  );
});

test("ProfilePayloadV1 rejects wrong-length hex avatarFileHash", () => {
  assert.throws(
    () => new ProfilePayloadV1({ displayName: "Alice", updatedAtMs: 1000, avatarFileHash: "abcdef" }),
    /64-char hex/,
  );
});

test("ProfilePayloadV1 rejects non-string avatarFileHash", () => {
  assert.throws(
    () => new ProfilePayloadV1({ displayName: "Alice", updatedAtMs: 1000, avatarFileHash: 42 }),
    /must be a string/,
  );
});

test("ProfilePayloadV1 accepts valid 64-char hex avatarFileHash", () => {
  const hash = "abcdef0123456789".repeat(4);
  const payload = new ProfilePayloadV1({ displayName: "Alice", updatedAtMs: 1000, avatarFileHash: hash });
  assert.equal(payload.avatarFileHash, hash);
});

test("ProfilePayloadV1 trims displayName", () => {
  const payload = new ProfilePayloadV1({ displayName: "  Alice  ", updatedAtMs: 1000 });
  assert.equal(payload.displayName, "Alice");
});

test("ProfilePayloadV1.fromJSON rejects non-object", () => {
  assert.throws(() => ProfilePayloadV1.fromJSON(null), /requires object/);
  assert.throws(() => ProfilePayloadV1.fromJSON("string"), /requires object/);
});

// --- CORE-2: prototype-poisoning at the profile boundary -------------------
// A profile is untrusted (any peer that can reach us can send one) AND
// deliberately preserves unknown fields for forward compatibility. Those two
// facts together are what made this reachable rather than theoretical.

test("CORE-2: fromBytes refuses a profile carrying __proto__", () => {
  const hostile = String.raw`{"kind":"rez.profile.v1","displayName":"Mallory","updatedAtMs":1710900000000,"__proto__":{"isAdmin":true}}`;
  const bytes = new TextEncoder().encode(hostile);
  assert.throws(() => ProfilePayloadV1.fromBytes(bytes), (err) => {
    assert.equal(err.code, "UNSAFE_JSON_KEY");
    assert.equal(err.key, "__proto__");
    return true;
  });
});

test("CORE-2: fromJSON and the constructor refuse constructor/prototype extras too", () => {
  for (const key of ["__proto__", "constructor", "prototype"]) {
    const json = JSON.parse(
      `{"kind":"rez.profile.v1","displayName":"Mallory","updatedAtMs":1710900000000,${JSON.stringify(key)}:{"x":1}}`,
    );
    assert.throws(() => ProfilePayloadV1.fromJSON(json), (err) => err.code === "UNSAFE_JSON_KEY", key);

    // And directly through the constructor, which is a separate entry point:
    // fromJSON is not the only way in.
    const direct = JSON.parse(`{"displayName":"Mallory","updatedAtMs":1710900000000,${JSON.stringify(key)}:{"x":1}}`);
    assert.throws(() => new ProfilePayloadV1(direct), (err) => err.code === "UNSAFE_JSON_KEY", key);
  }
});

test("CORE-2: extras carry no prototype, so nothing is inherited from a payload", () => {
  const payload = new ProfilePayloadV1({ displayName: "Alice", updatedAtMs: 1000, nickname: "Al", theme: "dark" });
  assert.equal(Object.getPrototypeOf(payload.extras), null);
  assert.equal(payload.extras.nickname, "Al");
  // The whole point of the null prototype: a merge of extras cannot pick up an
  // inherited surprise, whatever route a future edit takes to build it.
  assert.equal(Object.getPrototypeOf(Object.assign({}, payload.extras)), Object.prototype);
});

test("CORE-2: ordinary forward-compatible extras still round-trip untouched", () => {
  // The guard must reject hostile keys WITHOUT narrowing the forward-compat
  // contract that made extras exist in the first place.
  const json = {
    kind: "rez.profile.v1",
    displayName: "Alice",
    updatedAtMs: 1710900000000,
    pronouns: "they/them",
    links: [{ label: "site", url: "https://example.test" }],
  };
  const round = ProfilePayloadV1.fromJSON(json).toJSON();
  assert.equal(round.pronouns, "they/them");
  assert.deepEqual(round.links, [{ label: "site", url: "https://example.test" }]);
  assert.equal(round.displayName, "Alice");
});
