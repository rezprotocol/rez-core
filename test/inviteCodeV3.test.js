import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  encodeInviteCodeV3,
  parseInviteCodeV3,
  isInviteCodeV3,
  PEERLINK_INVITE_RECORD_KIND,
} from "../src/protocol/inviteCodeV3.js";

describe("invite code v3", () => {
  it("round-trips inviteId + publisherPublicKeyB64", () => {
    // A realistic DER-SPKI Ed25519 base64 key contains + / = — must survive.
    const pub = "MCowBQYDK2VwAyEA2crNvu+ZeiFMoMNP/imhLa/HIyYg6x96US6AyOqijPg=";
    const code = encodeInviteCodeV3({ inviteId: "plinv_abc123", publisherPublicKeyB64: pub });
    assert.ok(code.startsWith("rez:inv:v3:"));
    const parsed = parseInviteCodeV3(code);
    assert.equal(parsed.inviteId, "plinv_abc123");
    assert.equal(parsed.publisherPublicKeyB64, pub);
  });

  it("isInviteCodeV3 discriminates v3 from v2", () => {
    assert.equal(isInviteCodeV3("rez:inv:v3:a.b"), true);
    assert.equal(isInviteCodeV3("rez:inv:v2:a.b"), false);
    assert.equal(isInviteCodeV3("nonsense"), false);
    assert.equal(isInviteCodeV3(42), false);
  });

  it("rejects malformed codes", () => {
    assert.throws(() => parseInviteCodeV3("rez:inv:v2:a.b"), /prefix invalid/);
    assert.throws(() => parseInviteCodeV3("rez:inv:v3:nodot"), /malformed/);
    assert.throws(() => parseInviteCodeV3("rez:inv:v3:.onlypub"), /malformed/);
    assert.throws(() => parseInviteCodeV3("rez:inv:v3:onlyid."), /malformed/);
  });

  it("rejects encode with missing fields or a dotted inviteId", () => {
    assert.throws(() => encodeInviteCodeV3({ publisherPublicKeyB64: "k" }), /inviteId/);
    assert.throws(() => encodeInviteCodeV3({ inviteId: "x" }), /publisherPublicKeyB64/);
    assert.throws(() => encodeInviteCodeV3({ inviteId: "a.b", publisherPublicKeyB64: "k" }), /must not contain/);
  });

  it("exposes the durable-record kind constant", () => {
    assert.equal(PEERLINK_INVITE_RECORD_KIND, "peerlink-invite");
  });
});
