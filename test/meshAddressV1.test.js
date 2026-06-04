import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  MESH_ADDRESS_KINDS,
  buildInboxAddress,
  buildRendezvousAddress,
  isMeshAddress,
  assertValidMeshAddress,
} from "../src/protocol/meshAddressV1.js";

// A realistic DER-SPKI Ed25519 base64 key contains + / = — must survive trims/checks.
const PUB = "MCowBQYDK2VwAyEA2crNvu+ZeiFMoMNP/imhLa/HIyYg6x96US6AyOqijPg=";

describe("mesh address v1 — kinds", () => {
  it("exposes exactly the two general protocol kinds, frozen", () => {
    assert.equal(MESH_ADDRESS_KINDS.INBOX, "inbox");
    assert.equal(MESH_ADDRESS_KINDS.RENDEZVOUS, "rendezvous");
    assert.ok(Object.isFrozen(MESH_ADDRESS_KINDS));
  });

  it("carries NO app concept — there is no 'contact'/'peerLink' kind", () => {
    assert.equal(MESH_ADDRESS_KINDS.CONTACT, undefined);
    assert.equal(MESH_ADDRESS_KINDS.PEERLINK, undefined);
  });
});

describe("mesh address v1 — inbox (push to a routable queue)", () => {
  it("builds an inbox address from a resolved inboxId", () => {
    const addr = buildInboxAddress({ inboxId: "inbox_abc" });
    assert.deepEqual(addr, { kind: "inbox", inboxId: "inbox_abc" });
  });

  it("trims whitespace on the inboxId", () => {
    const addr = buildInboxAddress({ inboxId: "  inbox_abc  " });
    assert.equal(addr.inboxId, "inbox_abc");
  });

  it("rejects a missing/empty inboxId", () => {
    assert.throws(() => buildInboxAddress({}), /requires inboxId/);
    assert.throws(() => buildInboxAddress({ inboxId: "   " }), /requires inboxId/);
    assert.throws(() => buildInboxAddress(), /requires inboxId/);
  });

  it("carries NO chat concept — only the protocol-level inboxId", () => {
    const addr = buildInboxAddress({ inboxId: "inbox_abc" });
    assert.equal(addr.peerLinkId, undefined);
    assert.equal(addr.peerAccountId, undefined);
    assert.equal(addr.threadId, undefined);
  });
});

describe("mesh address v1 — rendezvous (addressed by coordinate)", () => {
  it("builds a rendezvous address from the durable-record coordinate", () => {
    const addr = buildRendezvousAddress({
      recordKind: "peerlink-invite", recordId: "plinv_abc", publisherPublicKeyB64: PUB,
    });
    assert.deepEqual(addr, {
      kind: "rendezvous",
      recordKind: "peerlink-invite",
      recordId: "plinv_abc",
      publisherPublicKeyB64: PUB,
    });
  });

  it("generalizes across record kinds (a blog post is the same shape)", () => {
    const addr = buildRendezvousAddress({
      recordKind: "blog-post", recordId: "post_42", publisherPublicKeyB64: PUB,
    });
    assert.equal(addr.kind, "rendezvous");
    assert.equal(addr.recordKind, "blog-post");
  });

  it("trims each coordinate field", () => {
    const addr = buildRendezvousAddress({
      recordKind: "  peerlink-invite ", recordId: " plinv_abc ", publisherPublicKeyB64: " " + PUB + " ",
    });
    assert.equal(addr.recordKind, "peerlink-invite");
    assert.equal(addr.recordId, "plinv_abc");
    assert.equal(addr.publisherPublicKeyB64, PUB);
  });

  it("rejects any missing coordinate component", () => {
    assert.throws(() => buildRendezvousAddress({ recordId: "x", publisherPublicKeyB64: PUB }), /requires recordKind/);
    assert.throws(() => buildRendezvousAddress({ recordKind: "k", publisherPublicKeyB64: PUB }), /requires recordId/);
    assert.throws(() => buildRendezvousAddress({ recordKind: "k", recordId: "x" }), /requires publisherPublicKeyB64/);
    assert.throws(() => buildRendezvousAddress(), /requires recordKind/);
  });
});

describe("mesh address v1 — isMeshAddress predicate", () => {
  it("accepts well-formed addresses of both kinds", () => {
    assert.equal(isMeshAddress(buildInboxAddress({ inboxId: "inbox_abc" })), true);
    assert.equal(isMeshAddress(buildRendezvousAddress({
      recordKind: "k", recordId: "x", publisherPublicKeyB64: PUB,
    })), true);
  });

  it("rejects unknown kinds and non-objects", () => {
    assert.equal(isMeshAddress({ kind: "contact", peerLinkId: "p" }), false);
    assert.equal(isMeshAddress({ kind: "inbox" }), false);
    assert.equal(isMeshAddress(null), false);
    assert.equal(isMeshAddress("inbox"), false);
    assert.equal(isMeshAddress(42), false);
    assert.equal(isMeshAddress(undefined), false);
  });

  it("rejects a kind whose required fields are missing or empty", () => {
    assert.equal(isMeshAddress({ kind: "inbox", inboxId: "" }), false);
    assert.equal(isMeshAddress({ kind: "rendezvous", recordKind: "k", recordId: "x" }), false);
    assert.equal(isMeshAddress({ kind: "rendezvous", recordKind: "k", recordId: "x", publisherPublicKeyB64: "  " }), false);
  });
});

describe("mesh address v1 — assertValidMeshAddress", () => {
  it("returns the address on success (guard-and-use in one step)", () => {
    const addr = buildInboxAddress({ inboxId: "inbox_abc" });
    assert.equal(assertValidMeshAddress(addr), addr);
  });

  it("throws a precise reason for a non-object", () => {
    assert.throws(() => assertValidMeshAddress(null), /must be an object/);
    assert.throws(() => assertValidMeshAddress("x"), /must be an object/);
  });

  it("throws naming the bad kind", () => {
    assert.throws(() => assertValidMeshAddress({ kind: "contact" }), /must be 'inbox' or 'rendezvous'/);
  });

  it("throws when a known kind is missing required fields", () => {
    assert.throws(() => assertValidMeshAddress({ kind: "inbox" }), /missing required fields/);
    assert.throws(
      () => assertValidMeshAddress({ kind: "rendezvous", recordKind: "k" }),
      /missing required fields/,
    );
  });
});
