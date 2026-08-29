import test from "node:test";
import assert from "node:assert/strict";
import { DepositPolicyV1 } from "../src/objects/inbox/DepositPolicyV1.js";

// SESSION_AUTH_V5 slice 3: requiresDepositorIdentity() — the pure record-side
// half of the DEPOSITOR_IDENTITY_REQUIRED verdict. BOTH lists count: a
// blocklist needs identity to match against exactly as much as an allowlist
// does. This table exists so nobody later "optimizes" the check into
// allowlists only.

function policy({ blocked = [], allowed = [] } = {}) {
  return new DepositPolicyV1({
    inboxId: "inbox:t",
    policyVersion: 1,
    blockedDepositorPubkeys: blocked,
    allowedDepositorPubkeys: allowed,
    issuedAtMs: 1,
    expiresAtMs: 2,
    claimantPublicKeyB64: "claimant",
    signatureB64: "sig",
  });
}

test("requiresDepositorIdentity truth table — either non-empty list requires identity", () => {
  assert.equal(policy().requiresDepositorIdentity(), false, "no lists ⇒ evaluable without identity");
  assert.equal(policy({ allowed: ["A"] }).requiresDepositorIdentity(), true, "allowlist alone requires identity");
  assert.equal(policy({ blocked: ["A"] }).requiresDepositorIdentity(), true, "blocklist ALONE requires identity too");
  assert.equal(policy({ allowed: ["A"], blocked: ["B"] }).requiresDepositorIdentity(), true);
});

test("the pre-slice-3 fail-open shape is documented: isDepositorBlocked('') is false even under a non-empty allowlist — which is WHY the node must ask requiresDepositorIdentity first", () => {
  const p = policy({ allowed: ["A"] });
  assert.equal(p.isDepositorBlocked(""), false, "the boolean helper cannot express 'cannot evaluate' — the node-side verdict exists for that");
  assert.equal(p.isDepositorBlocked("B"), true, "with identity available, the allowlist evaluates normally");
  assert.equal(p.isDepositorBlocked("A"), false);
});
