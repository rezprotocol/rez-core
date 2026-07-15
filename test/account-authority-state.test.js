import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  AccountAuthorityStateV1,
  ACCOUNT_AUTHORITY_STATE_PURPOSE,
} from "../src/objects/device/index.js";

// S2.5 S11 L3 — the F4 authority-state record. Its {revokedCertIds,
// minValidIssuedAtMs} projection is the revocationState param shape end to end;
// revokedCertIds is sorted+deduped so equal state serializes identically.

const NOW = 1_000_000;

function genKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const spki = new Uint8Array(publicKey.export({ format: "der", type: "spki" }));
  return { publicKeyB64: Buffer.from(spki).toString("base64"), privateKey };
}
function sign(privateKey, bytes) {
  return { alg: "ed25519", sigB64: Buffer.from(crypto.sign(null, Buffer.from(bytes), privateKey)).toString("base64") };
}
function verify(publicKeyB64, bytes, sig) {
  const keyObj = crypto.createPublicKey({ key: Buffer.from(publicKeyB64, "base64"), format: "der", type: "spki" });
  return crypto.verify(null, Buffer.from(bytes), keyObj, Buffer.from(sig.sigB64, "base64"));
}
const cap = (h) => "rez:cap:" + String(h).padEnd(64, "0");

function make({ account, signer, epoch = 1, revokedCertIds = [], minValidIssuedAtMs = 0, overrides = {} } = {}) {
  const body = {
    v: 1,
    purpose: ACCOUNT_AUTHORITY_STATE_PURPOSE,
    accountIdentityPublicKeyB64: account.publicKeyB64,
    epoch,
    revokedCertIds,
    minValidIssuedAtMs,
    issuedAtMs: NOW,
    signerPublicKeyB64: signer.publicKeyB64,
    ...overrides,
  };
  const sig = sign(signer.privateKey, AccountAuthorityStateV1.signableBytes(body));
  return new AccountAuthorityStateV1({ ...body, sig });
}

test("constructs, verifies, round-trips; empty state is valid", () => {
  const account = genKey();
  const rec = make({ account, signer: account, epoch: 0, revokedCertIds: [], minValidIssuedAtMs: 0 });
  assert.ok(verify(account.publicKeyB64, AccountAuthorityStateV1.signableBytes(rec.toJSON()), rec.sig));
  const back = AccountAuthorityStateV1.fromJSON(rec.toJSON());
  assert.equal(back.epoch, 0);
  assert.deepEqual(back.revokedCertIds, []);
  assert.deepEqual(back.toRevocationState(), { revokedCertIds: [], minValidIssuedAtMs: 0 });
});

test("revokedCertIds are sorted + deduped so equal state signs identically", () => {
  const account = genKey();
  const a = make({ account, signer: account, epoch: 3, revokedCertIds: [cap("bbb"), cap("aaa"), cap("bbb")] });
  const b = make({ account, signer: account, epoch: 3, revokedCertIds: [cap("aaa"), cap("bbb")] });
  assert.deepEqual(a.revokedCertIds, [cap("aaa"), cap("bbb")], "sorted + deduped");
  assert.equal(a.sig.sigB64, b.sig.sigB64, "canonicalization makes the two signatures identical");
});

test("toRevocationState projects the verifier param shape", () => {
  const account = genKey();
  const rec = make({ account, signer: account, epoch: 5, revokedCertIds: [cap("dead")], minValidIssuedAtMs: 12345 });
  assert.deepEqual(rec.toRevocationState(), { revokedCertIds: [cap("dead")], minValidIssuedAtMs: 12345 });
});

test("a delegated device may sign the authority state (enforcement lives in the verifier)", () => {
  const account = genKey();
  const deviceC = genKey();
  const rec = make({ account, signer: deviceC, epoch: 2, revokedCertIds: [cap("cccc")] });
  assert.equal(rec.signerPublicKeyB64, deviceC.publicKeyB64);
  assert.ok(verify(deviceC.publicKeyB64, AccountAuthorityStateV1.signableBytes(rec.toJSON()), rec.sig));
});

test("rejects a negative epoch, a non-cap revoked id, and a negative cutoff", () => {
  const account = genKey();
  assert.throws(() => make({ account, signer: account, overrides: { epoch: -1 } }), /epoch must be a non-negative integer/);
  assert.throws(() => make({ account, signer: account, revokedCertIds: ["not-a-cap"] }), /revokedCertIds entries must be canonical rez:cap:<64-hex> ids/);
  // F3-remediation finding 2: a bare rez:cap: prefix is no longer enough.
  assert.throws(() => make({ account, signer: account, revokedCertIds: ["rez:cap:revoked-leaf"] }), /revokedCertIds entries must be canonical rez:cap:<64-hex> ids/);
  assert.throws(() => make({ account, signer: account, overrides: { minValidIssuedAtMs: -5 } }), /minValidIssuedAtMs must be a non-negative number/);
});

test("the signature binds the state: tampering revokedCertIds breaks it", () => {
  const account = genKey();
  const rec = make({ account, signer: account, epoch: 4, revokedCertIds: [cap("aaaa")] });
  const tampered = { ...rec.toJSON(), revokedCertIds: [cap("aaaa"), cap("ffff")] };
  assert.ok(!verify(account.publicKeyB64, AccountAuthorityStateV1.signableBytes(tampered), rec.sig));
});
