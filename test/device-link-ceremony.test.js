import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  DEVICE_LINK_PSK_BYTES,
  DEVICE_LINK_RECORD_KIND,
  DEVICE_LINK_RECORD_ID_REQUEST,
  generateDeviceLinkPsk,
  encodeDeviceLinkCodeV1,
  parseDeviceLinkCodeV1,
  isDeviceLinkCodeV1,
  deriveCeremonySecrets,
  buildCeremonyRequest,
  openCeremonyRequest,
  buildCeremonyResponse,
  openCeremonyResponse,
  buildCeremonyConfirm,
  verifyCeremonyConfirm,
  deviceLinkFingerprint,
  sealCeremonyRecord,
  verifyCeremonyRecord,
} from "../src/protocol/deviceLinkV1.js";
import { bytesToBase64 } from "../src/util/bytes.js";
import { NodeRealCryptoProvider } from "./support/NodeRealCryptoProvider.js";

// S2.5 S10 P2 — the PSK device-link ceremony (audit F8), pure-function layer,
// REAL crypto only. Pins the transcript binding, the PSK-authenticated
// ephemeral DH (forward secrecy), the key confirmation, and every rejection
// the SDK state machines rely on.

const CRYPTO = new NodeRealCryptoProvider();
const NOW = Date.now();

function genEdKeyPairB64() {
  const kp = CRYPTO.generateSigningKeyPair();
  return { publicKeyB64: bytesToBase64(kp.publicKey), privateKeyB64: bytesToBase64(kp.privateKey) };
}

function genDh() {
  return CRYPTO.dhGenerateKeyPair({ alg: "X25519", fmt: "spki" });
}

// A full ceremony context: account root B (pub used; priv only for the cert
// in bundle tests), rendezvous keypair R (a plain Ed25519 pair here — the
// PSK→R derivation via SeedKeys is the SDK's job), device key C, psk.
function makeCeremony() {
  const psk = generateDeviceLinkPsk({ crypto: CRYPTO });
  const account = genEdKeyPairB64();
  const rendezvous = genEdKeyPairB64();
  const device = genEdKeyPairB64();
  const accountDh = genDh();
  return {
    psk,
    accountSignPublicKeyB64: account.publicKeyB64,
    rendezvousPublicKeyB64: rendezvous.publicKeyB64,
    rendezvousKeyPair: rendezvous,
    deviceKeyPair: device,
    bundle: {
      accountSignPublicKeyB64: account.publicKeyB64,
      accountDhKeyPair: {
        publicKeyB64: bytesToBase64(accountDh.publicKey),
        privateKeyB64: bytesToBase64(accountDh.privateKey),
      },
      certChain: [{ certId: "rez:cap:stub", accountIdentityPublicKeyB64: account.publicKeyB64 }],
      cachedDeviceSet: null,
    },
  };
}

async function runRequest(c) {
  return buildCeremonyRequest({
    crypto: CRYPTO,
    nowMs: NOW,
    psk: c.psk,
    accountSignPublicKeyB64: c.accountSignPublicKeyB64,
    rendezvousPublicKeyB64: c.rendezvousPublicKeyB64,
    deviceKeyPair: c.deviceKeyPair,
  });
}

async function runOpenRequest(c, payload) {
  return openCeremonyRequest({
    crypto: CRYPTO,
    nowMs: NOW,
    psk: c.psk,
    accountSignPublicKeyB64: c.accountSignPublicKeyB64,
    rendezvousPublicKeyB64: c.rendezvousPublicKeyB64,
    payload,
  });
}

// ---- link code ----

test("link code: encode/parse round-trip; prefix test; malformed inputs typed LINK_V1_INVALID_FORMAT", () => {
  const c = makeCeremony();
  const code = encodeDeviceLinkCodeV1({ psk: c.psk, accountSignPublicKeyB64: c.accountSignPublicKeyB64 });
  assert.equal(isDeviceLinkCodeV1(code), true);
  const parsed = parseDeviceLinkCodeV1(code);
  assert.deepEqual(parsed.psk, c.psk);
  assert.equal(parsed.accountSignPublicKeyB64, c.accountSignPublicKeyB64);

  const cases = [
    "rez:inv:v3:not-a-link-code",
    "rez:link:v1:",
    "rez:link:v1:nodot",
    "rez:link:v1:short." + c.accountSignPublicKeyB64,
    code.slice(0, -1), // truncated pubkey
    "rez:link:v1:" + code.split(":")[3].split(".")[0] + ".", // empty pubkey
  ];
  for (const bad of cases) {
    assert.throws(() => parseDeviceLinkCodeV1(bad), (err) => err.code === "LINK_V1_INVALID_FORMAT", bad);
  }
});

// ---- derivations ----

test("deriveCeremonySecrets: deterministic per psk, all outputs distinct, differ across psks", async () => {
  const c = makeCeremony();
  const a = await deriveCeremonySecrets({ crypto: CRYPTO, psk: c.psk });
  const b = await deriveCeremonySecrets({ crypto: CRYPTO, psk: c.psk });
  assert.deepEqual(a.rendezvousSeed, b.rendezvousSeed);
  assert.equal(a.ceremonyNonceB64, b.ceremonyNonceB64);
  assert.deepEqual(a.requestKey, b.requestKey);
  assert.notDeepEqual(a.rendezvousSeed, a.requestKey);
  assert.notEqual(bytesToBase64(a.rendezvousSeed), a.ceremonyNonceB64);
  const other = await deriveCeremonySecrets({ crypto: CRYPTO, psk: generateDeviceLinkPsk({ crypto: CRYPTO }) });
  assert.notDeepEqual(other.rendezvousSeed, a.rendezvousSeed);
  assert.notEqual(other.ceremonyNonceB64, a.ceremonyNonceB64);
});

// ---- happy path ----

test("happy path: request → open → response → open → confirm → verify (bundle + master secret agree)", async () => {
  const c = makeCeremony();
  const req = await runRequest(c);
  assert.equal(req.payload.step, "request");
  assert.match(req.fingerprint, /^[0-9a-f]{4}(-[0-9a-f]{4}){4}$/);

  const opened = await runOpenRequest(c, req.payload);
  assert.equal(opened.thRequestB64, req.thRequestB64);
  assert.equal(opened.newDeviceId, req.linkRequest.newDeviceId);
  assert.equal(opened.fingerprint, req.fingerprint);

  const resp = await buildCeremonyResponse({
    crypto: CRYPTO,
    psk: c.psk,
    accountSignPublicKeyB64: c.accountSignPublicKeyB64,
    rendezvousPublicKeyB64: c.rendezvousPublicKeyB64,
    thRequestB64: opened.thRequestB64,
    ephemeralDhPublicKeyB64: opened.ephemeralDhPublicKeyB64,
    delegationBundle: c.bundle,
  });
  const openedResp = await openCeremonyResponse({
    crypto: CRYPTO,
    psk: c.psk,
    accountSignPublicKeyB64: c.accountSignPublicKeyB64,
    rendezvousPublicKeyB64: c.rendezvousPublicKeyB64,
    thRequestB64: req.thRequestB64,
    ephemeralKeyPair: req.ephemeralKeyPair,
    payload: resp.payload,
  });
  assert.deepEqual(openedResp.delegationBundle, c.bundle);
  assert.deepEqual(openedResp.masterSecret, resp.masterSecret, "both sides derive the same master secret");
  assert.equal(openedResp.thResponseB64, resp.thResponseB64);

  const confirm = await buildCeremonyConfirm({
    crypto: CRYPTO,
    masterSecret: openedResp.masterSecret,
    thResponseB64: openedResp.thResponseB64,
  });
  assert.equal(await verifyCeremonyConfirm({
    crypto: CRYPTO,
    masterSecret: resp.masterSecret,
    thResponseB64: resp.thResponseB64,
    payload: confirm.payload,
  }), true);
});

// ---- request rejections ----

test("request rejections: wrong psk, tamper, wrong account, cross-ceremony nonce, expiry, skew, bad C sig, Ed25519-as-eA", async () => {
  const c = makeCeremony();
  const req = await runRequest(c);

  // Wrong psk cannot open (different K_req).
  const wrongPsk = { ...c, psk: generateDeviceLinkPsk({ crypto: CRYPTO }) };
  await assert.rejects(() => runOpenRequest(wrongPsk, req.payload));

  // Tampered ciphertext fails AEAD.
  const tampered = { ...req.payload, ciphertextB64: req.payload.ciphertextB64.slice(0, -4) + "AAA=" };
  await assert.rejects(() => runOpenRequest(c, tampered));

  // Wrong account in the opener's context — AAD differs, AEAD fails.
  const otherAccount = genEdKeyPairB64();
  await assert.rejects(() => runOpenRequest({ ...c, accountSignPublicKeyB64: otherAccount.publicKeyB64 }, req.payload));

  // Cross-ceremony replay: a request built under psk2 presented to psk1's
  // opener — K_req mismatch kills it at AEAD before the nonce check.
  const c2 = { ...makeCeremony(), accountSignPublicKeyB64: c.accountSignPublicKeyB64, rendezvousPublicKeyB64: c.rendezvousPublicKeyB64 };
  const req2 = await runRequest(c2);
  await assert.rejects(() => runOpenRequest(c, req2.payload));

  // Expired request.
  const expired = await buildCeremonyRequest({
    crypto: CRYPTO, nowMs: NOW - 60 * 60_000, psk: c.psk,
    accountSignPublicKeyB64: c.accountSignPublicKeyB64,
    rendezvousPublicKeyB64: c.rendezvousPublicKeyB64,
    deviceKeyPair: c.deviceKeyPair,
    requestTtlMs: 60_000,
  });
  await assert.rejects(() => runOpenRequest(c, expired.payload), /expired/);

  // Future-issued beyond skew.
  const future = await buildCeremonyRequest({
    crypto: CRYPTO, nowMs: NOW + 60 * 60_000, psk: c.psk,
    accountSignPublicKeyB64: c.accountSignPublicKeyB64,
    rendezvousPublicKeyB64: c.rendezvousPublicKeyB64,
    deviceKeyPair: c.deviceKeyPair,
  });
  await assert.rejects(() => runOpenRequest(c, future.payload), /future/);

  // An Ed25519 key masquerading as the ephemeral X25519 point is rejected at
  // build time (the X25519 SPKI pin).
  const edAsDh = CRYPTO.generateSigningKeyPair();
  await assert.rejects(() => buildCeremonyRequest({
    crypto: CRYPTO, nowMs: NOW, psk: c.psk,
    accountSignPublicKeyB64: c.accountSignPublicKeyB64,
    rendezvousPublicKeyB64: c.rendezvousPublicKeyB64,
    deviceKeyPair: c.deviceKeyPair,
    ephemeralKeyPair: edAsDh,
  }), /X25519 SPKI/);
});

// ---- response rejections ----

test("response rejections: eB AAD bind, wrong thRequest, forbidden bundle keys, missing ephemeral (FS)", async () => {
  const c = makeCeremony();
  const req = await runRequest(c);
  const opened = await runOpenRequest(c, req.payload);
  const resp = await buildCeremonyResponse({
    crypto: CRYPTO, psk: c.psk,
    accountSignPublicKeyB64: c.accountSignPublicKeyB64,
    rendezvousPublicKeyB64: c.rendezvousPublicKeyB64,
    thRequestB64: opened.thRequestB64,
    ephemeralDhPublicKeyB64: opened.ephemeralDhPublicKeyB64,
    delegationBundle: c.bundle,
  });

  const open = (payload, over = {}) => openCeremonyResponse({
    crypto: CRYPTO, psk: c.psk,
    accountSignPublicKeyB64: c.accountSignPublicKeyB64,
    rendezvousPublicKeyB64: c.rendezvousPublicKeyB64,
    thRequestB64: req.thRequestB64,
    ephemeralKeyPair: req.ephemeralKeyPair,
    payload,
    ...over,
  });

  // Swapping the plaintext-visible eB field breaks the AAD bind — the derived
  // key differs AND the AAD differs, so AEAD open fails.
  const swappedEb = genDh();
  await assert.rejects(() => open({ ...resp.payload, ephemeralDhPublicKeyB64: bytesToBase64(swappedEb.publicKey) }));

  // A response bound to a different request transcript fails.
  const otherTh = bytesToBase64(new Uint8Array(crypto.randomBytes(32)));
  await assert.rejects(() => open(resp.payload, { thRequestB64: otherTh }));

  // Forbidden bundle keys never reach the wire.
  for (const key of ["deviceKeyPair", "accountSignPrivateKeyB64", "accountSignKeyPair", "mnemonic", "seed"]) {
    await assert.rejects(() => buildCeremonyResponse({
      crypto: CRYPTO, psk: c.psk,
      accountSignPublicKeyB64: c.accountSignPublicKeyB64,
      rendezvousPublicKeyB64: c.rendezvousPublicKeyB64,
      thRequestB64: opened.thRequestB64,
      ephemeralDhPublicKeyB64: opened.ephemeralDhPublicKeyB64,
      delegationBundle: { ...c.bundle, [key]: "smuggled" },
    }), new RegExp("must not contain " + key));
  }

  // FORWARD SECRECY: psk + full wire transcript WITHOUT the ephemeral private
  // cannot open the response.
  await assert.rejects(() => open(resp.payload, { ephemeralKeyPair: null }), /requires the requester's ephemeralKeyPair/);
  // ...and a psk-derived key is NOT the response key: decrypting the response
  // ciphertext under K_req (everything an eavesdropper with the psk can
  // derive) fails.
  const secrets = await deriveCeremonySecrets({ crypto: CRYPTO, psk: c.psk });
  assert.throws(() => CRYPTO.aeadDecrypt({
    key: secrets.requestKey,
    nonce: Buffer.from(resp.payload.nonceB64, "base64"),
    ciphertext: Buffer.from(resp.payload.ciphertextB64, "base64"),
    aad: new Uint8Array(0),
  }));
});

test("oversized cachedDeviceSet is dropped, ceremony still completes; oversized core bundle throws", async () => {
  const c = makeCeremony();
  const req = await runRequest(c);
  const opened = await runOpenRequest(c, req.payload);
  const bigSet = { blob: "x".repeat(20_000) };
  const resp = await buildCeremonyResponse({
    crypto: CRYPTO, psk: c.psk,
    accountSignPublicKeyB64: c.accountSignPublicKeyB64,
    rendezvousPublicKeyB64: c.rendezvousPublicKeyB64,
    thRequestB64: opened.thRequestB64,
    ephemeralDhPublicKeyB64: opened.ephemeralDhPublicKeyB64,
    delegationBundle: { ...c.bundle, cachedDeviceSet: bigSet },
  });
  const openedResp = await openCeremonyResponse({
    crypto: CRYPTO, psk: c.psk,
    accountSignPublicKeyB64: c.accountSignPublicKeyB64,
    rendezvousPublicKeyB64: c.rendezvousPublicKeyB64,
    thRequestB64: req.thRequestB64,
    ephemeralKeyPair: req.ephemeralKeyPair,
    payload: resp.payload,
  });
  assert.equal(openedResp.delegationBundle.cachedDeviceSet, null, "the oversized set was dropped");

  await assert.rejects(() => buildCeremonyResponse({
    crypto: CRYPTO, psk: c.psk,
    accountSignPublicKeyB64: c.accountSignPublicKeyB64,
    rendezvousPublicKeyB64: c.rendezvousPublicKeyB64,
    thRequestB64: opened.thRequestB64,
    ephemeralDhPublicKeyB64: opened.ephemeralDhPublicKeyB64,
    delegationBundle: {
      ...c.bundle,
      certChain: [{ blob: "y".repeat(20_000) }],
    },
  }), /exceeds the durable-record payload budget/);
});

// ---- confirm ----

test("confirm: correct tag verifies; wrong transcript / flipped bit / wrong shape fail as boolean", async () => {
  const c = makeCeremony();
  const req = await runRequest(c);
  const opened = await runOpenRequest(c, req.payload);
  const resp = await buildCeremonyResponse({
    crypto: CRYPTO, psk: c.psk,
    accountSignPublicKeyB64: c.accountSignPublicKeyB64,
    rendezvousPublicKeyB64: c.rendezvousPublicKeyB64,
    thRequestB64: opened.thRequestB64,
    ephemeralDhPublicKeyB64: opened.ephemeralDhPublicKeyB64,
    delegationBundle: c.bundle,
  });
  const confirm = await buildCeremonyConfirm({ crypto: CRYPTO, masterSecret: resp.masterSecret, thResponseB64: resp.thResponseB64 });

  assert.equal(await verifyCeremonyConfirm({ crypto: CRYPTO, masterSecret: resp.masterSecret, thResponseB64: resp.thResponseB64, payload: confirm.payload }), true);
  const otherTh = bytesToBase64(new Uint8Array(crypto.randomBytes(32)));
  assert.equal(await verifyCeremonyConfirm({ crypto: CRYPTO, masterSecret: resp.masterSecret, thResponseB64: otherTh, payload: confirm.payload }), false);
  const flipped = { ...confirm.payload, tagB64: bytesToBase64(new Uint8Array(crypto.randomBytes(32))) };
  assert.equal(await verifyCeremonyConfirm({ crypto: CRYPTO, masterSecret: resp.masterSecret, thResponseB64: resp.thResponseB64, payload: flipped }), false);
  assert.equal(await verifyCeremonyConfirm({ crypto: CRYPTO, masterSecret: resp.masterSecret, thResponseB64: resp.thResponseB64, payload: { v: 1, step: "request", tagB64: confirm.payload.tagB64 } }), false);
});

// ---- record helpers ----

test("record helpers: seal→verify round-trip; wrong publisher/recordId/expiry/signature rejected", async () => {
  const c = makeCeremony();
  const payloadB64 = bytesToBase64(new TextEncoder().encode(JSON.stringify({ v: 1, step: "request", nonceB64: "x", ciphertextB64: "y" })));
  const record = await sealCeremonyRecord({
    crypto: CRYPTO, nowMs: NOW,
    rendezvousKeyPair: c.rendezvousKeyPair,
    recordId: DEVICE_LINK_RECORD_ID_REQUEST,
    payloadB64,
    expiresAtMs: NOW + 60_000,
  });
  assert.equal(record.recordKind, DEVICE_LINK_RECORD_KIND);

  const payload = await verifyCeremonyRecord({
    crypto: CRYPTO, nowMs: NOW, record,
    rendezvousPublicKeyB64: c.rendezvousPublicKeyB64,
    recordId: DEVICE_LINK_RECORD_ID_REQUEST,
  });
  assert.equal(payload.step, "request");

  const stranger = genEdKeyPairB64();
  await assert.rejects(() => verifyCeremonyRecord({
    crypto: CRYPTO, nowMs: NOW, record,
    rendezvousPublicKeyB64: stranger.publicKeyB64,
    recordId: DEVICE_LINK_RECORD_ID_REQUEST,
  }), /not published under this ceremony's rendezvous key/);
  await assert.rejects(() => verifyCeremonyRecord({
    crypto: CRYPTO, nowMs: NOW, record,
    rendezvousPublicKeyB64: c.rendezvousPublicKeyB64,
    recordId: "response",
  }), /wrong recordId/);
  await assert.rejects(() => verifyCeremonyRecord({
    crypto: CRYPTO, nowMs: NOW + 120_000, record,
    rendezvousPublicKeyB64: c.rendezvousPublicKeyB64,
    recordId: DEVICE_LINK_RECORD_ID_REQUEST,
  }), /expired/);
  await assert.rejects(() => verifyCeremonyRecord({
    crypto: CRYPTO, nowMs: NOW,
    record: { ...record, payloadB64: bytesToBase64(new TextEncoder().encode("{\"forged\":1}")) },
    rendezvousPublicKeyB64: c.rendezvousPublicKeyB64,
    recordId: DEVICE_LINK_RECORD_ID_REQUEST,
  }), /signature is invalid/);
});

// ---- fingerprint ----

test("fingerprint: stable xxxx-xxxx-xxxx-xxxx-xxxx from the deviceId; rejects non-device ids", () => {
  const id = "rez:dev:" + "ab12".repeat(16);
  const fp = deviceLinkFingerprint(id);
  assert.equal(fp, "ab12-ab12-ab12-ab12-ab12");
  assert.equal(deviceLinkFingerprint(id), fp);
  assert.throws(() => deviceLinkFingerprint("rez:acct:whatever"), /rez:dev/);
});
