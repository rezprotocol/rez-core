import test from "node:test";
import assert from "node:assert/strict";
import {
  DeviceLinkRequestV1,
  DEVICE_LINK_REQUEST_VERSION,
  DEVICE_LINK_REQUEST_PURPOSE,
  DeviceLinkRequestV2,
  DEVICE_LINK_REQUEST_V2_VERSION,
  DEVICE_LINK_REQUEST_V2_PURPOSE,
  AccountDeviceMutationV1,
  ACCOUNT_DEVICE_MUTATION_VERSION,
  ACCOUNT_DEVICE_MUTATION_PURPOSE,
  AccountDeviceMutationV2,
  ACCOUNT_DEVICE_MUTATION_V2_VERSION,
  ACCOUNT_DEVICE_MUTATION_V2_PURPOSE,
} from "../src/index.js";

// AUDIT #5 — GOLDEN SIGNED BYTES.
//
// The finding was that two signed schemas were changed in place: DeviceLinkRequestV1 gained a
// required `deviceInboxBinding` inside its signableBytes, and AccountDeviceMutationV1's device.add
// target gained a required `deviceCapability` (the target is covered wholesale). Both kept `v: 1`
// and their original purpose string — so a "v1" signature stopped meaning one thing and started
// meaning another, with nothing to detect it.
//
// These fixtures are the detector. The expected strings below are LITERALS, deliberately not
// computed from the classes: a test that rebuilds the body from the same code it is testing proves
// only that the code equals itself. If a field is added, removed, renamed, or reordered in any of
// these four schemas, the exact bytes change and this fails.
//
// A DELIBERATE schema change means adding a NEW version class and a NEW golden — never editing a
// golden below. Editing one is how the original bug would recur.

// Fixed, obviously-fake inputs. Real keys are irrelevant here: signableBytes is a pure function of
// the body, and pinning it needs determinism, not authenticity.
const ACCOUNT = "acct-pub-b64";
const DEVICE_PUB = "device-pub-b64";
const DEVICE_ID = "rez:dev:" + "1".repeat(64);
const NONCE = "nonce-b64";
const ISSUED = 1_700_000_000_000;
const EXPIRES = 1_700_000_600_000;
const BINDING = { v: 1, purpose: "rez:device-inbox-binding:v1", deviceId: DEVICE_ID, inboxId: "rez:inbox:x" };
const CAPABILITY = { v: 1, purpose: "rez:account-device-capability:v1", certId: "rez:cap:" + "a".repeat(64) };

function utf8(bytes) {
  return new TextDecoder().decode(bytes);
}

test("GOLDEN — DeviceLinkRequestV1 signed bytes (FROZEN, must never change)", () => {
  const bytes = DeviceLinkRequestV1.signableBytes({
    v: DEVICE_LINK_REQUEST_VERSION,
    purpose: DEVICE_LINK_REQUEST_PURPOSE,
    accountIdentityPublicKeyB64: ACCOUNT,
    newDevicePublicKeyB64: DEVICE_PUB,
    newDeviceId: DEVICE_ID,
    ceremonyNonceB64: NONCE,
    issuedAtMs: ISSUED,
    expiresAtMs: EXPIRES,
  });
  assert.equal(
    utf8(bytes),
    '{"accountIdentityPublicKeyB64":"acct-pub-b64","ceremonyNonceB64":"nonce-b64","expiresAtMs":1700000600000,"issuedAtMs":1700000000000,"newDeviceId":"rez:dev:1111111111111111111111111111111111111111111111111111111111111111","newDevicePublicKeyB64":"device-pub-b64","purpose":"rez:device-link-request:v1","v":1}',
  );
});

test("GOLDEN — DeviceLinkRequestV1 IGNORES deviceInboxBinding (the field that broke it)", () => {
  // The precise regression: passing the v2 field to v1 must not change v1's bytes. If this ever
  // fails, the field has crept back into the frozen schema.
  const withoutBinding = DeviceLinkRequestV1.signableBytes({
    v: DEVICE_LINK_REQUEST_VERSION,
    purpose: DEVICE_LINK_REQUEST_PURPOSE,
    accountIdentityPublicKeyB64: ACCOUNT,
    newDevicePublicKeyB64: DEVICE_PUB,
    newDeviceId: DEVICE_ID,
    ceremonyNonceB64: NONCE,
    issuedAtMs: ISSUED,
    expiresAtMs: EXPIRES,
  });
  const withBinding = DeviceLinkRequestV1.signableBytes({
    v: DEVICE_LINK_REQUEST_VERSION,
    purpose: DEVICE_LINK_REQUEST_PURPOSE,
    accountIdentityPublicKeyB64: ACCOUNT,
    newDevicePublicKeyB64: DEVICE_PUB,
    newDeviceId: DEVICE_ID,
    deviceInboxBinding: BINDING,
    ceremonyNonceB64: NONCE,
    issuedAtMs: ISSUED,
    expiresAtMs: EXPIRES,
  });
  assert.equal(utf8(withBinding), utf8(withoutBinding));
});

test("GOLDEN — DeviceLinkRequestV2 signed bytes", () => {
  const bytes = DeviceLinkRequestV2.signableBytes({
    v: DEVICE_LINK_REQUEST_V2_VERSION,
    purpose: DEVICE_LINK_REQUEST_V2_PURPOSE,
    accountIdentityPublicKeyB64: ACCOUNT,
    newDevicePublicKeyB64: DEVICE_PUB,
    newDeviceId: DEVICE_ID,
    deviceInboxBinding: BINDING,
    ceremonyNonceB64: NONCE,
    issuedAtMs: ISSUED,
    expiresAtMs: EXPIRES,
  });
  assert.equal(
    utf8(bytes),
    '{"accountIdentityPublicKeyB64":"acct-pub-b64","ceremonyNonceB64":"nonce-b64","deviceInboxBinding":{"deviceId":"rez:dev:1111111111111111111111111111111111111111111111111111111111111111","inboxId":"rez:inbox:x","purpose":"rez:device-inbox-binding:v1","v":1},"expiresAtMs":1700000600000,"issuedAtMs":1700000000000,"newDeviceId":"rez:dev:1111111111111111111111111111111111111111111111111111111111111111","newDevicePublicKeyB64":"device-pub-b64","purpose":"rez:device-link-request:v2","v":2}',
  );
});

test("GOLDEN — AccountDeviceMutationV1 device.add signed bytes (FROZEN)", () => {
  const bytes = AccountDeviceMutationV1.signableBytes({
    v: ACCOUNT_DEVICE_MUTATION_VERSION,
    purpose: ACCOUNT_DEVICE_MUTATION_PURPOSE,
    opId: "op-1",
    accountIdentityPublicKeyB64: ACCOUNT,
    expectedRevision: 0,
    action: "device.add",
    target: { deviceInboxBinding: BINDING },
    signerPublicKeyB64: DEVICE_PUB,
    issuedAtMs: ISSUED,
    expiresAtMs: EXPIRES,
  });
  assert.equal(
    utf8(bytes),
    '{"accountIdentityPublicKeyB64":"acct-pub-b64","action":"device.add","expectedRevision":0,"expiresAtMs":1700000600000,"issuedAtMs":1700000000000,"opId":"op-1","purpose":"rez:account-device-mutation:v1","signerPublicKeyB64":"device-pub-b64","target":{"deviceInboxBinding":{"deviceId":"rez:dev:1111111111111111111111111111111111111111111111111111111111111111","inboxId":"rez:inbox:x","purpose":"rez:device-inbox-binding:v1","v":1}},"v":1}',
  );
});

test("GOLDEN — AccountDeviceMutationV1 device.revoke signed bytes (FROZEN, still accepted)", () => {
  // device.revoke is the one v1 action that survives: its target shape never changed, only its
  // validation tightened, so old signatures still verify over the same bytes and still mean the
  // same thing. These bytes are what "still accepted" is measured against.
  const bytes = AccountDeviceMutationV1.signableBytes({
    v: ACCOUNT_DEVICE_MUTATION_VERSION,
    purpose: ACCOUNT_DEVICE_MUTATION_PURPOSE,
    opId: "op-2",
    accountIdentityPublicKeyB64: ACCOUNT,
    expectedRevision: 3,
    action: "device.revoke",
    target: { revokedDeviceId: DEVICE_ID, revokedCertId: CAPABILITY.certId },
    signerPublicKeyB64: DEVICE_PUB,
    issuedAtMs: ISSUED,
    expiresAtMs: EXPIRES,
  });
  assert.equal(
    utf8(bytes),
    '{"accountIdentityPublicKeyB64":"acct-pub-b64","action":"device.revoke","expectedRevision":3,"expiresAtMs":1700000600000,"issuedAtMs":1700000000000,"opId":"op-2","purpose":"rez:account-device-mutation:v1","signerPublicKeyB64":"device-pub-b64","target":{"revokedCertId":"rez:cap:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","revokedDeviceId":"rez:dev:1111111111111111111111111111111111111111111111111111111111111111"},"v":1}',
  );
});

test("GOLDEN — AccountDeviceMutationV2 device.add signed bytes", () => {
  const bytes = AccountDeviceMutationV2.signableBytes({
    v: ACCOUNT_DEVICE_MUTATION_V2_VERSION,
    purpose: ACCOUNT_DEVICE_MUTATION_V2_PURPOSE,
    opId: "op-1",
    accountIdentityPublicKeyB64: ACCOUNT,
    expectedRevision: 0,
    action: "device.add",
    target: { deviceInboxBinding: BINDING, deviceCapability: CAPABILITY },
    signerPublicKeyB64: DEVICE_PUB,
    issuedAtMs: ISSUED,
    expiresAtMs: EXPIRES,
  });
  assert.equal(
    utf8(bytes),
    '{"accountIdentityPublicKeyB64":"acct-pub-b64","action":"device.add","expectedRevision":0,"expiresAtMs":1700000600000,"issuedAtMs":1700000000000,"opId":"op-1","purpose":"rez:account-device-mutation:v2","signerPublicKeyB64":"device-pub-b64","target":{"deviceCapability":{"certId":"rez:cap:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","purpose":"rez:account-device-capability:v1","v":1},"deviceInboxBinding":{"deviceId":"rez:dev:1111111111111111111111111111111111111111111111111111111111111111","inboxId":"rez:inbox:x","purpose":"rez:device-inbox-binding:v1","v":1}},"v":2}',
  );
});

test("the two versions are DISTINGUISHABLE: different v AND different purpose", () => {
  // Either alone would be a weaker guarantee. A verifier that keys only on `v` and one that keys
  // only on `purpose` must both be able to tell these apart.
  assert.notEqual(DEVICE_LINK_REQUEST_VERSION, DEVICE_LINK_REQUEST_V2_VERSION);
  assert.notEqual(DEVICE_LINK_REQUEST_PURPOSE, DEVICE_LINK_REQUEST_V2_PURPOSE);
  assert.notEqual(ACCOUNT_DEVICE_MUTATION_VERSION, ACCOUNT_DEVICE_MUTATION_V2_VERSION);
  assert.notEqual(ACCOUNT_DEVICE_MUTATION_PURPOSE, ACCOUNT_DEVICE_MUTATION_V2_PURPOSE);
});

test("a V1 body and a V2 body NEVER produce the same signed bytes", () => {
  // The property that was actually violated: two schemas sharing an identity. Even with every
  // shared field identical, the version + purpose keep the signed bytes apart, so a signature made
  // for one can never be replayed as the other.
  const shared = {
    accountIdentityPublicKeyB64: ACCOUNT,
    newDevicePublicKeyB64: DEVICE_PUB,
    newDeviceId: DEVICE_ID,
    ceremonyNonceB64: NONCE,
    issuedAtMs: ISSUED,
    expiresAtMs: EXPIRES,
  };
  const v1 = DeviceLinkRequestV1.signableBytes({
    ...shared, v: DEVICE_LINK_REQUEST_VERSION, purpose: DEVICE_LINK_REQUEST_PURPOSE,
  });
  const v2 = DeviceLinkRequestV2.signableBytes({
    ...shared, v: DEVICE_LINK_REQUEST_V2_VERSION, purpose: DEVICE_LINK_REQUEST_V2_PURPOSE, deviceInboxBinding: BINDING,
  });
  assert.notEqual(utf8(v1), utf8(v2));
});
