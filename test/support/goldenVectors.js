/**
 * P7.1 — shared cross-runtime golden vectors (ATLAS_PREREQUISITES).
 *
 * FROZEN LITERALS (golden doctrine, cf. records.signed-schema-goldens): the
 * values below were generated ONCE from the fixed TEST-ONLY seed and are
 * deliberately not computed from the classes at test time. If a test here
 * fails after an edit, canonical bytes or ID derivation CHANGED — that is a
 * wire-breaking event, not a fixture chore. A deliberate change adds NEW
 * versioned vectors; never edit these.
 *
 * Key material is test-only (seed = ascii "atlas-prereqs-golden-vector-0001").
 * Consumers: rez-core (canonical bytes + IDs), rez-node (Node crypto verify +
 * DHT mapping), rez-sdk (WebCrypto verify + IndexedDB round trip). Ed25519 is
 * deterministic (RFC 8032), so both runtimes must REPRODUCE the signatures
 * byte-for-byte, not merely verify them.
 */

export const GOLDEN_SEED_HEX = "61746c61732d707265726571732d676f6c64656e2d766563746f722d30303031";
export const GOLDEN_NODE_PUBLIC_KEY_B64 = "MCowBQYDK2VwAyEAP/UMV9HcP6cqXuUUtfP76kSDXkPSIbbDYiKjtas596g=";
export const GOLDEN_NODE_PRIVATE_KEY_B64 = "MC4CAQAwBQYDK2VwBCIEIGF0bGFzLXByZXJlcXMtZ29sZGVuLXZlY3Rvci0wMDAx";
export const GOLDEN_RELAY_KEY_ID = "rez:relay:0d6e5bf065b91e8c80a83eea92c10948660d7fe6d5022abefe30df8e28cba30f";
export const GOLDEN_NODE_KEY_ID = "nodekey:0d6e5bf065b91e8c80a83eea92c10948";
export const GOLDEN_DHT_NODE_ID_HEX = "3965475dd2f581548aba83c1827364ce26700236a05dc7a453f3ce9dfd302a8b";
export const GOLDEN_NOW_MS = 1755216000000;

export const GOLDEN_RELAY_DESCRIPTOR = Object.freeze({
  "v": 1,
  "relayKeyId": "rez:relay:0d6e5bf065b91e8c80a83eea92c10948660d7fe6d5022abefe30df8e28cba30f",
  "endpoints": [
    {
      "host": "relay.golden.test",
      "port": 8443,
      "tls": true
    }
  ],
  "onionKeys": [
    {
      "v": 1,
      "onionKeyId": "golden-onion-1",
      "publicKeyBytes": [
        66,
        66,
        66,
        66,
        66,
        66,
        66,
        66,
        66,
        66,
        66,
        66,
        66,
        66,
        66,
        66,
        66,
        66,
        66,
        66,
        66,
        66,
        66,
        66,
        66,
        66,
        66,
        66,
        66,
        66,
        66,
        66
      ],
      "format": "raw",
      "createdAt": 1755215999000,
      "notBefore": 1755215999000,
      "notAfter": 1755302400000,
      "status": "active"
    }
  ],
  "expiresAt": 1755302400000,
  "sig": {
    "scheme": "ed25519",
    "keyId": "nodekey:0d6e5bf065b91e8c80a83eea92c10948",
    "sigB64": "rTkWWDkTFZPgtQPOTfLjjxxckQki2PM+H0Ro+PmS0XX5W0d/BFmk4jw5Lxldetuz1QSLMKCv1G42M8QxrsmCAA=="
  },
  "meta": {
    "v": 1,
    "node": {
      "keyId": "nodekey:0d6e5bf065b91e8c80a83eea92c10948",
      "publicKeyB64": "MCowBQYDK2VwAyEAP/UMV9HcP6cqXuUUtfP76kSDXkPSIbbDYiKjtas596g=",
      "protocolVersion": 4
    }
  }
});

export const GOLDEN_DESCRIPTOR_SIGNING_STRING = "{\"endpoints\":[{\"host\":\"relay.golden.test\",\"port\":8443,\"tls\":true}],\"expiresAt\":1755302400000,\"kind\":\"relay-descriptor\",\"meta\":{\"node\":{\"keyId\":\"nodekey:0d6e5bf065b91e8c80a83eea92c10948\",\"protocolVersion\":4,\"publicKeyB64\":\"MCowBQYDK2VwAyEAP/UMV9HcP6cqXuUUtfP76kSDXkPSIbbDYiKjtas596g=\"},\"v\":1},\"onionKeys\":[{\"createdAt\":1755215999000,\"format\":\"raw\",\"notAfter\":1755302400000,\"notBefore\":1755215999000,\"onionKeyId\":\"golden-onion-1\",\"publicKeyBytes\":[66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66],\"status\":\"active\",\"v\":1}],\"relayKeyId\":\"rez:relay:0d6e5bf065b91e8c80a83eea92c10948660d7fe6d5022abefe30df8e28cba30f\",\"v\":1}";

export const GOLDEN_DURABLE_RECORD_V1 = Object.freeze({
  "v": 1,
  "recordKind": "future-test-public-fact-v1",
  "recordId": "golden-1",
  "publisherPublicKeyB64": "MCowBQYDK2VwAyEAP/UMV9HcP6cqXuUUtfP76kSDXkPSIbbDYiKjtas596g=",
  "issuedAtMs": 1755216000000,
  "expiresAtMs": 1755219600000,
  "payloadB64": "Z29sZGVuIG9wYXF1ZSBwYXlsb2Fk",
  "sigB64": "+wy6mbcmQRnXshXKxw92XaETFmFqlJ9EpKTsQpX8Pbr8jzIbehUdiOB+orPHjQrn7nKcm+0U/wx6gbnf2/DKCw=="
});

export const GOLDEN_DURABLE_RECORD_V1_SIGNABLE_STRING = "{\"expiresAtMs\":1755219600000,\"issuedAtMs\":1755216000000,\"payloadB64\":\"Z29sZGVuIG9wYXF1ZSBwYXlsb2Fk\",\"publisherPublicKeyB64\":\"MCowBQYDK2VwAyEAP/UMV9HcP6cqXuUUtfP76kSDXkPSIbbDYiKjtas596g=\",\"recordId\":\"golden-1\",\"recordKind\":\"future-test-public-fact-v1\",\"v\":1}";

export const GOLDEN_DURABLE_RECORD_V1_LOCAL_ID = "15190e289495f0a0500b0edcd68d8fb74fdafc599815fdab3ddf3d66aa2455de";

// ── DurableRecordV2 vectors (re-audit R7) ───────────────────────────────────
// Device key seed = ascii "atlas-prereqs-golden-device-0001" (test-only).
// The V2 envelope is what the root-signed authority-state work rides on; a
// silent canonicalization change to durableRecordV2SignableBytes MUST fail
// these vectors in every runtime.

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const key of Object.keys(value)) deepFreeze(value[key]);
  }
  return value;
}

export const GOLDEN_DEVICE_PUBLIC_KEY_B64 = "MCowBQYDK2VwAyEA2JP7y/uR2BlDD9fc6hpHktd//KhEKDjqo4fhfnJ267s=";
export const GOLDEN_DEVICE_PRIVATE_KEY_B64 = "MC4CAQAwBQYDK2VwBCIEIGF0bGFzLXByZXJlcXMtZ29sZGVuLWRldmljZS0wMDAx";

export const GOLDEN_DEVICE_CERT = deepFreeze({
  "v": 1,
  "purpose": "rez:account-device-capability:v1",
  "accountIdentityPublicKeyB64": "MCowBQYDK2VwAyEAP/UMV9HcP6cqXuUUtfP76kSDXkPSIbbDYiKjtas596g=",
  "parentCertId": null,
  "granteeDevicePublicKeyB64": "MCowBQYDK2VwAyEA2JP7y/uR2BlDD9fc6hpHktd//KhEKDjqo4fhfnJ267s=",
  "granteeDeviceId": "rez:dev:d43a697415161bf861c5be7377cdda317bd5090be0c617fd25194ed74976a94b",
  "capabilities": ["deviceSet.publish"],
  "maxDelegationDepth": 0,
  "issuedAtMs": 1755215999000,
  "expiresAtMs": 1755302400000,
  "certId": "rez:cap:6185bef7d66a7d5c070718c104646d4ecc50de89f68d00df93837f94b6515eac",
  "signerPublicKeyB64": "MCowBQYDK2VwAyEAP/UMV9HcP6cqXuUUtfP76kSDXkPSIbbDYiKjtas596g=",
  "sig": {
    "alg": "ed25519",
    "sigB64": "RsPnDowJByM+NSNG80VT7T4WcM39+WFTdjw08d0V14OidKsIMLZ+PH9wau7JEzO1pHocrN8XmXFh91s/hHd1Ag=="
  }
});

export const GOLDEN_DEVICE_CERT_SIGNABLE_STRING = "{\"accountIdentityPublicKeyB64\":\"MCowBQYDK2VwAyEAP/UMV9HcP6cqXuUUtfP76kSDXkPSIbbDYiKjtas596g=\",\"capabilities\":[\"deviceSet.publish\"],\"certId\":\"rez:cap:6185bef7d66a7d5c070718c104646d4ecc50de89f68d00df93837f94b6515eac\",\"expiresAtMs\":1755302400000,\"granteeDeviceId\":\"rez:dev:d43a697415161bf861c5be7377cdda317bd5090be0c617fd25194ed74976a94b\",\"granteeDevicePublicKeyB64\":\"MCowBQYDK2VwAyEA2JP7y/uR2BlDD9fc6hpHktd//KhEKDjqo4fhfnJ267s=\",\"issuedAtMs\":1755215999000,\"maxDelegationDepth\":0,\"parentCertId\":null,\"purpose\":\"rez:account-device-capability:v1\",\"signerPublicKeyB64\":\"MCowBQYDK2VwAyEAP/UMV9HcP6cqXuUUtfP76kSDXkPSIbbDYiKjtas596g=\",\"v\":1}";

export const GOLDEN_DURABLE_RECORD_V2_DIRECT = deepFreeze({
  "v": 2,
  "recordKind": "rez.device-set.v1",
  "recordId": "golden-v2-direct",
  "ownerPublicKeyB64": "MCowBQYDK2VwAyEAP/UMV9HcP6cqXuUUtfP76kSDXkPSIbbDYiKjtas596g=",
  "signerPublicKeyB64": "MCowBQYDK2VwAyEAP/UMV9HcP6cqXuUUtfP76kSDXkPSIbbDYiKjtas596g=",
  "certChain": [],
  "requiredCapability": null,
  "issuedAtMs": 1755216000000,
  "expiresAtMs": 1755219600000,
  "payloadB64": "Z29sZGVuIHYyIGRpcmVjdCBwYXlsb2Fk",
  "sigB64": "eTvc8kmK1qrWH4vqT1J62GJdwBh4qDNDW52D6tUNaDwHLhU6iTF2DPFsl7OUunlPs/trLe5tQU27+A4bHQmHAQ=="
});

export const GOLDEN_DURABLE_RECORD_V2_DIRECT_SIGNABLE_STRING = "{\"certChainCertIds\":[],\"expiresAtMs\":1755219600000,\"issuedAtMs\":1755216000000,\"ownerPublicKeyB64\":\"MCowBQYDK2VwAyEAP/UMV9HcP6cqXuUUtfP76kSDXkPSIbbDYiKjtas596g=\",\"payloadB64\":\"Z29sZGVuIHYyIGRpcmVjdCBwYXlsb2Fk\",\"recordId\":\"golden-v2-direct\",\"recordKind\":\"rez.device-set.v1\",\"requiredCapability\":null,\"signerPublicKeyB64\":\"MCowBQYDK2VwAyEAP/UMV9HcP6cqXuUUtfP76kSDXkPSIbbDYiKjtas596g=\",\"v\":2}";

export const GOLDEN_DURABLE_RECORD_V2_DIRECT_SLOT = "8acd155cf325b53ac230607256e62bba809981d2bfd7b8e71fd1b17a05a7c62b";

export const GOLDEN_DURABLE_RECORD_V2_DELEGATED = deepFreeze({
  "v": 2,
  "recordKind": "rez.device-set.v1",
  "recordId": "golden-v2-delegated",
  "ownerPublicKeyB64": "MCowBQYDK2VwAyEAP/UMV9HcP6cqXuUUtfP76kSDXkPSIbbDYiKjtas596g=",
  "signerPublicKeyB64": "MCowBQYDK2VwAyEA2JP7y/uR2BlDD9fc6hpHktd//KhEKDjqo4fhfnJ267s=",
  "certChain": [{
    "v": 1,
    "purpose": "rez:account-device-capability:v1",
    "accountIdentityPublicKeyB64": "MCowBQYDK2VwAyEAP/UMV9HcP6cqXuUUtfP76kSDXkPSIbbDYiKjtas596g=",
    "parentCertId": null,
    "granteeDevicePublicKeyB64": "MCowBQYDK2VwAyEA2JP7y/uR2BlDD9fc6hpHktd//KhEKDjqo4fhfnJ267s=",
    "granteeDeviceId": "rez:dev:d43a697415161bf861c5be7377cdda317bd5090be0c617fd25194ed74976a94b",
    "capabilities": ["deviceSet.publish"],
    "maxDelegationDepth": 0,
    "issuedAtMs": 1755215999000,
    "expiresAtMs": 1755302400000,
    "certId": "rez:cap:6185bef7d66a7d5c070718c104646d4ecc50de89f68d00df93837f94b6515eac",
    "signerPublicKeyB64": "MCowBQYDK2VwAyEAP/UMV9HcP6cqXuUUtfP76kSDXkPSIbbDYiKjtas596g=",
    "sig": {
      "alg": "ed25519",
      "sigB64": "RsPnDowJByM+NSNG80VT7T4WcM39+WFTdjw08d0V14OidKsIMLZ+PH9wau7JEzO1pHocrN8XmXFh91s/hHd1Ag=="
    }
  }],
  "requiredCapability": "deviceSet.publish",
  "issuedAtMs": 1755216000000,
  "expiresAtMs": 1755219600000,
  "payloadB64": "Z29sZGVuIHYyIGRlbGVnYXRlZCBwYXlsb2Fk",
  "sigB64": "Ism3pF/NkA/VidSp054TP5SzNOdc7zAGZmGkzDfk9K9kbds+IFfCvtKBJgQcIph8Y9cz2tO0nV6OaPY1VkeLBg=="
});

export const GOLDEN_DURABLE_RECORD_V2_DELEGATED_SIGNABLE_STRING = "{\"certChainCertIds\":[\"rez:cap:6185bef7d66a7d5c070718c104646d4ecc50de89f68d00df93837f94b6515eac\"],\"expiresAtMs\":1755219600000,\"issuedAtMs\":1755216000000,\"ownerPublicKeyB64\":\"MCowBQYDK2VwAyEAP/UMV9HcP6cqXuUUtfP76kSDXkPSIbbDYiKjtas596g=\",\"payloadB64\":\"Z29sZGVuIHYyIGRlbGVnYXRlZCBwYXlsb2Fk\",\"recordId\":\"golden-v2-delegated\",\"recordKind\":\"rez.device-set.v1\",\"requiredCapability\":\"deviceSet.publish\",\"signerPublicKeyB64\":\"MCowBQYDK2VwAyEA2JP7y/uR2BlDD9fc6hpHktd//KhEKDjqo4fhfnJ267s=\",\"v\":2}";

export const GOLDEN_DURABLE_RECORD_V2_DELEGATED_SLOT = "e13cd138f6beefd38d34e267b20e9b07ae2c8ad466e8be9628044f6c6b85fede";

// ── shared-keyspace pin (re-audit R7 / ADR-RELAY-IDENTITY) ──────────────────
// DhtNodeId.fromRelayKeyId is ALSO the inbox-ID hasher. This literal pins the
// inbox path's bytes independently of the relay path: if the derivation is
// ever split or canonicalized, the inbox position must keep exactly these
// bytes or route announce/resolve breaks for every existing inbox.
export const GOLDEN_INBOX_ID = "inbox:golden-vector-0001";
export const GOLDEN_INBOX_DHT_POSITION_HEX = "f07f4c84c65813911f4ae0365cb1eb2e899360a3bea8b73847ca9a682ba458cc";
