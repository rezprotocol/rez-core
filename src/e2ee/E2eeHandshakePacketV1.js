import { RSerializable } from "../base/RSerializable.js";

/**
 * Required fields in the handshake data object.
 * If you can construct this record, all required fields are present and valid.
 *
 * Wire-type was bumped to `x3dh.handshake.v2` when the schema gained an
 * identity-bound signature (see docs/SECURITY_AUDIT.md CRITICAL-1). The
 * previous schema is unsupported — the receiver MUST reject v1 packets.
 */
const REQUIRED_HANDSHAKE_FIELDS = [
  "inviteId",
  "senderIdentitySigningPubKeyB64",
  "senderIdentityDhPubKeyB64",
  "senderIdentityDhSignatureB64",
  "ackNonce",
  "ephemeralPublicKeyB64",
  "initiatorDhPublicKeyB64",
];

const HANDSHAKE_TYPE = "x3dh.handshake.v2";

/**
 * Validated record for an E2EE handshake control message on the wire.
 *
 * Wire JSON shape:
 *   { "e2ee": 1, "type": "x3dh.handshake.v2", "signatureB64": "...", "handshake": { ... } }
 *
 * The top-level `signatureB64` is an Ed25519 signature over the canonical-JSON
 * bytes of `handshake`, produced by the private key matching
 * `handshake.senderIdentitySigningPubKeyB64`. The constructor validates shape
 * only — signature verification is a separate, crypto-dependent step (see
 * `verifyHandshakeEnvelope` in `handshakeSignature.js`).
 */
export class E2eeHandshakePacketV1 extends RSerializable {
  static type = "E2eeHandshakePacketV1";
  static wireType = HANDSHAKE_TYPE;

  constructor({ handshake, signatureB64 } = {}) {
    super();
    this.assert(
      handshake && typeof handshake === "object",
      "E2eeHandshakePacketV1.handshake must be object",
      { handshake },
    );
    for (const field of REQUIRED_HANDSHAKE_FIELDS) {
      this.assert(
        field in handshake,
        "E2eeHandshakePacketV1.handshake missing required field: " + field,
      );
    }
    this.assert(
      typeof handshake.senderIdentitySigningPubKeyB64 === "string" && handshake.senderIdentitySigningPubKeyB64.length > 0,
      "E2eeHandshakePacketV1.handshake.senderIdentitySigningPubKeyB64 must be non-empty string",
    );
    this.assert(
      typeof signatureB64 === "string" && signatureB64.length > 0,
      "E2eeHandshakePacketV1.signatureB64 must be non-empty string",
    );
    this.e2ee = 1;
    this.handshakeType = HANDSHAKE_TYPE;
    this.handshake = handshake;
    this.signatureB64 = signatureB64;
  }

  toJSON() {
    return { e2ee: 1, type: HANDSHAKE_TYPE, signatureB64: this.signatureB64, handshake: this.handshake };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("E2eeHandshakePacketV1.fromJSON requires object");
    }
    if (json.e2ee !== 1) {
      throw new Error("E2eeHandshakePacketV1.fromJSON: e2ee must be 1");
    }
    if (json.type !== HANDSHAKE_TYPE) {
      throw new Error("E2eeHandshakePacketV1.fromJSON: type must be " + HANDSHAKE_TYPE);
    }
    if (!json.handshake || typeof json.handshake !== "object") {
      throw new Error("E2eeHandshakePacketV1.fromJSON: handshake must be object");
    }
    if (typeof json.signatureB64 !== "string" || json.signatureB64.length === 0) {
      throw new Error("E2eeHandshakePacketV1.fromJSON: signatureB64 must be non-empty string");
    }
    return new E2eeHandshakePacketV1({ handshake: json.handshake, signatureB64: json.signatureB64 });
  }

  /** Serialize to wire bytes (UTF-8 JSON). */
  toBytes() {
    return new TextEncoder().encode(JSON.stringify(this.toJSON()));
  }

  /** Deserialize from wire bytes (UTF-8 JSON). */
  static fromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
      throw new Error("E2eeHandshakePacketV1.fromBytes requires non-empty Uint8Array");
    }
    const json = JSON.parse(new TextDecoder().decode(bytes));
    return E2eeHandshakePacketV1.fromJSON(json);
  }
}
