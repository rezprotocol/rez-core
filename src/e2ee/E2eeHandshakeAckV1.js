import { RSerializable } from "../base/RSerializable.js";

/**
 * Validated record for a handshake acknowledgement (inviter → acceptor).
 *
 * Wire JSON shape (v2 — no backward compat):
 *   {
 *     "kind": "rez.peerlink.handshake.ack.v2",
 *     "ack": {
 *       "senderIdentitySigningPubKeyB64": "...",
 *       "senderAccountId": "rez:acct:...",
 *       "senderInboxId": "...",
 *       "senderDisplayName": "...",
 *       "ackNonce": "...",
 *       "createdAtMs": 1234567890
 *     },
 *     "signatureB64": "..."   // Ed25519 sig by senderIdentitySigningPubKeyB64
 *                              // over the canonical-JSON of the `ack` object.
 *   }
 *
 * Authentication chain on the acceptor side (closes MED-1):
 *   1. Lookup peer-link by `(owner, senderAccountId)`.
 *   2. Peer-link record must already carry `remoteIdentitySigningPublicKeyB64`
 *      (persisted at acceptInvite time from the inviter's signed X3DH
 *      binding). The ack's `senderIdentitySigningPubKeyB64` MUST equal it.
 *   3. The ack signature MUST verify against that pubkey over the canonical
 *      `ack` payload.
 *   4. The `ackNonce` MUST match the nonce the acceptor stored when sending
 *      the handshake packet.
 *
 * Constructor validates structural shape; signature verification is done
 * separately via `verifyHandshakeEnvelope({ handshake: ack, ... })`.
 */
export class E2eeHandshakeAckV1 extends RSerializable {
  static type = "E2eeHandshakeAckV1";
  static KIND = "rez.peerlink.handshake.ack.v2";

  /**
   * @param {{
   *   senderIdentitySigningPubKeyB64: string,
   *   senderAccountId: string,
   *   senderInboxId: string|null,
   *   senderDisplayName: string,
   *   ackNonce: string,
   *   createdAtMs: number,
   *   signatureB64: string,
   * }} opts
   */
  constructor({
    senderIdentitySigningPubKeyB64,
    senderAccountId,
    senderInboxId,
    senderDisplayName,
    ackNonce,
    createdAtMs,
    signatureB64,
  } = {}) {
    super();
    this.assert(
      typeof senderIdentitySigningPubKeyB64 === "string" && senderIdentitySigningPubKeyB64.length > 0,
      "E2eeHandshakeAckV1 requires non-empty string senderIdentitySigningPubKeyB64",
    );
    this.assert(
      typeof senderAccountId === "string" && senderAccountId.length > 0,
      "E2eeHandshakeAckV1 requires non-empty string senderAccountId",
    );
    this.assert(
      typeof senderDisplayName === "string",
      "E2eeHandshakeAckV1 requires string senderDisplayName",
    );
    this.assert(
      typeof ackNonce === "string" && ackNonce.length > 0,
      "E2eeHandshakeAckV1 requires non-empty string ackNonce",
    );
    this.assert(
      Number.isFinite(Number(createdAtMs)) && Number(createdAtMs) > 0,
      "E2eeHandshakeAckV1 requires positive numeric createdAtMs",
    );
    this.assert(
      typeof signatureB64 === "string" && signatureB64.length > 0,
      "E2eeHandshakeAckV1 requires non-empty string signatureB64",
    );
    this.kind = E2eeHandshakeAckV1.KIND;
    this.senderIdentitySigningPubKeyB64 = senderIdentitySigningPubKeyB64;
    this.senderAccountId = senderAccountId;
    this.senderInboxId = typeof senderInboxId === "string" && senderInboxId.length > 0 ? senderInboxId : null;
    this.senderDisplayName = senderDisplayName;
    this.ackNonce = ackNonce;
    this.createdAtMs = Number(createdAtMs);
    this.signatureB64 = signatureB64;
  }

  /**
   * Canonical-JSON envelope content (the part covered by the signature).
   * Stable field set; do not include `signatureB64` here.
   */
  toAckPayload() {
    return {
      senderIdentitySigningPubKeyB64: this.senderIdentitySigningPubKeyB64,
      senderAccountId: this.senderAccountId,
      senderInboxId: this.senderInboxId,
      senderDisplayName: this.senderDisplayName,
      ackNonce: this.ackNonce,
      createdAtMs: this.createdAtMs,
    };
  }

  toJSON() {
    return {
      kind: this.kind,
      ack: this.toAckPayload(),
      signatureB64: this.signatureB64,
    };
  }

  toBytes() {
    return new TextEncoder().encode(JSON.stringify(this.toJSON()));
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("E2eeHandshakeAckV1.fromJSON requires object");
    }
    if (json.kind !== E2eeHandshakeAckV1.KIND) {
      throw new Error(`E2eeHandshakeAckV1.fromJSON: kind must be ${E2eeHandshakeAckV1.KIND}`);
    }
    const ack = json.ack && typeof json.ack === "object" ? json.ack : null;
    if (!ack) {
      throw new Error("E2eeHandshakeAckV1.fromJSON: missing `ack` payload");
    }
    return new E2eeHandshakeAckV1({
      senderIdentitySigningPubKeyB64: ack.senderIdentitySigningPubKeyB64,
      senderAccountId: ack.senderAccountId,
      senderInboxId: ack.senderInboxId,
      senderDisplayName: ack.senderDisplayName,
      ackNonce: ack.ackNonce,
      createdAtMs: ack.createdAtMs,
      signatureB64: json.signatureB64,
    });
  }

  static fromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
      throw new Error("E2eeHandshakeAckV1.fromBytes requires non-empty Uint8Array");
    }
    const json = JSON.parse(new TextDecoder().decode(bytes));
    return E2eeHandshakeAckV1.fromJSON(json);
  }
}
