import { RSerializable } from "../base/RSerializable.js";

/**
 * Validated record for a handshake rejection (inviter → acceptor).
 *
 * The inviter's handshake responder is the single maxUses enforcement point.
 * When an acceptor's handshake cannot be honoured (the invite is used up or
 * expired), the inviter signs and deposits this reject so the acceptor can
 * authenticate it and roll back the optimistic peer-link it created at
 * `acceptInvite` time — instead of silently leaving a half-open link.
 *
 * Wire JSON shape:
 *   {
 *     "kind": "rez.peerlink.handshake.reject.v1",
 *     "reject": {
 *       "senderIdentitySigningPubKeyB64": "...",
 *       "senderAccountId": "rez:acct:...",
 *       "reason": "INVITE_USED_UP" | "INVITE_EXPIRED",
 *       "ackNonce": "...",
 *       "createdAtMs": 1234567890
 *     },
 *     "signatureB64": "..."   // Ed25519 sig by senderIdentitySigningPubKeyB64
 *                              // over the canonical-JSON of the `reject` object.
 *   }
 *
 * Authentication chain on the acceptor side mirrors the ack (closes the same
 * MED-1 forgery surface):
 *   1. Lookup peer-link by `(owner, senderAccountId)`.
 *   2. The peer-link's persisted `remoteIdentitySigningPublicKeyB64` MUST equal
 *      the reject's `senderIdentitySigningPubKeyB64`.
 *   3. The signature MUST verify against that pubkey over the canonical
 *      `reject` payload.
 *   4. The `ackNonce` MUST match the nonce the acceptor stored when sending the
 *      handshake packet — so a stale reject cannot tear down a later attempt.
 *
 * Constructor validates structural shape; signature verification is done
 * separately via `verifyHandshakeEnvelope({ handshake: reject, ... })`.
 */
export class E2eeHandshakeRejectV1 extends RSerializable {
  static type = "E2eeHandshakeRejectV1";
  static KIND = "rez.peerlink.handshake.reject.v1";

  /**
   * @param {{
   *   senderIdentitySigningPubKeyB64: string,
   *   senderAccountId: string,
   *   reason: string,
   *   ackNonce: string,
   *   createdAtMs: number,
   *   signatureB64: string,
   * }} opts
   */
  constructor({
    senderIdentitySigningPubKeyB64,
    senderAccountId,
    reason,
    ackNonce,
    createdAtMs,
    signatureB64,
  } = {}) {
    super();
    this.assert(
      typeof senderIdentitySigningPubKeyB64 === "string" && senderIdentitySigningPubKeyB64.length > 0,
      "E2eeHandshakeRejectV1 requires non-empty string senderIdentitySigningPubKeyB64",
    );
    this.assert(
      typeof senderAccountId === "string" && senderAccountId.length > 0,
      "E2eeHandshakeRejectV1 requires non-empty string senderAccountId",
    );
    this.assert(
      typeof reason === "string" && reason.length > 0,
      "E2eeHandshakeRejectV1 requires non-empty string reason",
    );
    this.assert(
      typeof ackNonce === "string" && ackNonce.length > 0,
      "E2eeHandshakeRejectV1 requires non-empty string ackNonce",
    );
    this.assert(
      Number.isFinite(Number(createdAtMs)) && Number(createdAtMs) > 0,
      "E2eeHandshakeRejectV1 requires positive numeric createdAtMs",
    );
    this.assert(
      typeof signatureB64 === "string" && signatureB64.length > 0,
      "E2eeHandshakeRejectV1 requires non-empty string signatureB64",
    );
    this.kind = E2eeHandshakeRejectV1.KIND;
    this.senderIdentitySigningPubKeyB64 = senderIdentitySigningPubKeyB64;
    this.senderAccountId = senderAccountId;
    this.reason = reason;
    this.ackNonce = ackNonce;
    this.createdAtMs = Number(createdAtMs);
    this.signatureB64 = signatureB64;
  }

  /**
   * Canonical-JSON envelope content (the part covered by the signature).
   * Stable field set; do not include `signatureB64` here.
   */
  toRejectPayload() {
    return {
      senderIdentitySigningPubKeyB64: this.senderIdentitySigningPubKeyB64,
      senderAccountId: this.senderAccountId,
      reason: this.reason,
      ackNonce: this.ackNonce,
      createdAtMs: this.createdAtMs,
    };
  }

  toJSON() {
    return {
      kind: this.kind,
      reject: this.toRejectPayload(),
      signatureB64: this.signatureB64,
    };
  }

  toBytes() {
    return new TextEncoder().encode(JSON.stringify(this.toJSON()));
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("E2eeHandshakeRejectV1.fromJSON requires object");
    }
    if (json.kind !== E2eeHandshakeRejectV1.KIND) {
      throw new Error(`E2eeHandshakeRejectV1.fromJSON: kind must be ${E2eeHandshakeRejectV1.KIND}`);
    }
    const reject = json.reject && typeof json.reject === "object" ? json.reject : null;
    if (!reject) {
      throw new Error("E2eeHandshakeRejectV1.fromJSON: missing `reject` payload");
    }
    return new E2eeHandshakeRejectV1({
      senderIdentitySigningPubKeyB64: reject.senderIdentitySigningPubKeyB64,
      senderAccountId: reject.senderAccountId,
      reason: reject.reason,
      ackNonce: reject.ackNonce,
      createdAtMs: reject.createdAtMs,
      signatureB64: json.signatureB64,
    });
  }

  static fromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
      throw new Error("E2eeHandshakeRejectV1.fromBytes requires non-empty Uint8Array");
    }
    const json = JSON.parse(new TextDecoder().decode(bytes));
    return E2eeHandshakeRejectV1.fromJSON(json);
  }
}
