import { RSerializable } from "../base/RSerializable.js";

/**
 * E2EE re-handshake request — sent when ratchet state is corrupted and a
 * new session must be established between peers who already know each other.
 *
 * Contains the requestor's fresh X3DH pre-key bundle so the responder can
 * act as the X3DH initiator and establish a new session.
 *
 * Wire JSON shape:
 * {
 *   "e2ee": 1,
 *   "type": "x3dh.rehandshake.v1",
 *   "rehandshake": {
 *     "requestId": "uuid",
 *     "senderAccountId": "rez:acct:...",
 *     "senderInboxId": "inbox:...",
 *     "bundleJson": { ... serialized X3DHPreKeyBundle ... }
 *   }
 * }
 */
export class E2eeRehandshakeRequestV1 extends RSerializable {
  static type = "E2eeRehandshakeRequestV1";

  constructor({ requestId, senderAccountId, senderInboxId, bundleJson } = {}) {
    super();
    this.assert(
      typeof requestId === "string" && requestId.length > 0,
      "E2eeRehandshakeRequestV1 requires non-empty requestId",
    );
    this.assert(
      typeof senderAccountId === "string" && senderAccountId.length > 0,
      "E2eeRehandshakeRequestV1 requires non-empty senderAccountId",
    );
    this.assert(
      typeof senderInboxId === "string" && senderInboxId.length > 0,
      "E2eeRehandshakeRequestV1 requires non-empty senderInboxId",
    );
    this.assert(
      bundleJson && typeof bundleJson === "object",
      "E2eeRehandshakeRequestV1 requires bundleJson object",
    );
    this.assert(
      typeof bundleJson.receiverId === "string" && bundleJson.receiverId.length > 0,
      "E2eeRehandshakeRequestV1 bundleJson requires receiverId",
    );
    this.assert(
      typeof bundleJson.signedPreKeyPublicB64 === "string",
      "E2eeRehandshakeRequestV1 bundleJson requires signedPreKeyPublicB64",
    );

    this.e2ee = 1;
    this.type = "x3dh.rehandshake.v1";
    this.requestId = requestId;
    this.senderAccountId = senderAccountId;
    this.senderInboxId = senderInboxId;
    this.bundleJson = bundleJson;
  }

  toJSON() {
    return {
      e2ee: 1,
      type: "x3dh.rehandshake.v1",
      rehandshake: {
        requestId: this.requestId,
        senderAccountId: this.senderAccountId,
        senderInboxId: this.senderInboxId,
        bundleJson: this.bundleJson,
      },
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("E2eeRehandshakeRequestV1.fromJSON requires object");
    }
    const rh = json.rehandshake && typeof json.rehandshake === "object"
      ? json.rehandshake
      : json;
    return new E2eeRehandshakeRequestV1({
      requestId: rh.requestId,
      senderAccountId: rh.senderAccountId,
      senderInboxId: rh.senderInboxId,
      bundleJson: rh.bundleJson,
    });
  }

  toBytes() {
    return new TextEncoder().encode(JSON.stringify(this.toJSON()));
  }

  static fromBytes(bytes) {
    if (!(bytes instanceof Uint8Array)) {
      throw new Error("E2eeRehandshakeRequestV1.fromBytes requires Uint8Array");
    }
    return E2eeRehandshakeRequestV1.fromJSON(
      JSON.parse(new TextDecoder().decode(bytes)),
    );
  }
}
