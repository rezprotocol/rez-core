import { RSerializable } from "../base/RSerializable.js";

/**
 * E2EE introduction request — sent to establish a brand-new session between two
 * members of the same group who never directly invited each other (so no invite
 * envelope and no prior peer link exist between them).
 *
 * Structurally identical to E2eeRehandshakeRequestV1 — it carries the sender's
 * fresh X3DH pre-key bundle so the receiver can act as the X3DH initiator and
 * establish a new session — but uses a distinct wire type so the receiver applies
 * the *co-membership* trust gate (the senders are co-members of a group) instead
 * of rehandshake's *existing-link* trust gate. No new cryptography: the same
 * X3DH/establish machinery runs on both sides.
 *
 * Wire JSON shape:
 * {
 *   "e2ee": 1,
 *   "type": "x3dh.introduce.v1",
 *   "introduction": {
 *     "introductionId": "uuid",
 *     "senderAccountId": "rez:acct:...",
 *     "senderInboxId": "inbox:...",
 *     "bundleJson": { ... serialized X3DHPreKeyBundle ... }
 *   }
 * }
 */
export class E2eeIntroductionRequestV1 extends RSerializable {
  static type = "E2eeIntroductionRequestV1";

  constructor({ introductionId, senderAccountId, senderInboxId, bundleJson } = {}) {
    super();
    this.assert(
      typeof introductionId === "string" && introductionId.length > 0,
      "E2eeIntroductionRequestV1 requires non-empty introductionId",
    );
    this.assert(
      typeof senderAccountId === "string" && senderAccountId.length > 0,
      "E2eeIntroductionRequestV1 requires non-empty senderAccountId",
    );
    this.assert(
      typeof senderInboxId === "string" && senderInboxId.length > 0,
      "E2eeIntroductionRequestV1 requires non-empty senderInboxId",
    );
    this.assert(
      bundleJson && typeof bundleJson === "object",
      "E2eeIntroductionRequestV1 requires bundleJson object",
    );
    this.assert(
      typeof bundleJson.receiverId === "string" && bundleJson.receiverId.length > 0,
      "E2eeIntroductionRequestV1 bundleJson requires receiverId",
    );
    this.assert(
      typeof bundleJson.signedPreKeyPublicB64 === "string",
      "E2eeIntroductionRequestV1 bundleJson requires signedPreKeyPublicB64",
    );

    this.e2ee = 1;
    this.type = "x3dh.introduce.v1";
    this.introductionId = introductionId;
    this.senderAccountId = senderAccountId;
    this.senderInboxId = senderInboxId;
    this.bundleJson = bundleJson;
  }

  toJSON() {
    return {
      e2ee: 1,
      type: "x3dh.introduce.v1",
      introduction: {
        introductionId: this.introductionId,
        senderAccountId: this.senderAccountId,
        senderInboxId: this.senderInboxId,
        bundleJson: this.bundleJson,
      },
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("E2eeIntroductionRequestV1.fromJSON requires object");
    }
    const intro = json.introduction && typeof json.introduction === "object"
      ? json.introduction
      : json;
    return new E2eeIntroductionRequestV1({
      introductionId: intro.introductionId,
      senderAccountId: intro.senderAccountId,
      senderInboxId: intro.senderInboxId,
      bundleJson: intro.bundleJson,
    });
  }

  toBytes() {
    return new TextEncoder().encode(JSON.stringify(this.toJSON()));
  }

  static fromBytes(bytes) {
    if (!(bytes instanceof Uint8Array)) {
      throw new Error("E2eeIntroductionRequestV1.fromBytes requires Uint8Array");
    }
    return E2eeIntroductionRequestV1.fromJSON(
      JSON.parse(new TextDecoder().decode(bytes)),
    );
  }
}
