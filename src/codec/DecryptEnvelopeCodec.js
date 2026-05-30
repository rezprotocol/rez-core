import { RCodec } from "../base/index.js";
import { Envelope } from "../objects/Envelope.js";
import { EncryptedEnvelopeV1, SUITE_V1 } from "../objects/encryption/EncryptedEnvelopeV1.js";
import { RatchetHeaderV1 } from "../objects/encryption/RatchetHeaderV1.js";
import { deriveAeadKeyNonceV1 } from "../crypto/aead/KdfAeadV1.js";
import { decryptAes256Gcm } from "../crypto/aead/AeadAes256Gcm.js";
import { buildAadBytesV1 } from "./encryption/buildAadBytesV1.js";
import { RatchetService } from "../services/RatchetService.js";
import { CodecChain } from "./CodecChain.js";

function isBytes(value) {
  return value instanceof Uint8Array;
}

function asEncryptedEnvelope(body) {
  if (body instanceof EncryptedEnvelopeV1) return body;
  return EncryptedEnvelopeV1.fromJSON(body);
}

export class DecryptEnvelopeCodec extends RCodec {
  constructor({ innerCodecChain, ratchetService } = {}) {
    super();

    if (!(innerCodecChain instanceof CodecChain)) {
      throw new Error("DecryptEnvelopeCodec requires innerCodecChain (CodecChain)");
    }
    if (!(ratchetService instanceof RatchetService)) {
      throw new Error("DecryptEnvelopeCodec requires ratchetService (RatchetService)");
    }

    this.innerCodecChain = innerCodecChain;
    this.ratchet = ratchetService;
  }

  async decode(ctx) {
    if (!ctx || typeof ctx !== "object") {
      throw new Error("DecryptEnvelopeCodec.decode(ctx) requires object");
    }
    if (!(ctx.envelope instanceof Envelope)) {
      throw new Error("DecryptEnvelopeCodec.decode requires ctx.envelope (Envelope)");
    }
    if (ctx.envelope.header.type !== "rez.encrypted.v1") {
      throw new Error("DecryptEnvelopeCodec.decode requires rez.encrypted.v1 envelope");
    }

    const secure = ctx.meta?.secureChannel;
    if (!secure || !isBytes(secure.sid)) {
      throw new Error("DecryptEnvelopeCodec.decode requires ctx.meta.secureChannel.sid Uint8Array");
    }
    if (!secure.ratchetState) {
      throw new Error("DecryptEnvelopeCodec.decode requires ctx.meta.secureChannel.ratchetState");
    }

    const encrypted = asEncryptedEnvelope(ctx.envelope.body);
    if (encrypted.suite !== SUITE_V1) {
      throw new Error("DecryptEnvelopeCodec.decode unsupported suite");
    }
    if (!(encrypted.header instanceof RatchetHeaderV1)) {
      throw new Error("DecryptEnvelopeCodec.decode requires RatchetHeaderV1");
    }

    const { messageKey, nextState } = await this.ratchet.deriveReceivingKeyForHeader(
      secure.ratchetState,
      encrypted.header,
      { sid: secure.sid }
    );
    const { aeadKey, nonce } = await deriveAeadKeyNonceV1(
      this.ratchet.crypto,
      messageKey,
      secure.sid,
      encrypted.header.pn,
      encrypted.header.n,
      encrypted.header.dh
    );

    const aadBytes = buildAadBytesV1({ envelopeHeader: ctx.envelope.header, encrypted });
    const innerBytes = await decryptAes256Gcm(this.ratchet.crypto, aeadKey, nonce, encrypted.ct, aadBytes);

    const innerCtx = this.innerCodecChain.decode({ bytes: innerBytes });
    ctx.envelope = innerCtx.envelope;
    ctx.meta = { ...ctx.meta, secureChannel: { ...secure, ratchetState: nextState } };
    return ctx;
  }

  encode(ctx) {
    return this.abstract("encode");
  }
}
