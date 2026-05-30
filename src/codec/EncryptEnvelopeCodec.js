import { RCodec } from "../base/index.js";
import { Header } from "../objects/Header.js";
import { Envelope } from "../objects/Envelope.js";
import { RatchetHeaderV1 } from "../objects/encryption/RatchetHeaderV1.js";
import { EncryptedEnvelopeV1, SUITE_V1 } from "../objects/encryption/EncryptedEnvelopeV1.js";
import { deriveAeadKeyNonceV1 } from "../crypto/aead/KdfAeadV1.js";
import { encryptAes256Gcm } from "../crypto/aead/AeadAes256Gcm.js";
import { buildAadBytesV1 } from "./encryption/buildAadBytesV1.js";
import { RatchetService } from "../services/RatchetService.js";
import { CodecChain } from "./CodecChain.js";

function isBytes(value) {
  return value instanceof Uint8Array;
}

export class EncryptEnvelopeCodec extends RCodec {
  constructor({ innerCodecChain, ratchetService } = {}) {
    super();

    if (!(innerCodecChain instanceof CodecChain)) {
      throw new Error("EncryptEnvelopeCodec requires innerCodecChain (CodecChain)");
    }
    if (!(ratchetService instanceof RatchetService)) {
      throw new Error("EncryptEnvelopeCodec requires ratchetService (RatchetService)");
    }

    this.innerCodecChain = innerCodecChain;
    this.ratchet = ratchetService;
  }

  async encode(ctx) {
    if (!ctx || typeof ctx !== "object") {
      throw new Error("EncryptEnvelopeCodec.encode(ctx) requires object");
    }
    if (!(ctx.envelope instanceof Envelope)) {
      throw new Error("EncryptEnvelopeCodec.encode requires ctx.envelope (Envelope)");
    }

    const secure = ctx.meta?.secureChannel;
    if (!secure || !isBytes(secure.sid)) {
      throw new Error("EncryptEnvelopeCodec.encode requires ctx.meta.secureChannel.sid Uint8Array");
    }
    if (!secure.ratchetState) {
      throw new Error("EncryptEnvelopeCodec.encode requires ctx.meta.secureChannel.ratchetState");
    }

    const innerCtx = this.innerCodecChain.encode({ envelope: ctx.envelope });
    const innerBytes = innerCtx.bytes;
    if (!isBytes(innerBytes)) {
      throw new Error("EncryptEnvelopeCodec.encode requires inner codec bytes");
    }

    const state = secure.ratchetState;
    const n = state.sendingChain?.messageIndex ?? 0;
    const pn = state.receivingChain?.messageIndex ?? 0;
    const includeDh = Boolean(secure.includeDh);
    const dh = includeDh ? state.selfDhKeyPair.publicKey : null;
    const dhAlg = this.ratchet.dhAlg;
    const dhFmt = (state.selfDhKeyPair.publicKey.length === 32) ? "raw" : "spki";

    const { messageKey, newState } = await this.ratchet.nextSendingMessageKey(state);
    const { aeadKey, nonce } = await deriveAeadKeyNonceV1(
      this.ratchet.crypto,
      messageKey,
      secure.sid,
      pn,
      n,
      dh
    );

    const header = new RatchetHeaderV1({
      v: 1,
      sid: secure.sid,
      dh,
      dhAlg,
      dhFmt,
      pn,
      n,
    });

    const encrypted = new EncryptedEnvelopeV1({
      v: 1,
      suite: SUITE_V1,
      header,
      nonce,
      ct: new Uint8Array(1),
    });

    const outerHeader = new Header({
      id: ctx.envelope.header.id,
      type: "rez.encrypted.v1",
      createdAt: ctx.envelope.header.createdAt,
      links: ctx.envelope.header.links,
    });

    const aadBytes = buildAadBytesV1({ envelopeHeader: outerHeader, encrypted });
    const ct = await encryptAes256Gcm(this.ratchet.crypto, aeadKey, nonce, innerBytes, aadBytes);

    const finalEncrypted = new EncryptedEnvelopeV1({
      v: 1,
      suite: SUITE_V1,
      header,
      nonce,
      ct,
    });

    const outerEnvelope = new Envelope({
      header: outerHeader,
      body: finalEncrypted.toJSON(),
      meta: ctx.envelope.meta,
    });

    ctx.envelope = outerEnvelope;
    ctx.meta = { ...ctx.meta, secureChannel: { ...secure, ratchetState: newState } };
    return ctx;
  }

  decode(ctx) {
    return this.abstract("decode");
  }
}
