import { RCodec } from "../../base/index.js";
import { Envelope } from "../../objects/Envelope.js";
import { OnionPacketV2 } from "../../objects/onion/OnionPacketV2.js";
import { OnionLayerAeadV2 } from "../../crypto/onion/OnionLayerAeadV2.js";
import { parseOnionLayerV2 } from "./parseOnionLayerV2.js";
import { parseOnionPlaintextV2 } from "./parseOnionPlaintextV2.js";
import { RCryptoProvider } from "../../crypto/RCryptoProvider.js";
import { OnionKeyringV1 } from "../../services/relay/OnionKeyringV1.js";
import { base64ToBytes, bytesToHex } from "../../util/bytes.js";

function toBytes(value, label) {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return new Uint8Array(value);
  if (typeof value === "string") return base64ToBytes(value);
  throw new Error(`OnionPeelCodecV2.${label} must be Uint8Array`);
}

export class OnionPeelCodecV2 extends RCodec {
  constructor({ crypto, replayCache } = {}) {
    super();
    if (!(crypto instanceof RCryptoProvider)) {
      throw new Error("OnionPeelCodecV2 requires crypto (RCryptoProvider)");
    }
    this.crypto = crypto;
    this.layer = new OnionLayerAeadV2({ crypto });
    this.replayCache = replayCache || null;
  }

  async decode(ctx) {
    if (!ctx || typeof ctx !== "object") {
      throw new Error("OnionPeelCodecV2.decode(ctx) requires object");
    }
    if (!(ctx.envelope instanceof Envelope)) {
      throw new Error("OnionPeelCodecV2.decode requires ctx.envelope (Envelope)");
    }
    if (ctx.envelope.header.type !== "rez.onion.v2") {
      throw new Error("OnionPeelCodecV2.decode requires rez.onion.v2 envelope");
    }

    const onion = ctx.meta && ctx.meta.onion;
    if (!onion) {
      throw new Error("OnionPeelCodecV2.decode requires ctx.meta.onion");
    }
    const keyResolver = onion.keyResolver;
    const keyring = onion.keyring;
    const nowMs = Number.isFinite(ctx.meta && ctx.meta.nowMs) ? ctx.meta.nowMs : Date.now();
    if (typeof keyResolver !== "function" && !(keyring instanceof OnionKeyringV1)) {
      throw new Error("OnionPeelCodecV2.decode requires keyResolver or keyring");
    }

    const packet = ctx.envelope.body instanceof OnionPacketV2
      ? ctx.envelope.body
      : OnionPacketV2.fromJSON(ctx.envelope.body);

    const payloadBytes = packet.payload;
    const packetIdHex = bytesToHex(await this.crypto.hashSha256(payloadBytes));

    const cipherObj = parseOnionLayerV2(payloadBytes);
    if (cipherObj.v !== 2) {
      throw new Error("OnionPeelCodecV2.decode requires cipher v=2");
    }
    const hopIndex = cipherObj.hopIndex;
    if (!Number.isSafeInteger(hopIndex) || hopIndex < 0) {
      throw new Error("OnionPeelCodecV2.decode requires hopIndex >= 0");
    }
    if (Number.isInteger(onion.hopIndex) && onion.hopIndex !== hopIndex) {
      throw new Error("OnionPeelCodecV2.decode hopIndex mismatch");
    }
    const onionKeyId = cipherObj.onionKeyId;
    if (typeof onionKeyId !== "string" || onionKeyId.length === 0) {
      throw new Error("OnionPeelCodecV2.decode requires onionKeyId");
    }
    const ttl = cipherObj.ttl;
    if (!Number.isInteger(ttl) || ttl < 0) {
      throw new Error("OnionPeelCodecV2.decode requires cipher ttl >= 0");
    }

    if (this.replayCache) {
      this.replayCache.checkAndMark(packetIdHex, hopIndex, onionKeyId);
    }

    const privKeyBytes = keyring instanceof OnionKeyringV1
      ? keyring.getKeyForDecrypt(onionKeyId, nowMs)
      : keyResolver(onionKeyId);
    if (!(privKeyBytes instanceof Uint8Array)) {
      throw new Error("OnionPeelCodecV2.decode requires keyResolver to return Uint8Array");
    }

    const plaintextBytes = await this.layer.decryptLayerV2({
      relayPrivKeyBytes: privKeyBytes,
      layerObj: cipherObj,
      hopIndex,
    });

    const layerPlain = parseOnionPlaintextV2(plaintextBytes);
    if (layerPlain.v !== 2) {
      throw new Error("OnionPeelCodecV2.decode requires layer v=2");
    }
    if (layerPlain.ttl !== ttl) {
      throw new Error("OnionPeelCodecV2.decode ttl mismatch");
    }
    if (!layerPlain.next || typeof layerPlain.next !== "object") {
      throw new Error("OnionPeelCodecV2.decode requires next endpoint");
    }
    if (layerPlain.ttl <= 0) {
      throw new Error("OnionTTLExpired");
    }
    const nextTtl = layerPlain.ttl - 1;

    const innerBytes = toBytes(layerPlain.inner, "inner");
    if (innerBytes.length > packet.sizeClass) {
      throw new Error("OnionPeelCodecV2.decode inner exceeds sizeClass");
    }
    const padded = new Uint8Array(packet.sizeClass);
    padded.set(innerBytes, 0);

    ctx.bytes = padded;
    ctx.meta = {
      ...ctx.meta,
      onion: {
        ...onion,
        nextEndpoint: layerPlain.next,
        ttl: nextTtl,
        flags: layerPlain.flags,
        onionKeyId,
      },
    };
    return ctx;
  }

  encode(ctx) {
    return this.abstract("encode");
  }
}
