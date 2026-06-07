import { RCodec } from "../../base/index.js";
import { Envelope } from "../../objects/Envelope.js";
import { Header } from "../../objects/Header.js";
import { OnionPacketV2 } from "../../objects/onion/OnionPacketV2.js";
import { OnionLayerAeadV2 } from "../../crypto/onion/OnionLayerAeadV2.js";
import { buildFixedOnionPacketV2 } from "./buildFixedOnionPacketV2.js";
import { canonicalJSONStringify } from "../../util/canonicalize.js";
import { RCryptoProvider } from "../../crypto/RCryptoProvider.js";
import { RelayDescriptorV1 } from "../../objects/relay/RelayDescriptorV1.js";
import { selectOnionKeyForSendV1 } from "../../services/relay/selectOnionKeyForSendV1.js";
import { bytesToBase64 } from "../../util/bytes.js";

const encoder = new TextEncoder();

function isBytes(value) {
  return value instanceof Uint8Array;
}

function encodeJsonBytes(obj) {
  return encoder.encode(canonicalJSONStringify(obj));
}

export class OnionEncodeCodecV2 extends RCodec {
  constructor({ crypto } = {}) {
    super();
    if (!(crypto instanceof RCryptoProvider)) {
      throw new Error("OnionEncodeCodecV2 requires crypto (RCryptoProvider)");
    }
    this.crypto = crypto;
    this.layer = new OnionLayerAeadV2({ crypto });
  }

  async encode(ctx) {
    if (!ctx || typeof ctx !== "object") {
      throw new Error("OnionEncodeCodecV2.encode(ctx) requires object");
    }
    if (!isBytes(ctx.bytes)) {
      throw new Error("OnionEncodeCodecV2.encode requires ctx.bytes Uint8Array");
    }

    const onion = ctx.meta && ctx.meta.onion;
    const path = onion && onion.path;
    if (!Array.isArray(path) || path.length === 0) {
      throw new Error("OnionEncodeCodecV2.encode requires meta.onion.path[]");
    }

    const ttl = Number.isInteger(onion && onion.ttl) ? onion.ttl : path.length;
    if (!Number.isInteger(ttl) || ttl < 0) {
      throw new Error("OnionEncodeCodecV2.encode requires ttl >= 0");
    }
    const flags = onion && onion.flags != null ? onion.flags : { dropOnFail: true };
    const sizeClass = onion && onion.sizeClass;
    const nowMs = Number.isFinite(ctx.meta && ctx.meta.nowMs) ? ctx.meta.nowMs : Date.now();
    const finalEndpoint = onion && onion.finalEndpoint;
    if (!finalEndpoint || typeof finalEndpoint !== "object") {
      throw new Error("OnionEncodeCodecV2.encode requires meta.onion.finalEndpoint");
    }

    let blob = ctx.bytes;

    for (let i = path.length - 1; i >= 0; i -= 1) {
      const hop = path[i];
      if (!hop || typeof hop !== "object") {
        throw new Error("OnionEncodeCodecV2.encode requires path entries");
      }
      if (!hop.endpoint || typeof hop.endpoint !== "object") {
        throw new Error("OnionEncodeCodecV2.encode requires hop.endpoint");
      }
      let onionPubKeyBytes = hop.onionPubKeyBytes;
      let onionKeyId = hop.onionKeyId;
      if (hop.relayDescriptor) {
        const descriptor = hop.relayDescriptor instanceof RelayDescriptorV1
          ? hop.relayDescriptor
          : RelayDescriptorV1.fromJSON(hop.relayDescriptor, { nowMs });
        const selected = selectOnionKeyForSendV1(descriptor.onionKeys, nowMs);
        onionPubKeyBytes = selected.publicKeyBytes;
        onionKeyId = selected.onionKeyId;
      }
      if (!onionPubKeyBytes) {
        throw new Error("OnionEncodeCodecV2.encode requires hop.onionPubKeyBytes or relayDescriptor");
      }
      if (typeof onionKeyId !== "string" || onionKeyId.length === 0) {
        throw new Error("OnionEncodeCodecV2.encode requires hop.onionKeyId");
      }

      const hopTtl = Math.max(0, ttl - i);
      const next = (i + 1 < path.length) ? path[i + 1].endpoint : finalEndpoint;

      const layerPlain = {
        v: 2,
        ttl: hopTtl,
        next,
        flags,
        inner: bytesToBase64(blob),
      };

      const plaintextBytes = encodeJsonBytes(layerPlain);
      const encrypted = await this.layer.encryptLayerV2({
        relayPubKeyBytes: onionPubKeyBytes,
        plaintextBytes,
        hopIndex: i,
        ttl: hopTtl,
        onionKeyId,
      });

      const cipherObj = {
        v: 2,
        hopIndex: i,
        onionKeyId: encrypted.onionKeyId,
        ttl: hopTtl,
        ephPub: bytesToBase64(encrypted.ephPub),
        ct: bytesToBase64(encrypted.ct),
      };

      blob = encodeJsonBytes(cipherObj);
    }

    const onionPacket = buildFixedOnionPacketV2(blob, sizeClass);
    const header = new Header({
      id: ctx.meta && ctx.meta.headerId || `onion-${Date.now()}`,
      type: "rez.onion.v2",
      createdAt: ctx.meta && ctx.meta.createdAt != null ? ctx.meta.createdAt : Date.now(),
      links: ctx.meta && ctx.meta.links != null ? ctx.meta.links : [],
    });

    ctx.envelope = new Envelope({
      header,
      body: onionPacket.toJSON(),
    });
    ctx.bytes = undefined;
    return ctx;
  }

  decode(ctx) {
    return this.abstract("decode");
  }
}
