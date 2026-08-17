import { E2eeEncryptedPacketV1 } from "./E2eeEncryptedPacketV1.js";
import { E2eeHandshakePacketV1 } from "./E2eeHandshakePacketV1.js";
import { parseUntrustedJson, UNSAFE_JSON_KEY } from "../util/safeJson.js";

const E2EE_MARKER = "e2ee";
const HANDSHAKE_TYPE = E2eeHandshakePacketV1.wireType;

/**
 * Every non-handshake exit from `decryptIncoming`. Written once so the result
 * shape cannot drift between the seven of them — the drift that produced CORE-4
 * was one branch quietly returning a different set of fields from the others.
 */
function _nonHandshake(plaintextBytes, encrypted) {
  return { plaintextBytes, encrypted, peerId: null, handshake: null, handshakeSignatureB64: null };
}

/**
 * Packet-level encrypt/decrypt codec using validated record types.
 *
 * All methods operate on Uint8Array (bytes) and return validated records
 * or structured result objects. No stringly-typed packetB64 anywhere.
 *
 * Encrypted packets: E2eeEncryptedPacketV1
 * Handshake packets: E2eeHandshakePacketV1
 */
export class E2eePacketCodec {
  #secureChannelManager;

  constructor({ secureChannelManager } = {}) {
    if (!secureChannelManager) {
      throw new Error("E2eePacketCodec requires secureChannelManager");
    }
    this.#secureChannelManager = secureChannelManager;
  }

  /**
   * Encrypt plaintext bytes for a peer. Returns an E2eeEncryptedPacketV1 record.
   * Throws if no session exists (no silent fallback to plaintext).
   *
   * @param {{ peerId: string, plaintextBytes: Uint8Array }} opts
   * @returns {Promise<E2eeEncryptedPacketV1>}
   */
  async encryptForPeer({ peerId, plaintextBytes } = {}) {
    if (!peerId || typeof peerId !== "string") {
      throw new Error("encryptForPeer requires peerId string");
    }
    if (!(plaintextBytes instanceof Uint8Array) || plaintextBytes.length === 0) {
      throw new Error("encryptForPeer requires non-empty plaintextBytes Uint8Array");
    }

    if (!this.#secureChannelManager.hasSession(peerId)) {
      const err = new Error("No E2EE session for peer: " + peerId);
      err.code = "NO_SESSION";
      throw err;
    }

    const encryptedBytes = await this.#secureChannelManager.encryptPayload(peerId, plaintextBytes);
    return new E2eeEncryptedPacketV1({ payloadBytes: encryptedBytes });
  }

  /**
   * Decrypt incoming packet bytes. Detects encrypted vs plaintext automatically.
   * Uses validated record types for parsing.
   *
   * A handshake result carries BOTH halves of the envelope (CORE-4). The
   * signature is not decoration: it is the only thing binding the handshake to
   * `handshake.senderIdentitySigningPubKeyB64`, so a result that returned the
   * handshake alone offered callers an unverifiable object and no way to notice
   * — the shape invited the unsafe half of the split. `handshakeSignatureB64`
   * is non-null exactly when `handshake` is; pass both to
   * `verifyHandshakeEnvelope`.
   *
   * @param {{ packetBytes: Uint8Array }} opts
   * @returns {Promise<{ plaintextBytes: Uint8Array, encrypted: boolean, peerId: string|null, handshake: object|null, handshakeSignatureB64: string|null }>}
   */
  async decryptIncoming({ packetBytes } = {}) {
    if (!(packetBytes instanceof Uint8Array) || packetBytes.length === 0) {
      return _nonHandshake(packetBytes || new Uint8Array(0), false);
    }

    let decoded;
    try {
      decoded = parseUntrustedJson(new TextDecoder().decode(packetBytes), "e2ee packet");
    } catch (err) {
      // A packet that is not JSON is plaintext, and this codec's whole job is to
      // tell those apart. A packet that IS JSON but carries a prototype-poisoning
      // key is neither — it is hostile, and must not be handed onward as
      // "plaintext" for the app layer to parse a second time.
      if (err && err.code === UNSAFE_JSON_KEY) throw err;
      return _nonHandshake(packetBytes, false);
    }

    if (!decoded || decoded[E2EE_MARKER] !== 1) {
      return _nonHandshake(packetBytes, false);
    }

    // Handshake control message (plaintext)
    if (decoded.type === HANDSHAKE_TYPE) {
      const record = E2eeHandshakePacketV1.fromJSON(decoded);
      return {
        plaintextBytes: packetBytes,
        encrypted: false,
        peerId: null,
        handshake: record.handshake,
        handshakeSignatureB64: record.signatureB64,
      };
    }

    // Encrypted message — parse via record (validates structure)
    if (decoded.v === 1 && decoded.payload) {
      const record = E2eeEncryptedPacketV1.fromJSON(decoded);
      try {
        const result = await this.#secureChannelManager.decryptPayload(record.payloadBytes);
        if (!result) {
          return _nonHandshake(packetBytes, true);
        }

        return {
          plaintextBytes: result.plaintextBytes,
          encrypted: true,
          peerId: result.peerId,
          handshake: null,
          handshakeSignatureB64: null,
        };
      } catch {
        // Decryption failed — return as-is with encrypted flag
        return _nonHandshake(packetBytes, true);
      }
    }

    return _nonHandshake(packetBytes, false);
  }

  /**
   * Check if packet bytes contain an encrypted payload (without decrypting).
   * @param {Uint8Array} packetBytes
   * @returns {boolean}
   */
  isEncryptedPacket(packetBytes) {
    if (!(packetBytes instanceof Uint8Array) || packetBytes.length === 0) return false;
    try {
      const decoded = JSON.parse(new TextDecoder().decode(packetBytes));
      return decoded && decoded[E2EE_MARKER] === 1;
    } catch {
      return false;
    }
  }

  /**
   * Create a handshake control message as an E2eeHandshakePacketV1 record.
   *
   * `signatureB64` is required: it is the Ed25519 signature over canonical
   * `handshakeData` produced by the private key matching
   * `handshakeData.senderIdentitySigningPubKeyB64`. Use `signHandshakeEnvelope`
   * from `handshakeSignature.js` to produce it.
   *
   * @param {{ handshakeData: object, signatureB64: string }} opts
   * @returns {E2eeHandshakePacketV1}
   */
  static createHandshakePacket({ handshakeData, signatureB64 } = {}) {
    return new E2eeHandshakePacketV1({ handshake: handshakeData, signatureB64 });
  }
}
