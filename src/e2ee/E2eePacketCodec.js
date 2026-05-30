import { E2eeEncryptedPacketV1 } from "./E2eeEncryptedPacketV1.js";
import { E2eeHandshakePacketV1 } from "./E2eeHandshakePacketV1.js";

const E2EE_MARKER = "e2ee";
const HANDSHAKE_TYPE = E2eeHandshakePacketV1.wireType;

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
   * @param {{ packetBytes: Uint8Array }} opts
   * @returns {Promise<{ plaintextBytes: Uint8Array, encrypted: boolean, peerId: string|null, handshake: object|null }>}
   */
  async decryptIncoming({ packetBytes } = {}) {
    if (!(packetBytes instanceof Uint8Array) || packetBytes.length === 0) {
      return { plaintextBytes: packetBytes || new Uint8Array(0), encrypted: false, peerId: null, handshake: null };
    }

    let decoded;
    try {
      decoded = JSON.parse(new TextDecoder().decode(packetBytes));
    } catch {
      return { plaintextBytes: packetBytes, encrypted: false, peerId: null, handshake: null };
    }

    if (!decoded || decoded[E2EE_MARKER] !== 1) {
      return { plaintextBytes: packetBytes, encrypted: false, peerId: null, handshake: null };
    }

    // Handshake control message (plaintext)
    if (decoded.type === HANDSHAKE_TYPE) {
      const record = E2eeHandshakePacketV1.fromJSON(decoded);
      return {
        plaintextBytes: packetBytes,
        encrypted: false,
        peerId: null,
        handshake: record.handshake,
      };
    }

    // Encrypted message — parse via record (validates structure)
    if (decoded.v === 1 && decoded.payload) {
      const record = E2eeEncryptedPacketV1.fromJSON(decoded);
      try {
        const result = await this.#secureChannelManager.decryptPayload(record.payloadBytes);
        if (!result) {
          return { plaintextBytes: packetBytes, encrypted: true, peerId: null, handshake: null };
        }

        return {
          plaintextBytes: result.plaintextBytes,
          encrypted: true,
          peerId: result.peerId,
          handshake: null,
        };
      } catch {
        // Decryption failed — return as-is with encrypted flag
        return { plaintextBytes: packetBytes, encrypted: true, peerId: null, handshake: null };
      }
    }

    return { plaintextBytes: packetBytes, encrypted: false, peerId: null, handshake: null };
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
