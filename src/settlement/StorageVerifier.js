import { RAbstract } from "../base/index.js";

/**
 * Abstract storage verifier for challenge-response proofs.
 *
 * Concrete implementations:
 *   ChallengeResponseVerifier — SHA-256 byte-range challenges (rez-node)
 *
 * Verification logic lives in rez-core (shared by challenger and responder).
 * Networking and dispatch lives in rez-node.
 */
export class StorageVerifier extends RAbstract {
  static type = "StorageVerifier";

  /**
   * Issue a storage challenge to a target relay.
   * @param {string} targetRelayKeyId
   * @param {string} objectId
   * @returns {Promise<StorageChallengeV1>}
   */
  issueChallenge(_targetRelayKeyId, _objectId) {
    return this.abstract("issueChallenge");
  }

  /**
   * Respond to a storage challenge by producing the requested hash.
   * @param {StorageChallengeV1} challenge
   * @returns {Promise<StorageChallengeResponseV1>}
   */
  respondToChallenge(_challenge) {
    return this.abstract("respondToChallenge");
  }

  /**
   * Verify a challenge response.
   * @param {StorageChallengeV1} challenge
   * @param {StorageChallengeResponseV1} response
   * @returns {Promise<{valid: boolean, reason?: string}>}
   */
  verifyResponse(_challenge, _response) {
    return this.abstract("verifyResponse");
  }
}
