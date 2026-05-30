import { RAbstract } from "../base/index.js";

/**
 * Abstract settlement provider for relay service payments.
 *
 * Concrete implementations:
 *   LocalSettlementProvider  — KV-backed ledger (rez-node)
 *   ChainSettlementProvider  — Base L2 ERC-20 contract (rez-node, future)
 *
 * All methods return signed receipt records that are verifiable
 * regardless of which backend produced them.
 */
export class SettlementProvider extends RAbstract {
  static type = "SettlementProvider";

  /**
   * Get the balance for an account.
   * @param {string} accountId
   * @returns {Promise<{available: number, escrowed: number, total: number}>}
   */
  balance(_accountId) {
    return this.abstract("balance");
  }

  /**
   * Debit an account for a service.
   * @param {string} accountId
   * @param {number} amount
   * @param {{serviceId: string, serviceRef: string}} serviceInfo
   * @returns {Promise<DebitReceiptV1>}
   */
  debit(_accountId, _amount, _serviceInfo) {
    return this.abstract("debit");
  }

  /**
   * Credit an account (relay reward, free tier allowance, etc).
   * @param {string} accountId
   * @param {number} amount
   * @param {string} reason
   * @returns {Promise<CreditReceiptV1>}
   */
  credit(_accountId, _amount, _reason) {
    return this.abstract("credit");
  }

  /**
   * Lock funds in escrow for a service commitment.
   * @param {string} accountId
   * @param {number} amount
   * @param {{commitment: string, expiresAtMs: number}} commitmentInfo
   * @returns {Promise<EscrowReceiptV1>}
   */
  escrow(_accountId, _amount, _commitmentInfo) {
    return this.abstract("escrow");
  }

  /**
   * Release escrowed funds to a recipient.
   * @param {string} escrowId
   * @param {string} recipientId
   * @returns {Promise<ReleaseReceiptV1>}
   */
  releaseEscrow(_escrowId, _recipientId) {
    return this.abstract("releaseEscrow");
  }

  /**
   * Slash escrowed funds (burned, not redistributed).
   * @param {string} escrowId
   * @param {string} reason
   * @returns {Promise<SlashReceiptV1>}
   */
  slash(_escrowId, _reason) {
    return this.abstract("slash");
  }
}
