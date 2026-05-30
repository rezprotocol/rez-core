import { RAbstract } from "../base/index.js";

/**
 * Abstract pricing resolver for relay services.
 *
 * Concrete implementations:
 *   ConfigPricingResolver      — reads fixed prices from relay config (rez-node)
 *   GovernancePricingResolver  — enforces on-chain price floors (rez-node, future)
 *
 * Relay operators set their own prices via config. The resolver
 * determines the cost for a given service request.
 */
export class PricingResolver extends RAbstract {
  static type = "PricingResolver";

  /**
   * Resolve the price for a service request.
   * @param {string} serviceId — e.g. "handle.register", "mailbox.persistent"
   * @param {object} params — service-specific parameters (size, duration, etc.)
   * @returns {{cost: number, currency: string, breakdown: object}}
   */
  resolve(_serviceId, _params) {
    return this.abstract("resolve");
  }

  /**
   * List all services and their prices.
   * @returns {ServicePricingV1[]}
   */
  listServices() {
    return this.abstract("listServices");
  }
}
