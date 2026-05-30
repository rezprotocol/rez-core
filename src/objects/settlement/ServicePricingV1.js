import { RSerializable } from "../../base/index.js";
import { isNonEmptyString } from "../../util/strings.js";
import { PRICING_UNITS, isFinitePositive } from "../../util/settlement.js";

export class ServicePricingV1 extends RSerializable {
  static type = "ServicePricingV1";

  constructor({
    v = 1,
    serviceId,
    costPerUnit,
    unit,
    currency = "REZ",
    description = "",
  } = {}) {
    super();

    this.assert(v === 1, "ServicePricingV1.v must be 1", { v });
    this.assert(isNonEmptyString(serviceId) && serviceId.length <= 128, "ServicePricingV1.serviceId must be non-empty string <= 128 chars", { serviceId });
    this.assert(isFinitePositive(costPerUnit), "ServicePricingV1.costPerUnit must be positive number", { costPerUnit });
    this.assert(PRICING_UNITS.has(unit), "ServicePricingV1.unit must be one of: " + [...PRICING_UNITS].join(", "), { unit });
    this.assert(isNonEmptyString(currency), "ServicePricingV1.currency must be non-empty string", { currency });
    this.assert(typeof description === "string", "ServicePricingV1.description must be string", { description });

    this.v = 1;
    this.serviceId = serviceId;
    this.costPerUnit = costPerUnit;
    this.unit = unit;
    this.currency = currency;
    this.description = description;
  }

  toJSON() {
    return {
      v: this.v,
      serviceId: this.serviceId,
      costPerUnit: this.costPerUnit,
      unit: this.unit,
      currency: this.currency,
      description: this.description,
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("ServicePricingV1.fromJSON(json) requires object");
    }
    return new ServicePricingV1({
      v: json.v,
      serviceId: json.serviceId,
      costPerUnit: json.costPerUnit,
      unit: json.unit,
      currency: json.currency,
      description: json.description,
    });
  }
}
