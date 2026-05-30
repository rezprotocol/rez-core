import { BRIDGE_FRAME_TYPES } from "./types.js";
import { BridgeRequest } from "./BridgeRequest.js";
import { BridgeResponse } from "./BridgeResponse.js";
import { BridgeEvent } from "./BridgeEvent.js";

export class BridgeRouter {
  #bridges = new Map();

  register(spec) {
    if (spec === null || spec === undefined || typeof spec !== "object") {
      throw new Error("BridgeRouter.register requires a spec object");
    }
    const ns = typeof spec.namespace === "string" ? spec.namespace.trim() : "";
    if (ns.length === 0) {
      throw new Error("BridgeRouter.register requires non-empty namespace");
    }
    if (this.#bridges.has(ns)) {
      throw new Error("BridgeRouter: namespace '" + ns + "' already registered");
    }
    const methods = spec.methods && typeof spec.methods === "object" ? spec.methods : {};
    const events = spec.events && typeof spec.events === "object" ? spec.events : {};

    for (const [name, methodSpec] of Object.entries(methods)) {
      if (methodSpec === null || methodSpec === undefined || typeof methodSpec !== "object") {
        throw new Error("BridgeRouter: method '" + name + "' spec must be an object");
      }
      if (typeof methodSpec.params !== "function") {
        throw new Error("BridgeRouter: method '" + name + "' missing params constructor");
      }
      if (typeof methodSpec.result !== "function") {
        throw new Error("BridgeRouter: method '" + name + "' missing result constructor");
      }
    }

    for (const [name, eventClass] of Object.entries(events)) {
      if (typeof eventClass !== "function") {
        throw new Error("BridgeRouter: event '" + name + "' must be a constructor");
      }
    }

    this.#bridges.set(ns, { namespace: ns, methods, events });
  }

  parseFrame(rawJsonString) {
    if (typeof rawJsonString !== "string") {
      throw new Error("BridgeRouter.parseFrame requires a string");
    }
    let parsed;
    try {
      parsed = JSON.parse(rawJsonString);
    } catch (err) {
      throw new Error("BridgeRouter.parseFrame: invalid JSON — " + (err && err.message ? err.message : String(err)));
    }
    if (parsed === null || parsed === undefined || typeof parsed !== "object") {
      throw new Error("BridgeRouter.parseFrame: expected object");
    }
    const frameType = typeof parsed.type === "string" ? parsed.type : "";
    if (frameType === BRIDGE_FRAME_TYPES.REQUEST) {
      return BridgeRequest.fromJSON(parsed);
    }
    if (frameType === BRIDGE_FRAME_TYPES.RESPONSE) {
      return BridgeResponse.fromJSON(parsed);
    }
    if (frameType === BRIDGE_FRAME_TYPES.EVENT) {
      return BridgeEvent.fromJSON(parsed);
    }
    throw new Error("BridgeRouter.parseFrame: unknown frame type '" + frameType + "'");
  }

  rehydrateParams(request) {
    if (request === null || request === undefined || typeof request !== "object") {
      throw new Error("BridgeRouter.rehydrateParams requires a request object");
    }
    const bridge = this.#bridges.get(request.ns);
    if (bridge === undefined) {
      throw new Error("BridgeRouter: unknown namespace '" + request.ns + "'");
    }
    const methodSpec = bridge.methods[request.method];
    if (methodSpec === undefined) {
      throw new Error("BridgeRouter: unknown method '" + request.method + "' in namespace '" + request.ns + "'");
    }
    return methodSpec.params.fromJSON(request.params);
  }

  rehydrateResult(response) {
    if (response === null || response === undefined || typeof response !== "object") {
      throw new Error("BridgeRouter.rehydrateResult requires a response object");
    }
    if (response.ok !== true) {
      throw new Error("BridgeRouter.rehydrateResult: response is not ok");
    }
    const bridge = this.#bridges.get(response.ns);
    if (bridge === undefined) {
      throw new Error("BridgeRouter: unknown namespace '" + response.ns + "'");
    }
    const methodSpec = bridge.methods[response.method];
    if (methodSpec === undefined) {
      throw new Error("BridgeRouter: unknown method '" + response.method + "' in namespace '" + response.ns + "'");
    }
    return methodSpec.result.fromJSON(response.data);
  }

  rehydrateEvent(event) {
    if (event === null || event === undefined || typeof event !== "object") {
      throw new Error("BridgeRouter.rehydrateEvent requires an event object");
    }
    const bridge = this.#bridges.get(event.ns);
    if (bridge === undefined) {
      throw new Error("BridgeRouter: unknown namespace '" + event.ns + "'");
    }
    const eventClass = bridge.events[event.event];
    if (eventClass === undefined) {
      throw new Error("BridgeRouter: unknown event '" + event.event + "' in namespace '" + event.ns + "'");
    }
    return eventClass.fromJSON(event.data);
  }

  getBridge(ns) {
    const bridge = this.#bridges.get(ns);
    if (bridge === undefined) {
      return null;
    }
    return bridge;
  }

  listNamespaces() {
    return [...this.#bridges.keys()];
  }

  getMethods(ns) {
    const bridge = this.#bridges.get(ns);
    if (bridge === undefined) {
      return [];
    }
    return Object.keys(bridge.methods);
  }

  getEvents(ns) {
    const bridge = this.#bridges.get(ns);
    if (bridge === undefined) {
      return [];
    }
    return Object.keys(bridge.events);
  }
}
