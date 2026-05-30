export class MemoryNetwork {
  constructor() {
    this.transports = new Map();
  }

  register(endpointId, transport) {
    this.transports.set(endpointId, transport);
  }

  unregister(endpointId) {
    this.transports.delete(endpointId);
  }

  deliver(packet) {
    const dest = this.transports.get(packet.to);
    if (!dest) return false;
    dest.deliver(packet);
    return true;
  }
}
