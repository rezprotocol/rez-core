export class NoSessionForPeerError extends Error {
  constructor(peerId) {
    super(`No session for peerId: ${peerId}`);
    this.name = "NoSessionForPeerError";
    this.peerId = peerId;
  }
}

export class UnknownSessionError extends Error {
  constructor(sidHex) {
    super(`Unknown session for sid: ${sidHex}`);
    this.name = "UnknownSessionError";
    this.sidHex = sidHex;
  }
}
