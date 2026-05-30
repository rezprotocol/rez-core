import { RSessionManager } from "./RSessionManager.js";

export function applySendSessionContext({ sessionManager, peerId, ctx }) {
  if (!(sessionManager instanceof RSessionManager)) {
    throw new Error("applySendSessionContext requires sessionManager (RSessionManager)");
  }
  if (!ctx || typeof ctx !== "object") {
    throw new Error("applySendSessionContext requires ctx object");
  }

  const send = sessionManager.getSendContext(peerId);
  ctx.meta = { ...ctx.meta, secureChannel: { sid: send.sid, ratchetState: send.ratchetState, includeDh: send.includeDh } };

  return {
    commit: (nextState, opts) => send.commit(nextState, opts),
  };
}

export function applyRecvSessionContext({ sessionManager, sid, ctx }) {
  if (!(sessionManager instanceof RSessionManager)) {
    throw new Error("applyRecvSessionContext requires sessionManager (RSessionManager)");
  }
  if (!ctx || typeof ctx !== "object") {
    throw new Error("applyRecvSessionContext requires ctx object");
  }

  const recv = sessionManager.getRecvContext(sid);
  ctx.meta = { ...ctx.meta, secureChannel: { sid, ratchetState: recv.ratchetState } };

  return {
    commit: (nextState) => recv.commit(nextState),
    peerId: recv.peerId,
  };
}
