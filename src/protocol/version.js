/**
 * The node↔client wire contract version.
 *
 * SessionHello asserts EQUALITY against this (not ">="), so a mismatched pair is refused at the
 * handshake rather than at whichever later RPC happens to touch a changed record. Bump it whenever
 * a request/response record changes shape in a way an older peer cannot satisfy or interpret —
 * a newly REQUIRED field counts, even though an added optional one would not.
 *
 * 4 (2026-07-27) — the signed device schemas split into V1/V2 (audit #5). DeviceLinkRequestV2 and
 *   AccountDeviceMutationV2 are now the only versions produced, and a v1 device.add is refused.
 *   A record-level `v` alone would only surface a mismatch AFTER a client had already built and
 *   signed a mutation — mid-ceremony, in the device.add case. Bumping the contract version refuses
 *   the mismatched pair at session.hello instead, before anything is signed. Chosen over
 *   per-capability negotiation because this is a hard break, not a feature: there is no useful
 *   degraded mode in which an old client and a new node agree about device.add.
 * 3 (2026-07-26) — OutboxLeaseClaimResponse gained a REQUIRED `awaitingRootSignature`. A new client
 *   against a v2 node throws on every claim (the field is absent); a v2 client against a new node
 *   silently reads awaiting-root as "nothing pending" and never learns why its revocations are not
 *   propagating. Both are refused at connect now instead. See
 *   rez-sdk/test/compat.outbox-claim-mixed-version.test.js for the measured fallback behavior.
 * 2 — prior baseline.
 */
export const CONTRACT_VERSION = 4;
