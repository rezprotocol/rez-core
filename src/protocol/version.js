/**
 * The node↔client wire contract version.
 *
 * SessionHello asserts EQUALITY against this (not ">="), so a mismatched pair is refused at the
 * handshake rather than at whichever later RPC happens to touch a changed record. Bump it whenever
 * a request/response record changes shape in a way an older peer cannot satisfy or interpret —
 * a newly REQUIRED field counts, even though an added optional one would not.
 *
 * 3 (2026-07-26) — OutboxLeaseClaimResponse gained a REQUIRED `awaitingRootSignature`. A new client
 *   against a v2 node throws on every claim (the field is absent); a v2 client against a new node
 *   silently reads awaiting-root as "nothing pending" and never learns why its revocations are not
 *   propagating. Both are refused at connect now instead. See
 *   rez-sdk/test/compat.outbox-claim-mixed-version.test.js for the measured fallback behavior.
 * 2 — prior baseline.
 */
export const CONTRACT_VERSION = 3;
