export { HandleClaimV1, HANDLE_MIN_LENGTH, HANDLE_MAX_LENGTH, HANDLE_PATTERN, DEFAULT_TTL_MS } from "./HandleClaimV1.js";
export {
  canonicalHandleProofBytes,
  signHandleOwnershipProof,
  verifyHandleOwnershipProof,
  PROOF_KINDS as HANDLE_PROOF_KINDS,
} from "./handleOwnershipProof.js";
