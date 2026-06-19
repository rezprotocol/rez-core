import { RRecord } from "../../base/index.js";
import { isNonEmptyString } from "../../util/strings.js";
import { Hash } from "../../base/util/Hash.js";
import { canonicalJSONStringify } from "../../util/canonicalize.js";
import { base64ToBytes, bytesToBase64, bytesToHex } from "../../util/bytes.js";

export const DEVICE_REGISTRATION_VERSION = 1;

// Domain separator (audit P2). Carried INSIDE the signed body so this record's
// signature can never be reinterpreted as some other canonicalJSONStringify-signed
// record with a structurally-compatible field set (cf. DebitReceiptV1.networkId).
export const DEVICE_REGISTRATION_PURPOSE = "rez:device-registration:v1";

// Ed25519 public key encoded as SPKI DER is exactly 44 bytes: a fixed 12-byte
// AlgorithmIdentifier prefix + the 32-byte raw key. Pinning BOTH the length and
// the prefix (audit P2) rejects a raw-32 key, a PKCS8 private key, or any other
// key type masquerading as a device/account identity key.
const ED25519_SPKI_PREFIX_HEX = "302a300506032b6570032100";
const ED25519_SPKI_LEN = 44;
const CANONICAL_B64 = /^[A-Za-z0-9+/]+={0,2}$/;

/**
 * DeviceRegistrationV1 — the account→device authorization that anchors
 * multi-device E2EE (S2.5). The ACCOUNT identity key signs a binding that
 * vouches for an INDEPENDENT device key. Everything downstream (per-device
 * ratchet sessions, prekey bundles, the home device-inbox binding, the durable
 * cursor) keys on a device key that chains back to the account through this
 * record.
 *
 * `deviceId` is self-certifying: `rez:dev:<sha256(devicePublicKeyB64)>`. It is
 * carried INSIDE the signed body and re-derived by every verifier, so a
 * registration cannot claim a deviceId that does not match its device key.
 * This corrects the pre-S2.5 reality where `deviceId` was an unsigned,
 * client-minted random string with no key behind it.
 *
 * Key encoding (audit P2): `accountIdentityPublicKeyB64` and
 * `devicePublicKeyB64` are canonical STANDARD base64 (no whitespace, `+/`
 * alphabet) of the **44-byte Ed25519 SPKI DER** public key. The encoding is
 * enforced, not merely documented: the base64 must round-trip exactly (decode →
 * re-encode → identical, so `A=` / `abcde` / non-canonical padding are rejected)
 * AND the decoded bytes must carry the Ed25519 SPKI length + DER prefix. This is
 * the exact encoding the SDK signer/verifier and the rez-node verifier share;
 * any other encoding yields a different `deviceId` (it hashes the exact string)
 * and a failed verify.
 *
 * Signed body (everything except `sig`):
 *   { v, purpose, accountIdentityPublicKeyB64, devicePublicKeyB64, deviceId,
 *     issuedAtMs, expiresAtMs }
 * sig = Ed25519 over canonicalJSONStringify(body) by the account identity key,
 * carried as `{ alg: "ed25519", sigB64 }`. The signing key lives inside the
 * signed body, so verification is self-contained (no external key lookup — cf.
 * durableRecordV1). VERIFYING the signature alone is NOT a trust decision: it
 * only proves self-consistency for whatever account the body claims — see
 * verifyDeviceRegistrationV1, which REQUIRES an expected account.
 *
 * Record policy (audit P2): this is a proper `RRecord`. Every field is JSON-safe
 * — the signature is a base64 STRING (`sig.sigB64`), not a Uint8Array — so the
 * inherited auto-`toJSON`/`fromJSON` round-trip it with no custom binary
 * handling, satisfying the AGENTS.md requirement that new structured/wire
 * payloads be RRecord subclasses (no RSerializable carve-out).
 */
export class DeviceRegistrationV1 extends RRecord {
  static type = "DeviceRegistrationV1";

  constructor({
    v = DEVICE_REGISTRATION_VERSION,
    purpose = DEVICE_REGISTRATION_PURPOSE,
    accountIdentityPublicKeyB64,
    devicePublicKeyB64,
    deviceId,
    issuedAtMs,
    expiresAtMs,
    sig,
  } = {}) {
    super();
    this.v = v;
    this.purpose = purpose;
    this.accountIdentityPublicKeyB64 = accountIdentityPublicKeyB64;
    this.devicePublicKeyB64 = devicePublicKeyB64;
    this.deviceId = deviceId;
    this.issuedAtMs = issuedAtMs;
    this.expiresAtMs = expiresAtMs;
    this.sig = normalizeSig(sig);
    this._seal();
  }

  validate() {
    this.assert(this.v === DEVICE_REGISTRATION_VERSION, "DeviceRegistrationV1.v must be 1", { v: this.v });
    this.assert(this.purpose === DEVICE_REGISTRATION_PURPOSE, "DeviceRegistrationV1.purpose must be " + DEVICE_REGISTRATION_PURPOSE, { purpose: this.purpose });
    requireCanonicalSpkiB64(this.accountIdentityPublicKeyB64, "DeviceRegistrationV1.accountIdentityPublicKeyB64");
    requireCanonicalSpkiB64(this.devicePublicKeyB64, "DeviceRegistrationV1.devicePublicKeyB64");
    this.assert(isNonEmptyString(this.deviceId), "DeviceRegistrationV1.deviceId must be non-empty string", { deviceId: this.deviceId });
    const expectedDeviceId = DeviceRegistrationV1.deviceIdFor(this.devicePublicKeyB64);
    this.assert(this.deviceId === expectedDeviceId, "DeviceRegistrationV1.deviceId must equal rez:dev:sha256(devicePublicKeyB64)", { deviceId: this.deviceId, expectedDeviceId });
    this.assert(isFiniteNumber(this.issuedAtMs), "DeviceRegistrationV1.issuedAtMs must be number", { issuedAtMs: this.issuedAtMs });
    this.assert(isFiniteNumber(this.expiresAtMs), "DeviceRegistrationV1.expiresAtMs must be number", { expiresAtMs: this.expiresAtMs });
    this.assert(this.expiresAtMs > this.issuedAtMs, "DeviceRegistrationV1.expiresAtMs must be after issuedAtMs", { issuedAtMs: this.issuedAtMs, expiresAtMs: this.expiresAtMs });
    validateDeviceSig(this.sig);
  }

  /**
   * Self-certifying device id: rez:dev:<sha256(devicePublicKeyB64)>. SSOT used
   * by the signer, the verifier, and every consumer that addresses a device.
   * Hashes the EXACT canonical SPKI key string (no trimming) — see the
   * key-encoding note above.
   */
  static deviceIdFor(devicePublicKeyB64) {
    const pub = requireCanonicalSpkiB64(devicePublicKeyB64, "DeviceRegistrationV1.deviceIdFor devicePublicKeyB64");
    return "rez:dev:" + Hash.sha256Hex(pub);
  }

  /**
   * The exact bytes the account identity key signs and every verifier
   * recomputes — the signed body minus `sig`. Deterministic via canonical JSON.
   */
  static signableBytes({ v, purpose, accountIdentityPublicKeyB64, devicePublicKeyB64, deviceId, issuedAtMs, expiresAtMs } = {}) {
    const body = {
      v,
      purpose,
      accountIdentityPublicKeyB64,
      devicePublicKeyB64,
      deviceId,
      issuedAtMs,
      expiresAtMs,
    };
    return new TextEncoder().encode(canonicalJSONStringify(body));
  }
}

// Accept the canonical `{ alg, sigB64 }` shape. Tolerate a missing/!object sig
// here (validate() asserts it) so the constructor can assign a stable shape.
function normalizeSig(sig) {
  if (!sig || typeof sig !== "object") return sig;
  return { alg: sig.alg, sigB64: sig.sigB64 };
}

function requireCanonicalSpkiB64(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(label + " must be a non-empty canonical base64 string");
  }
  if (!CANONICAL_B64.test(value)) {
    throw new Error(label + " must be canonical standard base64 (no whitespace)");
  }
  let bytes;
  try {
    bytes = base64ToBytes(value);
  } catch (err) {
    throw new Error(label + " is not decodable base64: " + (err && err.message ? err.message : "unknown"));
  }
  // Canonical round-trip: decode then re-encode must reproduce the input exactly.
  // Rejects non-canonical strings that base64ToBytes tolerates (stray padding,
  // unused trailing bits) which would hash to a different deviceId than the key.
  if (bytesToBase64(bytes) !== value) {
    throw new Error(label + " must be canonical base64 (round-trip mismatch)");
  }
  if (bytes.length !== ED25519_SPKI_LEN) {
    throw new Error(label + " must be a 44-byte Ed25519 SPKI DER public key, got " + bytes.length + " bytes");
  }
  if (bytesToHex(bytes.subarray(0, 12)) !== ED25519_SPKI_PREFIX_HEX) {
    throw new Error(label + " must carry the Ed25519 SPKI DER prefix");
  }
  return value;
}

function isFiniteNumber(value) {
  return typeof value === "number" && Number.isFinite(value);
}

function validateDeviceSig(sig) {
  if (!sig || typeof sig !== "object") {
    throw new Error("DeviceRegistrationV1.sig must be an object");
  }
  if (sig.alg !== "ed25519") {
    throw new Error('DeviceRegistrationV1.sig.alg must be "ed25519"');
  }
  if (typeof sig.sigB64 !== "string" || sig.sigB64.length === 0 || !CANONICAL_B64.test(sig.sigB64)) {
    throw new Error("DeviceRegistrationV1.sig.sigB64 must be a non-empty canonical base64 string");
  }
}
