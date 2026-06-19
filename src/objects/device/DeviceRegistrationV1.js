import { RSerializable } from "../../base/index.js";
import { isNonEmptyString } from "../../util/strings.js";
import { Hash } from "../../base/util/Hash.js";
import { canonicalJSONStringify } from "../../util/canonicalize.js";

export const DEVICE_REGISTRATION_VERSION = 1;

// Domain separator (audit P2). Carried INSIDE the signed body so this record's
// signature can never be reinterpreted as some other canonicalJSONStringify-signed
// record with a structurally-compatible field set (cf. DebitReceiptV1.networkId).
export const DEVICE_REGISTRATION_PURPOSE = "rez:device-registration:v1";

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
 * alphabet) of the SPKI DER public key — the encoding the SDK signer/verifier
 * and the rez-node verifier MUST share. A different encoding yields a different
 * `deviceId` (it hashes the exact string) and a failed verify, so the encoding
 * is intrinsically pinned. Non-canonical input (whitespace, which `base64ToBytes`
 * silently strips) is rejected outright so two strings can't collide on one key.
 *
 * Signed body (everything except `sig`):
 *   { v, purpose, accountIdentityPublicKeyB64, devicePublicKeyB64, deviceId,
 *     issuedAtMs, expiresAtMs }
 * sig = Ed25519 over canonicalJSONStringify(body) by the account identity key.
 * The signing key lives inside the signed body, so verification is
 * self-contained (no external key lookup — cf. durableRecordV1). VERIFYING the
 * signature alone is NOT a trust decision: it only proves self-consistency for
 * whatever account the body claims — see verifyDeviceRegistrationV1, which
 * REQUIRES an expected account.
 *
 * Like the settlement receipts (DebitReceiptV1 et al.) this is a signed
 * value-object carrying a BINARY `sig` that needs manual JSON conversion, so it
 * extends `RSerializable` with explicit toJSON/fromJSON — deliberately NOT the
 * plain-JSON `RRecord` bus/WS-contract pattern (RRecord's auto-toJSON cannot
 * serialize the Uint8Array signature).
 */
export class DeviceRegistrationV1 extends RSerializable {
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

    this.assert(v === DEVICE_REGISTRATION_VERSION, "DeviceRegistrationV1.v must be 1", { v });
    this.assert(purpose === DEVICE_REGISTRATION_PURPOSE, "DeviceRegistrationV1.purpose must be " + DEVICE_REGISTRATION_PURPOSE, { purpose });
    requireCanonicalB64(accountIdentityPublicKeyB64, "DeviceRegistrationV1.accountIdentityPublicKeyB64");
    requireCanonicalB64(devicePublicKeyB64, "DeviceRegistrationV1.devicePublicKeyB64");
    this.assert(isNonEmptyString(deviceId), "DeviceRegistrationV1.deviceId must be non-empty string", { deviceId });
    const expectedDeviceId = DeviceRegistrationV1.deviceIdFor(devicePublicKeyB64);
    this.assert(deviceId === expectedDeviceId, "DeviceRegistrationV1.deviceId must equal rez:dev:sha256(devicePublicKeyB64)", { deviceId, expectedDeviceId });
    this.assert(isFiniteNumber(issuedAtMs), "DeviceRegistrationV1.issuedAtMs must be number", { issuedAtMs });
    this.assert(isFiniteNumber(expiresAtMs), "DeviceRegistrationV1.expiresAtMs must be number", { expiresAtMs });
    this.assert(expiresAtMs > issuedAtMs, "DeviceRegistrationV1.expiresAtMs must be after issuedAtMs", { issuedAtMs, expiresAtMs });
    validateDeviceSig(sig);

    this.v = DEVICE_REGISTRATION_VERSION;
    this.purpose = DEVICE_REGISTRATION_PURPOSE;
    this.accountIdentityPublicKeyB64 = accountIdentityPublicKeyB64;
    this.devicePublicKeyB64 = devicePublicKeyB64;
    this.deviceId = deviceId;
    this.issuedAtMs = issuedAtMs;
    this.expiresAtMs = expiresAtMs;
    this.sig = { alg: sig.alg, sig: toSigBytes(sig.sig, "DeviceRegistrationV1.sig.sig") };
  }

  /**
   * Self-certifying device id: rez:dev:<sha256(devicePublicKeyB64)>. SSOT used
   * by the signer, the verifier, and every consumer that addresses a device.
   * Hashes the EXACT canonical key string (no trimming) — see the key-encoding
   * note above.
   */
  static deviceIdFor(devicePublicKeyB64) {
    const pub = requireCanonicalB64(devicePublicKeyB64, "DeviceRegistrationV1.deviceIdFor devicePublicKeyB64");
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

  toJSON() {
    return {
      v: this.v,
      purpose: this.purpose,
      accountIdentityPublicKeyB64: this.accountIdentityPublicKeyB64,
      devicePublicKeyB64: this.devicePublicKeyB64,
      deviceId: this.deviceId,
      issuedAtMs: this.issuedAtMs,
      expiresAtMs: this.expiresAtMs,
      sig: { alg: this.sig.alg, sig: Array.from(this.sig.sig) },
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("DeviceRegistrationV1.fromJSON(json) requires object");
    }
    return new DeviceRegistrationV1({
      v: json.v,
      purpose: json.purpose,
      accountIdentityPublicKeyB64: json.accountIdentityPublicKeyB64,
      devicePublicKeyB64: json.devicePublicKeyB64,
      deviceId: json.deviceId,
      issuedAtMs: json.issuedAtMs,
      expiresAtMs: json.expiresAtMs,
      sig: json.sig,
    });
  }
}

const CANONICAL_B64 = /^[A-Za-z0-9+/]+={0,2}$/;

function requireCanonicalB64(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(label + " must be a non-empty canonical base64 string");
  }
  if (!CANONICAL_B64.test(value)) {
    throw new Error(label + " must be canonical standard base64 (no whitespace)");
  }
  return value;
}

function isFiniteNumber(value) {
  return typeof value === "number" && Number.isFinite(value);
}

function toSigBytes(value, label) {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return new Uint8Array(value);
  throw new Error(label + " must be Uint8Array");
}

function validateDeviceSig(sig) {
  if (!sig || typeof sig !== "object") {
    throw new Error("DeviceRegistrationV1.sig must be an object");
  }
  if (sig.alg !== "ed25519") {
    throw new Error('DeviceRegistrationV1.sig.alg must be "ed25519"');
  }
  const bytes = sig.sig;
  const ok = (bytes instanceof Uint8Array && bytes.length > 0) || (Array.isArray(bytes) && bytes.length > 0);
  if (!ok) {
    throw new Error("DeviceRegistrationV1.sig.sig must be non-empty Uint8Array");
  }
}
