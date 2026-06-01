import { hkdfSync, createPrivateKey, createPublicKey } from "node:crypto";

const HKDF_SALT_TEXT = "rez-v1";

// Fixed PKCS#8 DER prefix for an Ed25519 private key whose seed is the
// 32 bytes that follow. Bytes break down as:
//   30 2e               SEQUENCE, length 46
//     02 01 00          INTEGER version=0
//     30 05             SEQUENCE, length 5 (AlgorithmIdentifier)
//       06 03 2b 65 70  OID 1.3.101.112 (Ed25519)
//     04 22             OCTET STRING, length 34
//       04 20           inner OCTET STRING, length 32
//       <32 bytes>      raw seed
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

// Fixed SPKI DER prefix for an Ed25519 public key whose raw 32 bytes follow.
//   30 2a               SEQUENCE, length 42
//     30 05             SEQUENCE, length 5 (AlgorithmIdentifier)
//       06 03 2b 65 70  OID 1.3.101.112 (Ed25519)
//     03 21             BIT STRING, length 33
//       00              zero-bit padding count
//       <32 bytes>      raw public key
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/**
 * Derive subkeys + ed25519 identities from a BIP39 seed.
 *
 * The seed is the 64-byte output of Bip39.mnemonicToSeed(). We HKDF-expand
 * it under a fixed salt ("rez-v1") with a per-purpose info label, then use
 * the resulting 32 bytes as the raw private-scalar of an ed25519 keypair.
 *
 * Labels in use (extend the list — do NOT reuse a label for a different
 * purpose; that would silently couple two keys):
 *   "rez/identity/desktop-account/v1" — DesktopVaultService account identity
 *   "rez/identity/chat-server/v1"     — chat-server's signing identity
 *   "rez/backup/v1"                    — encrypted-backup KEK (used by DesktopBackupService)
 */
export class SeedKeys {
  static deriveBytes({ seed, label, length = 32 }) {
    if (!(seed instanceof Uint8Array) && !Buffer.isBuffer(seed)) {
      throw new Error("SeedKeys.deriveBytes: seed must be Uint8Array or Buffer");
    }
    if (seed.length < 32) {
      throw new Error(`SeedKeys.deriveBytes: seed must be >= 32 bytes, got ${seed.length}`);
    }
    if (typeof label !== "string" || label.length === 0) {
      throw new Error("SeedKeys.deriveBytes: label is required");
    }
    if (!Number.isInteger(length) || length <= 0 || length > 255 * 32) {
      throw new Error(`SeedKeys.deriveBytes: length ${length} is out of range`);
    }
    const salt = Buffer.from(HKDF_SALT_TEXT, "utf8");
    const info = Buffer.from(label, "utf8");
    const out = hkdfSync("sha256", seed, salt, info, length);
    // hkdfSync returns ArrayBuffer in some Node versions; normalize to Buffer.
    return Buffer.from(out);
  }

  /**
   * Derive a deterministic ed25519 keypair from a seed + label.
   *
   * Returns the same on-the-wire shape as Identity.toObject() in this codebase:
   *   - privateKeyB64 = base64-encoded PKCS#8 DER (48 bytes)
   *   - publicKeyB64  = base64-encoded SPKI    DER (44 bytes)
   *
   * This matches `await subtle.exportKey("pkcs8"|"spki", key)` so the bytes
   * drop directly into `Identity.fromObject({...})` without conversion.
   *
   * Implementation: HKDF the seed+label → 32-byte raw private seed → wrap in
   * a minimal PKCS#8 prefix → createPrivateKey(...) → createPublicKey() derives
   * the matching public point → export both to PKCS#8 / SPKI DER bytes.
   */
  static deriveEd25519({ seed, label }) {
    const rawPriv = SeedKeys.deriveBytes({ seed, label, length: 32 });
    const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, rawPriv]);
    const privKeyObj = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
    const pubKeyObj = createPublicKey(privKeyObj);
    const privPkcs8 = privKeyObj.export({ format: "der", type: "pkcs8" });
    const pubSpki = pubKeyObj.export({ format: "der", type: "spki" });
    return {
      privateKeyB64: Buffer.from(privPkcs8).toString("base64"),
      publicKeyB64: Buffer.from(pubSpki).toString("base64"),
    };
  }

  /**
   * Raw-bytes variant of deriveEd25519 — exposed for internal callers that
   * need the 32-byte private scalar directly (e.g., chat-server storage key
   * derivation, which HKDFs from the raw private bytes).
   */
  static deriveEd25519RawPrivate({ seed, label }) {
    return SeedKeys.deriveBytes({ seed, label, length: 32 });
  }
}
