export { RCryptoProvider } from "./RCryptoProvider.js";
export { RSigner } from "./RSigner.js";
export { RKeyManager } from "./RKeyManager.js";
export { RDh } from "./RDh.js";
export { RPublicKey } from "./RPublicKey.js";
export { RPrivateKey } from "./RPrivateKey.js";
export { deriveMessageKey } from "./ratchet/KdfChain.js";
export { deriveRootKey } from "./ratchet/KdfRoot.js";
export { deriveAeadKeyNonceV1 } from "./aead/KdfAeadV1.js";
export { encryptAes256Gcm, decryptAes256Gcm, AES_GCM_TAG_BITS } from "./aead/AeadAes256Gcm.js";
export { deriveSessionIdV1 } from "./sessions/deriveSessionIdV1.js";
export * from "./onion/index.js";
// NOTE: Bip39 + SeedKeys are intentionally NOT re-exported here. They depend
// on `node:crypto` and `node:util` APIs (scrypt, hkdfSync, promisify,
// PKCS#8/SPKI DER wrapping) that don't exist in the browser. The rez-chat
// renderer bundles rez-core via Vite, and a barrel re-export would cause
// `__vite-browser-external` to fail at build time. Node-side importers
// (DesktopVaultService, DesktopBackupService, tests) MUST reach the modules
// directly: `import { Bip39, SeedKeys } from "@rezprotocol/core/src/crypto/bip39.js"`
// — see crypto/bip39.js + crypto/seedDerivation.js.
