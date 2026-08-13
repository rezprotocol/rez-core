import test from "node:test";
import assert from "node:assert/strict";
import {
  BROWSER_ACCOUNT_SEED_LABEL,
  BROWSER_ACCOUNT_DH_SEED_LABEL,
  deriveBrowserAccountRecovery,
  generateBrowserMnemonic,
} from "../src/keystore/index.js";
import { Bip39 } from "../src/crypto/bip39.js";
import { SeedKeys } from "../src/crypto/seedDerivation.js";

test("browser recovery derives byte-identical keys to canonical desktop seed derivation", async () => {
  const mnemonic = await generateBrowserMnemonic({ words: 24 });
  const browser = await deriveBrowserAccountRecovery(mnemonic);
  const seed = await Bip39.mnemonicToSeed(mnemonic);
  try {
    assert.deepEqual(
      browser.identityKeyPair,
      SeedKeys.deriveEd25519({ seed, label: BROWSER_ACCOUNT_SEED_LABEL }),
    );
    assert.deepEqual(
      browser.accountIdentityDhKeyPair,
      SeedKeys.deriveX25519({ seed, label: BROWSER_ACCOUNT_DH_SEED_LABEL }),
    );
  } finally {
    seed.fill(0);
  }
});
