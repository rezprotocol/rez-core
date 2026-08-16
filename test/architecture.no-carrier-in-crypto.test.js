import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// DT-003 boundary guardrail (frozen delivery-transports plan, Phase 0).
// WHAT THIS ENFORCES: crypto/session modules must never learn about delivery
// carriers. The delivery-carrier layer (RDeliveryTransport, rez-sdk) sits
// AFTER E2EE sealing; a carrier identifier (email address, SMTP/IMAP host)
// appearing in these modules means the boundary leaked. This also enforces
// the plan's scope-lock non-goal: there is NO global email-address/DHT
// index — email vocabulary has no business existing in protocol code at all.
// WHAT IS DELIBERATELY NOT ENFORCED: prose in docs/, tests, and the future
// carrier adapter directory in rez-sdk (which has its own guardrail).
// See rez-core/docs/adr/ADR-DELIVERY-TRANSPORT-LAYERS.md.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CORE_ROOT = path.resolve(__dirname, "..");

const CRYPTO_DIRS = [
  "src/e2ee",
  "src/crypto",
  "src/keystore",
  "src/objects/ratchet",
];

const CARRIER_PATTERN = /smtp|imap|nodemailer|mailparser|\bpop3\b|(^|[^a-z])e-?mail/i;

function walk(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.isFile() && full.endsWith(".js")) out.push(full);
  }
  return out;
}

test("crypto/session modules contain no carrier identifiers (smtp/imap/email/...)", () => {
  const violations = [];
  for (const rel of CRYPTO_DIRS) {
    for (const file of walk(path.join(CORE_ROOT, rel))) {
      const src = fs.readFileSync(file, "utf8");
      const lines = src.split("\n");
      for (let i = 0; i < lines.length; i++) {
        if (CARRIER_PATTERN.test(lines[i])) {
          violations.push(path.relative(CORE_ROOT, file) + ":" + (i + 1) + "  " + lines[i].trim());
        }
      }
    }
  }
  assert.deepEqual(violations, [],
    "Carrier vocabulary leaked into crypto/session modules. Carriers live behind "
    + "RDeliveryTransport in rez-sdk, post-seal — crypto never learns the carrier. "
    + "See docs/adr/ADR-DELIVERY-TRANSPORT-LAYERS.md.\n" + violations.join("\n"));
});
