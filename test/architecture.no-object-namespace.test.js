import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as core from "../src/index.js";

// CORE-3. CAPABILITY_MODEL.md §9 records that the `object:` namespace "is
// removed wholesale ... preserved in memory for a future correctly-shaped
// rebuild". The authorization half was indeed gone; the storage half was still
// re-exported from the package barrel, so the surface the canonical spec called
// removed was in fact rez-core's public API.
//
// The module is now deleted, not merely unexported. Three checks rather than
// one, because each would survive the others failing: the export could come
// back without the files, the files could come back without the export, and an
// internal importer could appear without either being noticed. Prose cannot
// hold any of that shut — one `export *` line put it back last time.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CORE_ROOT = path.resolve(__dirname, "..");

test("CORE-3: the object-store surface is not part of rez-core's public API", () => {
  assert.equal(
    Object.prototype.hasOwnProperty.call(core, "RObjectStore"),
    false,
    "RObjectStore is re-exported from the package barrel again. The capability "
    + "model says the object namespace is removed; exporting its storage half "
    + "invites a future caller to bind authorization to semantics that no longer "
    + "exist. See docs/CAPABILITY_MODEL.md §9.",
  );
});

test("CORE-3: the object-store module is gone from the tree", () => {
  assert.equal(
    fs.existsSync(path.join(CORE_ROOT, "src", "objectstore")),
    false,
    "src/objectstore/ is back. The capability model says this namespace is removed "
    + "wholesale; a dead module with passing tests looks maintained and invites a "
    + "caller. If it is being rebuilt, rebuild the capability semantics with it.",
  );
});

test("CORE-3: nothing inside src/ imports the object-store module", () => {
  // Deleting the files is not the same as nobody reaching for the name — a
  // re-added module with a live importer is the state this actually guards.
  const violations = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile() && full.endsWith(".js")) {
        const text = fs.readFileSync(full, "utf8");
        if (/from\s+["'][^"']*objectstore/.test(text)) {
          violations.push(path.relative(CORE_ROOT, full));
        }
      }
    }
  };
  walk(path.join(CORE_ROOT, "src"));
  assert.deepEqual(violations, [], "live importer(s) of the dead object-store surface:\n" + violations.join("\n"));
});
