import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const SRC = path.resolve("src");

function walk(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.isFile() && full.endsWith(".js")) out.push(full);
  }
  return out;
}

function hasPathSegment(p, segment) {
  const norm = p.replace(/\\/g, "/");
  return norm.split("/").includes(segment);
}

test("rez-core must not contain app-domain folders (chat, ui, app)", () => {
  const bannedSegments = ["chat", "ui", "apps", "app"];
  const files = walk(SRC);
  const violations = files
    .filter((f) => bannedSegments.some((seg) => hasPathSegment(f, seg)))
    .map((f) => path.relative(SRC, f));

  assert.deepEqual(
    violations,
    [],
    `rez-core contains app-domain path segments:\n${violations.join("\n")}`
  );
});
