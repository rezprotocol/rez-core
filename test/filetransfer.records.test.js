import test from "node:test";
import assert from "node:assert/strict";

import { FileManifestV1 } from "../src/filetransfer/FileManifestV1.js";
import { FileChunkV1 } from "../src/filetransfer/FileChunkV1.js";
import { FileTransferSessionV1 } from "../src/filetransfer/FileTransferSessionV1.js";

const HASH_64 = "a".repeat(64);
const HASH_64_B = "b".repeat(64);

function validManifestOpts(overrides) {
  return {
    transferId: "xfer-001",
    fileName: "photo.jpg",
    mimeType: "image/jpeg",
    fileSizeBytes: 2048,
    chunkSizeBytes: 1024,
    chunkCount: 2,
    fileHashHex: HASH_64,
    chunkHashesHex: [HASH_64, HASH_64_B],
    ...overrides,
  };
}

// --- FileManifestV1 ---

test("FileManifestV1 — construct with valid fields", () => {
  const m = new FileManifestV1(validManifestOpts());
  assert.equal(m.kind, "rez.file.manifest.v1");
  assert.equal(m.transferId, "xfer-001");
  assert.equal(m.fileName, "photo.jpg");
  assert.equal(m.mimeType, "image/jpeg");
  assert.equal(m.fileSizeBytes, 2048);
  assert.equal(m.chunkSizeBytes, 1024);
  assert.equal(m.chunkCount, 2);
  assert.equal(m.fileHashHex, HASH_64);
  assert.deepEqual(m.chunkHashesHex, [HASH_64, HASH_64_B]);
});

test("FileManifestV1 — default mimeType", () => {
  const m = new FileManifestV1(validManifestOpts({ mimeType: undefined }));
  assert.equal(m.mimeType, "application/octet-stream");
});

test("FileManifestV1 — rejects empty transferId", () => {
  assert.throws(() => new FileManifestV1(validManifestOpts({ transferId: "" })), /transferId/);
});

test("FileManifestV1 — rejects fileName over 255 chars", () => {
  assert.throws(
    () => new FileManifestV1(validManifestOpts({ fileName: "x".repeat(256) })),
    /fileName/,
  );
});

test("FileManifestV1 — rejects non-positive fileSizeBytes", () => {
  assert.throws(() => new FileManifestV1(validManifestOpts({ fileSizeBytes: 0 })), /fileSizeBytes/);
});

test("FileManifestV1 — rejects chunkSizeBytes below 1024", () => {
  assert.throws(
    () => new FileManifestV1(validManifestOpts({ chunkSizeBytes: 512 })),
    /chunkSizeBytes/,
  );
});

test("FileManifestV1 — rejects chunkSizeBytes above 1048576", () => {
  assert.throws(
    () => new FileManifestV1(validManifestOpts({ chunkSizeBytes: 2000000 })),
    /chunkSizeBytes/,
  );
});

test("FileManifestV1 — rejects mismatched chunkHashesHex length", () => {
  assert.throws(
    () => new FileManifestV1(validManifestOpts({ chunkHashesHex: [HASH_64] })),
    /chunkHashesHex/,
  );
});

test("FileManifestV1 — rejects bad hex in fileHashHex", () => {
  assert.throws(
    () => new FileManifestV1(validManifestOpts({ fileHashHex: "xyz" })),
    /fileHashHex/,
  );
});

test("FileManifestV1 — toJSON/fromJSON roundtrip", () => {
  const m = new FileManifestV1(validManifestOpts());
  const json = m.toJSON();
  const m2 = FileManifestV1.fromJSON(json);
  assert.deepEqual(m2.toJSON(), json);
});

test("FileManifestV1 — toBytes/fromBytes roundtrip", () => {
  const m = new FileManifestV1(validManifestOpts());
  const bytes = m.toBytes();
  assert.ok(bytes instanceof Uint8Array);
  const m2 = FileManifestV1.fromBytes(bytes);
  assert.deepEqual(m2.toJSON(), m.toJSON());
});

test("FileManifestV1 — fromJSON rejects wrong kind", () => {
  assert.throws(
    () => FileManifestV1.fromJSON({ kind: "wrong" }),
    /kind/,
  );
});

test("FileManifestV1 — fromBytes rejects empty", () => {
  assert.throws(
    () => FileManifestV1.fromBytes(new Uint8Array(0)),
    /non-empty/,
  );
});

// --- FileChunkV1 ---

test("FileChunkV1 — construct with valid fields", () => {
  const c = new FileChunkV1({
    transferId: "xfer-001",
    chunkIndex: 0,
    dataB64: "AQID",
    hashHex: HASH_64,
  });
  assert.equal(c.kind, "rez.file.chunk.v1");
  assert.equal(c.transferId, "xfer-001");
  assert.equal(c.chunkIndex, 0);
  assert.equal(c.dataB64, "AQID");
  assert.equal(c.hashHex, HASH_64);
});

test("FileChunkV1 — rejects negative chunkIndex", () => {
  assert.throws(
    () => new FileChunkV1({ transferId: "x", chunkIndex: -1, dataB64: "AA==", hashHex: HASH_64 }),
    /chunkIndex/,
  );
});

test("FileChunkV1 — rejects empty dataB64", () => {
  assert.throws(
    () => new FileChunkV1({ transferId: "x", chunkIndex: 0, dataB64: "", hashHex: HASH_64 }),
    /dataB64/,
  );
});

test("FileChunkV1 — toJSON/fromJSON roundtrip", () => {
  const c = new FileChunkV1({
    transferId: "xfer-001",
    chunkIndex: 3,
    dataB64: "AQID",
    hashHex: HASH_64,
  });
  const json = c.toJSON();
  const c2 = FileChunkV1.fromJSON(json);
  assert.deepEqual(c2.toJSON(), json);
});

test("FileChunkV1 — toBytes/fromBytes roundtrip", () => {
  const c = new FileChunkV1({
    transferId: "xfer-001",
    chunkIndex: 0,
    dataB64: "AQID",
    hashHex: HASH_64,
  });
  const bytes = c.toBytes();
  const c2 = FileChunkV1.fromBytes(bytes);
  assert.deepEqual(c2.toJSON(), c.toJSON());
});

// --- FileTransferSessionV1 ---

function makeManifest() {
  return new FileManifestV1(validManifestOpts());
}

test("FileTransferSessionV1 — construct with valid fields", () => {
  const manifest = makeManifest();
  const s = new FileTransferSessionV1({
    transferId: "xfer-001",
    manifest,
    receivedChunks: [false, false],
    state: "pending",
    createdAtMs: 1000,
    updatedAtMs: 1000,
  });
  assert.equal(s.transferId, "xfer-001");
  assert.equal(s.state, "pending");
  assert.equal(s.receivedCount, 0);
  assert.equal(s.isComplete, false);
  assert.equal(s.progress, 0);
});

test("FileTransferSessionV1 — progress reflects received chunks", () => {
  const manifest = makeManifest();
  const s = new FileTransferSessionV1({
    transferId: "xfer-001",
    manifest,
    receivedChunks: [true, false],
    state: "receiving",
    createdAtMs: 1000,
    updatedAtMs: 1000,
  });
  assert.equal(s.receivedCount, 1);
  assert.equal(s.progress, 0.5);
  assert.equal(s.isComplete, false);
});

test("FileTransferSessionV1 — markChunkReceived returns new session", () => {
  const manifest = makeManifest();
  const s = new FileTransferSessionV1({
    transferId: "xfer-001",
    manifest,
    receivedChunks: [false, false],
    state: "pending",
    createdAtMs: 1000,
    updatedAtMs: 1000,
  });
  const s2 = s.markChunkReceived(0);
  assert.notEqual(s, s2);
  assert.equal(s.receivedChunks[0], false); // original unchanged
  assert.equal(s2.receivedChunks[0], true);
  assert.equal(s2.state, "receiving");
});

test("FileTransferSessionV1 — markChunkReceived last chunk sets complete", () => {
  const manifest = makeManifest();
  const s = new FileTransferSessionV1({
    transferId: "xfer-001",
    manifest,
    receivedChunks: [true, false],
    state: "receiving",
    createdAtMs: 1000,
    updatedAtMs: 1000,
  });
  const s2 = s.markChunkReceived(1);
  assert.equal(s2.state, "complete");
  assert.equal(s2.isComplete, true);
  assert.equal(s2.progress, 1);
});

test("FileTransferSessionV1 — rejects invalid state", () => {
  assert.throws(
    () => new FileTransferSessionV1({
      transferId: "xfer-001",
      manifest: makeManifest(),
      receivedChunks: [false, false],
      state: "bogus",
      createdAtMs: 1000,
      updatedAtMs: 1000,
    }),
    /state/,
  );
});

test("FileTransferSessionV1 — toJSON/fromJSON roundtrip", () => {
  const manifest = makeManifest();
  const s = new FileTransferSessionV1({
    transferId: "xfer-001",
    manifest,
    receivedChunks: [true, false],
    state: "receiving",
    createdAtMs: 1000,
    updatedAtMs: 2000,
  });
  const json = s.toJSON();
  const s2 = FileTransferSessionV1.fromJSON(json);
  assert.deepEqual(s2.toJSON(), json);
});
