import test from "node:test";
import assert from "node:assert/strict";

import { FileChunker } from "../src/filetransfer/FileChunker.js";
import { FileManifestV1 } from "../src/filetransfer/FileManifestV1.js";
import { FileChunkV1 } from "../src/filetransfer/FileChunkV1.js";
import { Hash } from "../src/base/util/Hash.js";
import { bytesToHex, bytesToBase64 } from "../src/util/bytes.js";

function makeBytes(len) {
  const b = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    b[i] = i % 256;
  }
  return b;
}

test("FileChunker.chunk — small file produces 1 chunk", () => {
  const data = makeBytes(500);
  const { manifest, chunks } = FileChunker.chunk(data, { fileName: "small.bin", chunkSizeBytes: 1024 });
  assert.ok(manifest instanceof FileManifestV1);
  assert.equal(manifest.chunkCount, 1);
  assert.equal(chunks.length, 1);
  assert.equal(manifest.fileSizeBytes, 500);
  assert.equal(manifest.fileName, "small.bin");
  assert.equal(manifest.mimeType, "application/octet-stream");
  assert.equal(chunks[0].chunkIndex, 0);
});

test("FileChunker.chunk — multi-chunk file", () => {
  const data = makeBytes(3000);
  const { manifest, chunks } = FileChunker.chunk(data, { fileName: "multi.bin", chunkSizeBytes: 1024 });
  assert.equal(manifest.chunkCount, 3);
  assert.equal(chunks.length, 3);
  assert.equal(manifest.chunkHashesHex.length, 3);
  // verify each chunk hash matches
  for (let i = 0; i < chunks.length; i++) {
    assert.equal(chunks[i].hashHex, manifest.chunkHashesHex[i]);
  }
});

test("FileChunker.chunk — exact chunk boundary", () => {
  const data = makeBytes(2048);
  const { manifest, chunks } = FileChunker.chunk(data, { fileName: "exact.bin", chunkSizeBytes: 1024 });
  assert.equal(manifest.chunkCount, 2);
  assert.equal(chunks.length, 2);
});

test("FileChunker.chunk — custom mimeType", () => {
  const data = makeBytes(1024);
  const { manifest } = FileChunker.chunk(data, { fileName: "img.png", mimeType: "image/png", chunkSizeBytes: 1024 });
  assert.equal(manifest.mimeType, "image/png");
});

test("FileChunker.chunk — default chunk size is 64KB", () => {
  const data = makeBytes(65536 * 2 + 100);
  const { manifest } = FileChunker.chunk(data, { fileName: "big.bin" });
  assert.equal(manifest.chunkSizeBytes, 65536);
  assert.equal(manifest.chunkCount, 3);
});

test("FileChunker.chunk — throws on empty bytes", () => {
  assert.throws(
    () => FileChunker.chunk(new Uint8Array(0), { fileName: "empty.bin" }),
    /non-empty/,
  );
});

test("FileChunker.chunk — throws on missing fileName", () => {
  assert.throws(
    () => FileChunker.chunk(makeBytes(100), {}),
    /fileName/,
  );
});

test("FileChunker — chunk then reassemble roundtrip", () => {
  const data = makeBytes(5000);
  const { manifest, chunks } = FileChunker.chunk(data, { fileName: "round.bin", chunkSizeBytes: 1024 });
  const result = FileChunker.reassemble(manifest, chunks);
  assert.deepEqual(result, data);
});

test("FileChunker — reassemble with out-of-order chunks", () => {
  const data = makeBytes(3000);
  const { manifest, chunks } = FileChunker.chunk(data, { fileName: "ooo.bin", chunkSizeBytes: 1024 });
  const shuffled = [chunks[2], chunks[0], chunks[1]];
  const result = FileChunker.reassemble(manifest, shuffled);
  assert.deepEqual(result, data);
});

test("FileChunker.reassemble — throws on missing chunk", () => {
  const data = makeBytes(3000);
  const { manifest, chunks } = FileChunker.chunk(data, { fileName: "miss.bin", chunkSizeBytes: 1024 });
  assert.throws(
    () => FileChunker.reassemble(manifest, [chunks[0], chunks[2]]),
    /missing chunk/,
  );
});

test("FileChunker.reassemble — throws on chunk hash mismatch", () => {
  const data = makeBytes(2048);
  const { manifest, chunks } = FileChunker.chunk(data, { fileName: "bad.bin", chunkSizeBytes: 1024 });
  // tamper with chunk data — fill with 0xFF to differ from makeBytes pattern
  const badData = new Uint8Array(1024);
  badData.fill(0xFF);
  const tampered = new FileChunkV1({
    transferId: chunks[0].transferId,
    chunkIndex: 0,
    dataB64: bytesToBase64(badData),
    hashHex: chunks[0].hashHex, // original hash, wrong data
  });
  assert.throws(
    () => FileChunker.reassemble(manifest, [tampered, chunks[1]]),
    /hash mismatch/,
  );
});

test("FileChunker.reassemble — throws on file hash mismatch", () => {
  const data = makeBytes(1024);
  const { manifest, chunks } = FileChunker.chunk(data, { fileName: "fhash.bin", chunkSizeBytes: 1024 });
  // create manifest with wrong file hash but correct chunk hashes
  const badManifest = new FileManifestV1({
    transferId: manifest.transferId,
    fileName: manifest.fileName,
    mimeType: manifest.mimeType,
    fileSizeBytes: manifest.fileSizeBytes,
    chunkSizeBytes: manifest.chunkSizeBytes,
    chunkCount: manifest.chunkCount,
    fileHashHex: "b".repeat(64),
    chunkHashesHex: manifest.chunkHashesHex,
  });
  assert.throws(
    () => FileChunker.reassemble(badManifest, chunks),
    /file hash mismatch/,
  );
});
