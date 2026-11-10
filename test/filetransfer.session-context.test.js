import test from "node:test";
import assert from "node:assert/strict";
import { FileChunker } from "../src/filetransfer/FileChunker.js";
import { FileTransferSessionV1 } from "../src/filetransfer/FileTransferSessionV1.js";

test("transfer session round-trip and receipt updates preserve authenticated context", () => {
  const { manifest } = FileChunker.chunk(new Uint8Array(2048), { fileName: "context.bin", chunkSizeBytes: 1024 });
  const session = new FileTransferSessionV1({ transferId: manifest.transferId, manifest, receivedChunks: [false, false], state: "pending", createdAtMs: 1, updatedAtMs: 1, senderAccountId: "acct:alice", contextId: "thread:one" });
  const next = FileTransferSessionV1.fromJSON(session.markChunkReceived(0).toJSON());
  assert.equal(next.senderAccountId, "acct:alice");
  assert.equal(next.contextId, "thread:one");
  assert.equal(next.receivedCount, 1);
  assert.throws(() => new FileTransferSessionV1({ ...session.toJSON(), manifest, transferId: "different" }), /must match manifest/);
  assert.throws(() => new FileTransferSessionV1({ ...session.toJSON(), manifest, contextId: null }), /requires both/);
  const legacy = session.toJSON(); delete legacy.senderAccountId; delete legacy.contextId;
  assert.equal(FileTransferSessionV1.fromJSON(legacy).senderAccountId, null, "legacy records remain readable and explicitly unbound");
});
