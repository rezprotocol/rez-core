import { RSerializable } from "../base/RSerializable.js";
import { FileManifestV1 } from "./FileManifestV1.js";

const VALID_STATES = ["pending", "receiving", "complete", "failed"];

export class FileTransferSessionV1 extends RSerializable {
  static type = "FileTransferSessionV1";

  constructor({ transferId, manifest, receivedChunks, state, createdAtMs, updatedAtMs } = {}) {
    super();

    this.assert(
      typeof transferId === "string" && transferId.length > 0,
      "FileTransferSessionV1 requires non-empty string transferId",
    );
    this.assert(
      manifest instanceof FileManifestV1,
      "FileTransferSessionV1 requires FileManifestV1 manifest",
    );
    this.assert(
      Array.isArray(receivedChunks) && receivedChunks.length === manifest.chunkCount,
      "FileTransferSessionV1 receivedChunks must be boolean[] of length chunkCount",
    );
    for (let i = 0; i < receivedChunks.length; i++) {
      this.assert(
        typeof receivedChunks[i] === "boolean",
        "FileTransferSessionV1 receivedChunks[" + i + "] must be boolean",
      );
    }
    this.assert(
      typeof state === "string" && VALID_STATES.indexOf(state) !== -1,
      "FileTransferSessionV1 state must be one of: " + VALID_STATES.join(", "),
    );
    this.assert(
      typeof createdAtMs === "number" && createdAtMs > 0,
      "FileTransferSessionV1 requires positive number createdAtMs",
    );
    this.assert(
      typeof updatedAtMs === "number" && updatedAtMs > 0,
      "FileTransferSessionV1 requires positive number updatedAtMs",
    );

    this.transferId = transferId;
    this.manifest = manifest;
    this.receivedChunks = receivedChunks.slice();
    this.state = state;
    this.createdAtMs = createdAtMs;
    this.updatedAtMs = updatedAtMs;
  }

  get receivedCount() {
    let count = 0;
    for (let i = 0; i < this.receivedChunks.length; i++) {
      if (this.receivedChunks[i]) count++;
    }
    return count;
  }

  get isComplete() {
    return this.receivedCount === this.manifest.chunkCount;
  }

  get progress() {
    if (this.manifest.chunkCount === 0) return 1;
    return this.receivedCount / this.manifest.chunkCount;
  }

  markChunkReceived(chunkIndex) {
    this.assert(
      Number.isInteger(chunkIndex) && chunkIndex >= 0 && chunkIndex < this.manifest.chunkCount,
      "FileTransferSessionV1.markChunkReceived: chunkIndex out of range",
    );
    const newChunks = this.receivedChunks.slice();
    newChunks[chunkIndex] = true;
    const allReceived = newChunks.indexOf(false) === -1;
    return new FileTransferSessionV1({
      transferId: this.transferId,
      manifest: this.manifest,
      receivedChunks: newChunks,
      state: allReceived ? "complete" : "receiving",
      createdAtMs: this.createdAtMs,
      updatedAtMs: Date.now(),
    });
  }

  toJSON() {
    return {
      transferId: this.transferId,
      manifest: this.manifest.toJSON(),
      receivedChunks: this.receivedChunks.slice(),
      state: this.state,
      createdAtMs: this.createdAtMs,
      updatedAtMs: this.updatedAtMs,
    };
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("FileTransferSessionV1.fromJSON requires object");
    }
    return new FileTransferSessionV1({
      transferId: json.transferId,
      manifest: FileManifestV1.fromJSON(json.manifest),
      receivedChunks: json.receivedChunks,
      state: json.state,
      createdAtMs: json.createdAtMs,
      updatedAtMs: json.updatedAtMs,
    });
  }
}
