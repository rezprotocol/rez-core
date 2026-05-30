import { Hash } from "../base/util/Hash.js";
import { bytesToHex } from "../util/bytes.js";
import { bytesToBase64, base64ToBytes } from "../util/bytes.js";
import { FileManifestV1 } from "./FileManifestV1.js";
import { FileChunkV1 } from "./FileChunkV1.js";

export class FileChunker {
  static DEFAULT_CHUNK_SIZE = 65536;

  static chunk(fileBytes, { fileName, mimeType, chunkSizeBytes, text } = {}) {
    if (!(fileBytes instanceof Uint8Array) || fileBytes.length === 0) {
      throw new Error("FileChunker.chunk requires non-empty Uint8Array");
    }
    if (typeof fileName !== "string" || fileName.length === 0) {
      throw new Error("FileChunker.chunk requires non-empty fileName");
    }

    const size = chunkSizeBytes !== undefined && chunkSizeBytes !== null
      ? chunkSizeBytes
      : FileChunker.DEFAULT_CHUNK_SIZE;
    const resolvedMime = mimeType !== undefined && mimeType !== null
      ? mimeType
      : "application/octet-stream";

    const transferId = crypto.randomUUID();
    const fileHashHex = bytesToHex(Hash.sha256(fileBytes));

    const chunkCount = Math.ceil(fileBytes.length / size);
    const chunkHashesHex = [];
    const chunks = [];

    for (let i = 0; i < chunkCount; i++) {
      const start = i * size;
      const end = Math.min(start + size, fileBytes.length);
      const raw = fileBytes.subarray(start, end);
      const hashHex = bytesToHex(Hash.sha256(raw));
      chunkHashesHex.push(hashHex);

      chunks.push(new FileChunkV1({
        transferId,
        chunkIndex: i,
        dataB64: bytesToBase64(raw),
        hashHex,
      }));
    }

    const manifest = new FileManifestV1({
      transferId,
      fileName,
      mimeType: resolvedMime,
      fileSizeBytes: fileBytes.length,
      chunkSizeBytes: size,
      chunkCount,
      fileHashHex,
      chunkHashesHex,
      text: typeof text === "string" ? text : "",
    });

    return { manifest, chunks };
  }

  static reassemble(manifest, chunks) {
    if (!(manifest instanceof FileManifestV1)) {
      throw new Error("FileChunker.reassemble requires FileManifestV1 manifest");
    }
    if (!Array.isArray(chunks)) {
      throw new Error("FileChunker.reassemble requires array of FileChunkV1");
    }

    const indexed = new Array(manifest.chunkCount);
    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i];
      if (!(chunk instanceof FileChunkV1)) {
        throw new Error("FileChunker.reassemble: chunks[" + i + "] must be FileChunkV1");
      }
      if (chunk.chunkIndex < 0 || chunk.chunkIndex >= manifest.chunkCount) {
        throw new Error("FileChunker.reassemble: chunk index " + chunk.chunkIndex + " out of range");
      }
      indexed[chunk.chunkIndex] = chunk;
    }

    for (let i = 0; i < manifest.chunkCount; i++) {
      if (!indexed[i]) {
        throw new Error("FileChunker.reassemble: missing chunk at index " + i);
      }
    }

    const parts = [];
    let totalLen = 0;

    for (let i = 0; i < manifest.chunkCount; i++) {
      const chunk = indexed[i];
      const actualHash = bytesToHex(Hash.sha256(base64ToBytes(chunk.dataB64)));
      if (actualHash !== manifest.chunkHashesHex[i]) {
        throw new Error(
          "FileChunker.reassemble: chunk " + i + " hash mismatch — expected "
          + manifest.chunkHashesHex[i] + ", got " + actualHash,
        );
      }
      const raw = base64ToBytes(chunk.dataB64);
      parts.push(raw);
      totalLen += raw.length;
    }

    const output = new Uint8Array(totalLen);
    let offset = 0;
    for (let i = 0; i < parts.length; i++) {
      output.set(parts[i], offset);
      offset += parts[i].length;
    }

    const outputHash = bytesToHex(Hash.sha256(output));
    if (outputHash !== manifest.fileHashHex) {
      throw new Error(
        "FileChunker.reassemble: file hash mismatch — expected "
        + manifest.fileHashHex + ", got " + outputHash,
      );
    }

    return output;
  }
}
