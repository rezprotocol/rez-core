import { RSerializable } from "../base/RSerializable.js";

const HEX_RE = /^[0-9a-f]{64}$/;

export class FileManifestV1 extends RSerializable {
  static type = "FileManifestV1";

  constructor({ transferId, fileName, mimeType, fileSizeBytes,
                chunkSizeBytes, chunkCount, fileHashHex, chunkHashesHex, text } = {}) {
    super();

    this.assert(
      typeof transferId === "string" && transferId.length > 0,
      "FileManifestV1 requires non-empty string transferId",
    );
    this.assert(
      typeof fileName === "string" && fileName.length > 0 && fileName.length <= 255,
      "FileManifestV1 requires non-empty string fileName (max 255 chars)",
    );

    const mime = mimeType !== undefined && mimeType !== null ? mimeType : "application/octet-stream";
    this.assert(
      typeof mime === "string" && mime.length > 0 && mime.length <= 255,
      "FileManifestV1 mimeType must be a non-empty string (max 255 chars)",
    );

    this.assert(
      Number.isInteger(fileSizeBytes) && fileSizeBytes > 0,
      "FileManifestV1 requires positive integer fileSizeBytes",
    );
    this.assert(
      Number.isInteger(chunkSizeBytes) && chunkSizeBytes >= 1024 && chunkSizeBytes <= 1048576,
      "FileManifestV1 requires integer chunkSizeBytes (1024..1048576)",
    );
    this.assert(
      Number.isInteger(chunkCount) && chunkCount > 0,
      "FileManifestV1 requires positive integer chunkCount",
    );
    // TRUST: chunkCount is self-asserted and drives receiver-side array
    // allocation; cap it and cross-check it against fileSizeBytes/chunkSizeBytes
    // so a peer cannot claim an enormous count to force a huge allocation, and so
    // the count/size/chunkSize triple is internally consistent.
    this.assert(
      chunkCount === Math.ceil(fileSizeBytes / chunkSizeBytes),
      "FileManifestV1 chunkCount must equal ceil(fileSizeBytes / chunkSizeBytes)",
    );
    this.assert(
      typeof fileHashHex === "string" && HEX_RE.test(fileHashHex),
      "FileManifestV1 requires 64-char lowercase hex fileHashHex",
    );
    this.assert(
      Array.isArray(chunkHashesHex) && chunkHashesHex.length === chunkCount,
      "FileManifestV1 chunkHashesHex must be array of length chunkCount",
    );
    for (let i = 0; i < chunkHashesHex.length; i++) {
      this.assert(
        typeof chunkHashesHex[i] === "string" && HEX_RE.test(chunkHashesHex[i]),
        "FileManifestV1 chunkHashesHex[" + i + "] must be 64-char lowercase hex",
      );
    }

    this.kind = "rez.file.manifest.v1";
    this.transferId = transferId;
    this.fileName = fileName;
    this.mimeType = mime;
    this.fileSizeBytes = fileSizeBytes;
    this.chunkSizeBytes = chunkSizeBytes;
    this.chunkCount = chunkCount;
    this.fileHashHex = fileHashHex;
    this.chunkHashesHex = chunkHashesHex.slice();
    this.text = typeof text === "string" ? text : "";
  }

  toJSON() {
    const json = {
      kind: this.kind,
      transferId: this.transferId,
      fileName: this.fileName,
      mimeType: this.mimeType,
      fileSizeBytes: this.fileSizeBytes,
      chunkSizeBytes: this.chunkSizeBytes,
      chunkCount: this.chunkCount,
      fileHashHex: this.fileHashHex,
      chunkHashesHex: this.chunkHashesHex.slice(),
    };
    if (this.text.length > 0) {
      json.text = this.text;
    }
    return json;
  }

  toBytes() {
    return new TextEncoder().encode(JSON.stringify(this.toJSON()));
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("FileManifestV1.fromJSON requires object");
    }
    if (json.kind !== "rez.file.manifest.v1") {
      throw new Error("FileManifestV1.fromJSON: kind must be rez.file.manifest.v1");
    }
    return new FileManifestV1({
      transferId: json.transferId,
      fileName: json.fileName,
      mimeType: json.mimeType,
      fileSizeBytes: json.fileSizeBytes,
      chunkSizeBytes: json.chunkSizeBytes,
      chunkCount: json.chunkCount,
      fileHashHex: json.fileHashHex,
      chunkHashesHex: json.chunkHashesHex,
      text: json.text,
    });
  }

  static fromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
      throw new Error("FileManifestV1.fromBytes requires non-empty Uint8Array");
    }
    const json = JSON.parse(new TextDecoder().decode(bytes));
    return FileManifestV1.fromJSON(json);
  }
}
