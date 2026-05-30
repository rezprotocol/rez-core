import { RSerializable } from "../base/RSerializable.js";

const HEX_RE = /^[0-9a-f]{64}$/;

export class FileChunkV1 extends RSerializable {
  static type = "FileChunkV1";

  constructor({ transferId, chunkIndex, dataB64, hashHex } = {}) {
    super();

    this.assert(
      typeof transferId === "string" && transferId.length > 0,
      "FileChunkV1 requires non-empty string transferId",
    );
    this.assert(
      Number.isInteger(chunkIndex) && chunkIndex >= 0,
      "FileChunkV1 requires non-negative integer chunkIndex",
    );
    this.assert(
      typeof dataB64 === "string" && dataB64.length > 0,
      "FileChunkV1 requires non-empty string dataB64",
    );
    this.assert(
      typeof hashHex === "string" && HEX_RE.test(hashHex),
      "FileChunkV1 requires 64-char lowercase hex hashHex",
    );

    this.kind = "rez.file.chunk.v1";
    this.transferId = transferId;
    this.chunkIndex = chunkIndex;
    this.dataB64 = dataB64;
    this.hashHex = hashHex;
  }

  toJSON() {
    return {
      kind: this.kind,
      transferId: this.transferId,
      chunkIndex: this.chunkIndex,
      dataB64: this.dataB64,
      hashHex: this.hashHex,
    };
  }

  toBytes() {
    return new TextEncoder().encode(JSON.stringify(this.toJSON()));
  }

  static fromJSON(json) {
    if (!json || typeof json !== "object") {
      throw new Error("FileChunkV1.fromJSON requires object");
    }
    if (json.kind !== "rez.file.chunk.v1") {
      throw new Error("FileChunkV1.fromJSON: kind must be rez.file.chunk.v1");
    }
    return new FileChunkV1({
      transferId: json.transferId,
      chunkIndex: json.chunkIndex,
      dataB64: json.dataB64,
      hashHex: json.hashHex,
    });
  }

  static fromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
      throw new Error("FileChunkV1.fromBytes requires non-empty Uint8Array");
    }
    const json = JSON.parse(new TextDecoder().decode(bytes));
    return FileChunkV1.fromJSON(json);
  }
}
