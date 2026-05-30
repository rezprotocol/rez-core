import { canonicalize } from "../../util/canonicalize.js";
import { Envelope } from "../../objects/Envelope.js";
import { Header } from "../../objects/Header.js";

const encoder = new TextEncoder();

function normalizeLinks(links) {
  if (!Array.isArray(links)) return [];
  return links.map((link) => {
    if (link && typeof link.toJSON === "function") return link.toJSON();
    return link;
  });
}

export function buildAadBytesV1({ envelopeHeader, encrypted }) {
  if (!(envelopeHeader instanceof Header)) {
    throw new Error("buildAadBytesV1 requires envelopeHeader (Header)");
  }
  if (!encrypted || typeof encrypted !== "object") {
    throw new Error("buildAadBytesV1 requires encrypted object");
  }

  const aadObj = {
    envSchemaVersion: Envelope.schemaVersion,
    header: {
      schemaVersion: Header.schemaVersion,
      id: envelopeHeader.id,
      type: envelopeHeader.type,
      createdAt: envelopeHeader.createdAt,
      links: normalizeLinks(envelopeHeader.links),
    },
    encrypted: {
      v: encrypted.v,
      suite: encrypted.suite,
      ratchetHeader: encrypted.header?.toJSON ? encrypted.header.toJSON() : encrypted.header,
    },
  };

  const canonical = canonicalize(aadObj);
  return encoder.encode(JSON.stringify(canonical));
}
