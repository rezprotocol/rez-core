import { RService } from "../base/index.js";
import { Envelope } from "../objects/Envelope.js";
import { CodecChain } from "../codec/CodecChain.js";
import { StorageProvider } from "../storage/StorageProvider.js";
import { RLogger } from "../base/index.js";
import { NullLogTransport } from "../base/index.js";
import { isNonEmptyString } from "../util/strings.js";

export class RezRuntime extends RService {
  constructor({ codecChain, storageProvider, logger } = {}) {
    const log = logger || new RLogger({ transports: [new NullLogTransport()] });
    super({ log });

    if (!(codecChain instanceof CodecChain)) {
      throw new Error("RezRuntime requires codecChain (CodecChain)");
    }
    if (!(storageProvider instanceof StorageProvider)) {
      throw new Error("RezRuntime requires storageProvider (StorageProvider)");
    }
    if (!(log instanceof RLogger)) {
      throw new Error("RezRuntime requires logger (RLogger)");
    }

    this.codecChain = codecChain;
    this.storage = storageProvider;
    this.log = log;
  }

  encodeEnvelope(envelope) {
    if (!(envelope instanceof Envelope)) {
      throw new Error("RezRuntime.encodeEnvelope(envelope) requires an Envelope");
    }
    const ctx = this.codecChain.encode({ envelope, meta: {} });
    return ctx.bytes;
  }

  decodeEnvelope(bytes) {
    if (!(bytes instanceof Uint8Array)) {
      throw new Error("RezRuntime.decodeEnvelope(bytes) requires a Uint8Array");
    }
    const ctx = this.codecChain.decode({ bytes, meta: {} });
    return ctx.envelope;
  }

  saveEnvelope(envelope) {
    if (!(envelope instanceof Envelope)) {
      throw new Error("RezRuntime.saveEnvelope(envelope) requires an Envelope");
    }
    this.storage.getObjectStore().put(envelope);
    return envelope.header.id;
  }

  loadEnvelope(id) {
    if (!isNonEmptyString(id)) {
      throw new Error("RezRuntime.loadEnvelope(id) requires a non-empty string");
    }
    return this.storage.getObjectStore().get(id);
  }

  depositToMailbox(mailboxId, envelopeId) {
    if (!isNonEmptyString(mailboxId)) {
      throw new Error("RezRuntime.depositToMailbox(mailboxId, envelopeId) requires mailboxId");
    }
    if (!isNonEmptyString(envelopeId)) {
      throw new Error("RezRuntime.depositToMailbox(mailboxId, envelopeId) requires envelopeId");
    }
    this.storage.getMailboxStore().append(mailboxId, envelopeId);
  }

  listMailbox(mailboxId) {
    if (!isNonEmptyString(mailboxId)) {
      throw new Error("RezRuntime.listMailbox(mailboxId) requires a non-empty string");
    }
    return this.storage.getMailboxStore().list(mailboxId);
  }

  async start() {
    await super.start();
  }

  async stop() {
    await super.stop();
  }

  async receivePacket(packet) {
    if (!packet || !(packet.bytes instanceof Uint8Array)) {
      throw new Error("RezRuntime.receivePacket(packet) requires packet.bytes Uint8Array");
    }

    const envelope = await Promise.resolve(this.decodeEnvelope(packet.bytes));
    const id = await Promise.resolve(this.saveEnvelope(envelope));

    const mailboxId = packet.meta && packet.meta.depositMailboxId;
    if (mailboxId) {
      await Promise.resolve(this.depositToMailbox(mailboxId, id));
    }

    return { envelopeId: id };
  }
}
