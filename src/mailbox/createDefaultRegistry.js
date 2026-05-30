import { MailboxRecordRegistry } from "./MailboxRecordRegistry.js";
import { OuterPacketRecord } from "../packets/OuterPacketRecord.js";
import { AppDepositRecord } from "./AppDepositRecord.js";

/**
 * Create a MailboxRecordRegistry with all built-in record types registered.
 *
 * Wire types (hydrated from network bytes):
 *   - OuterPacketRecord
 *
 * App types (constructed in code, never from wire):
 *   - AppDepositRecord
 *
 * @returns {MailboxRecordRegistry}
 */
export function createDefaultRegistry() {
  const registry = new MailboxRecordRegistry();
  registry.register(OuterPacketRecord);
  registry.registerAppType(AppDepositRecord);
  return registry;
}
