import { MailboxStore } from "../MailboxStore.js";

export class MemoryMailboxStore extends MailboxStore {
  constructor() {
    super();
    this.mailboxes = new Map();
  }

  append(mailboxId, objectId) {
    const list = this.mailboxes.get(mailboxId) ?? [];
    list.push(objectId);
    this.mailboxes.set(mailboxId, list);
  }

  list(mailboxId) {
    const list = this.mailboxes.get(mailboxId) ?? [];
    return [...list];
  }

  deleteMailbox(mailboxId) {
    return this.mailboxes.delete(mailboxId);
  }
}
