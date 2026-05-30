import { RAbstract } from "../base/index.js";

export class MailboxStore extends RAbstract {
  append(_mailboxId, _objectId) {
    return this.abstract("append");
  }

  list(_mailboxId) {
    return this.abstract("list");
  }

  deleteMailbox(_mailboxId) {
    return this.abstract("deleteMailbox");
  }
}
