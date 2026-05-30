# WS Contracts

Generated file. Do not edit by hand.

Source: `rez-node/src/contracts` and shared type vocabulary from `rez-core`.

Generated at: 2026-05-08T16:51:34.181Z

## Registry Table

| Type (`t`) | Direction | Contract Class |
|---|---|---|
| `capability.grant` | client -> server | `CapabilityGrantRequest` |
| `capability.grant.res` | server -> client | `CapabilityGrantResponse` |
| `channel.close` | client -> server | `ChannelCloseRequest` |
| `channel.close.res` | server -> client | `ChannelCloseResponse` |
| `channel.open` | client -> server | `ChannelOpenRequest` |
| `channel.open.res` | server -> client | `ChannelOpenResponse` |
| `channel.signal` | client -> server | `ChannelSignalEvent` |
| `error` | server -> client | `WsErrorEvent` |
| `evt.mailbox.deposited` | server -> client | `MailboxDepositedEvent` |
| `mailbox.ack` | client -> server | `MailboxAckRequest` |
| `mailbox.ack.res` | server -> client | `MailboxAckResponse` |
| `mailbox.deposit` | client -> server | `MailboxDepositRequest` |
| `mailbox.deposit.res` | server -> client | `MailboxDepositResponse` |
| `mailbox.fetch` | client -> server | `MailboxFetchRequest` |
| `mailbox.fetch.res` | server -> client | `MailboxFetchResponse` |
| `mailbox.list` | client -> server | `MailboxListRequest` |
| `mailbox.list.res` | server -> client | `MailboxListResponse` |
| `node.status` | client -> server | `NodeStatusRequest` |
| `node.status.res` | server -> client | `NodeStatusResponse` |
| `object.delete` | client -> server | `ObjectDeleteRequest` |
| `object.delete.res` | server -> client | `ObjectDeleteResponse` |
| `object.get` | client -> server | `ObjectGetRequest` |
| `object.get.res` | server -> client | `ObjectGetResponse` |
| `object.list` | client -> server | `ObjectListRequest` |
| `object.list.res` | server -> client | `ObjectListResponse` |
| `object.publish` | client -> server | `ObjectPublishRequest` |
| `object.publish.res` | server -> client | `ObjectPublishResponse` |
| `session.hello` | client -> server | `SessionHello` |
| `session.ready` | server -> client | `SessionReadyEvent` |

## Examples

### capability.grant

```json
{
  "id": "example:capability.grant",
  "t": "capability.grant",
  "body": {
    "parentCapabilityId": "cap_root_001",
    "resource": "mailbox:inbox:test",
    "actions": [
      "read"
    ],
    "constraints": {},
    "capabilityId": null
  },
  "v": 2
}
```

### capability.grant.res

```json
{
  "id": "example:capability.grant.res",
  "t": "capability.grant.res",
  "body": {
    "capabilityId": "cap_child_001",
    "resource": "mailbox:inbox:test",
    "actions": [
      "read"
    ],
    "constraints": {},
    "signatureB64": "c2lnbmF0dXJl"
  },
  "v": 2
}
```

### channel.close

```json
{
  "id": "example:channel.close",
  "t": "channel.close",
  "body": {
    "channelId": "ch_test_001"
  },
  "v": 2
}
```

### channel.close.res

```json
{
  "id": "example:channel.close.res",
  "t": "channel.close.res",
  "body": {
    "channelId": "ch_test_001",
    "code": "OK",
    "message": "channel closed"
  },
  "v": 2
}
```

### channel.open

```json
{
  "id": "example:channel.open",
  "t": "channel.open",
  "body": {
    "channelId": "ch_test_001",
    "capabilityId": null
  },
  "v": 2
}
```

### channel.open.res

```json
{
  "id": "example:channel.open.res",
  "t": "channel.open.res",
  "body": {
    "channelId": "ch_test_001",
    "code": "OK",
    "message": "channel opened"
  },
  "v": 2
}
```

### channel.signal

```json
{
  "id": "example:channel.signal",
  "t": "channel.signal",
  "body": {
    "channelId": "ch_test_001",
    "signal": "offer",
    "data": {
      "sdp": "example"
    }
  },
  "v": 2
}
```

### error

```json
{
  "id": "example:error",
  "t": "error",
  "body": {
    "code": "BAD_REQUEST",
    "message": "invalid request",
    "detail": {
      "retryable": false,
      "threadId": null,
      "clientMsgId": null
    }
  },
  "v": 2
}
```

### evt.mailbox.deposited

```json
{
  "id": "example:evt.mailbox.deposited",
  "t": "evt.mailbox.deposited",
  "body": {
    "mailboxId": "inbox:test",
    "eventId": "evt_001",
    "objectId": "obj_test_001",
    "createdAtMs": 1772496000000
  },
  "v": 2
}
```

### mailbox.ack

```json
{
  "id": "example:mailbox.ack",
  "t": "mailbox.ack",
  "body": {
    "mailboxId": "inbox:test",
    "eventId": "evt_001",
    "capabilityId": null
  },
  "v": 2
}
```

### mailbox.ack.res

```json
{
  "id": "example:mailbox.ack.res",
  "t": "mailbox.ack.res",
  "body": {
    "mailboxId": "inbox:test",
    "eventId": "evt_001",
    "removed": true
  },
  "v": 2
}
```

### mailbox.deposit

```json
{
  "id": "example:mailbox.deposit",
  "t": "mailbox.deposit",
  "body": {
    "mailboxId": "inbox:test",
    "objectId": "obj_test_001",
    "ciphertextB64": "Y2lwaGVydGV4dA==",
    "metadata": {
      "contentType": "application/octet-stream"
    },
    "capabilityId": null
  },
  "v": 2
}
```

### mailbox.deposit.res

```json
{
  "id": "example:mailbox.deposit.res",
  "t": "mailbox.deposit.res",
  "body": {
    "mailboxId": "inbox:test",
    "eventId": "evt_001"
  },
  "v": 2
}
```

### mailbox.fetch

```json
{
  "id": "example:mailbox.fetch",
  "t": "mailbox.fetch",
  "body": {
    "mailboxId": "inbox:test",
    "eventId": "evt_001",
    "capabilityId": null
  },
  "v": 2
}
```

### mailbox.fetch.res

```json
{
  "id": "example:mailbox.fetch.res",
  "t": "mailbox.fetch.res",
  "body": {
    "mailboxId": "inbox:test",
    "eventId": "evt_001",
    "objectId": "obj_test_001",
    "ciphertextB64": "Y2lwaGVydGV4dA==",
    "metadata": {
      "contentType": "application/octet-stream"
    },
    "createdAtMs": 1772496000000
  },
  "v": 2
}
```

### mailbox.list

```json
{
  "id": "example:mailbox.list",
  "t": "mailbox.list",
  "body": {
    "mailboxId": "inbox:test",
    "cursor": null,
    "limit": 50,
    "sinceMs": null,
    "capabilityId": null
  },
  "v": 2
}
```

### mailbox.list.res

```json
{
  "id": "example:mailbox.list.res",
  "t": "mailbox.list.res",
  "body": {
    "mailboxId": "inbox:test",
    "items": [
      {
        "eventId": "evt_001",
        "objectId": "obj_test_001",
        "createdAtMs": 1772496000000
      }
    ],
    "nextCursor": null
  },
  "v": 2
}
```

### node.status

```json
{
  "id": "example:node.status",
  "t": "node.status",
  "body": {},
  "v": 2
}
```

### node.status.res

```json
{
  "id": "example:node.status.res",
  "t": "node.status.res",
  "body": {
    "accountId": "rez:test:acct:example",
    "meshEnabled": true,
    "meshMode": "seeded-gossip",
    "peerCount": 0,
    "uptimeMs": 1000
  },
  "v": 2
}
```

### object.delete

```json
{
  "id": "example:object.delete",
  "t": "object.delete",
  "body": {
    "resourceId": "res:test",
    "objectId": "obj_test_001",
    "capabilityId": null
  },
  "v": 2
}
```

### object.delete.res

```json
{
  "id": "example:object.delete.res",
  "t": "object.delete.res",
  "body": {
    "resourceId": "res:test",
    "objectId": "obj_test_001",
    "removed": true
  },
  "v": 2
}
```

### object.get

```json
{
  "id": "example:object.get",
  "t": "object.get",
  "body": {
    "resourceId": "res:test",
    "objectId": "obj_test_001",
    "capabilityId": null
  },
  "v": 2
}
```

### object.get.res

```json
{
  "id": "example:object.get.res",
  "t": "object.get.res",
  "body": {
    "resourceId": "res:test",
    "objectId": "obj_test_001",
    "ciphertextB64": "Y2lwaGVydGV4dA==",
    "metadata": {},
    "createdAtMs": 1772496000000
  },
  "v": 2
}
```

### object.list

```json
{
  "id": "example:object.list",
  "t": "object.list",
  "body": {
    "resourceId": "res:test",
    "cursor": null,
    "limit": 50,
    "capabilityId": null
  },
  "v": 2
}
```

### object.list.res

```json
{
  "id": "example:object.list.res",
  "t": "object.list.res",
  "body": {
    "resourceId": "res:test",
    "items": [
      {
        "objectId": "obj_test_001",
        "createdAtMs": 1772496000000
      }
    ],
    "nextCursor": null
  },
  "v": 2
}
```

### object.publish

```json
{
  "id": "example:object.publish",
  "t": "object.publish",
  "body": {
    "resourceId": "res:test",
    "objectId": "obj_test_001",
    "ciphertextB64": "Y2lwaGVydGV4dA==",
    "metadata": {},
    "capabilityId": null
  },
  "v": 2
}
```

### object.publish.res

```json
{
  "id": "example:object.publish.res",
  "t": "object.publish.res",
  "body": {
    "resourceId": "res:test",
    "objectId": "obj_test_001",
    "createdAtMs": 1772496000000
  },
  "v": 2
}
```

### session.hello

```json
{
  "id": "example:session.hello",
  "t": "session.hello",
  "body": {
    "contractVersion": 2,
    "clientName": "test-client",
    "clientVersion": "0.0.1",
    "deviceId": "dev:test",
    "accountId": "rez:test:acct:example",
    "accountIdentityPublicKeyB64": "dGVzdC1wdWJsaWMta2V5"
  },
  "v": 2
}
```

### session.ready

```json
{
  "id": "example:session.ready",
  "t": "session.ready",
  "body": {
    "serverTime": 1772496000000,
    "accountId": "rez:test:acct:example",
    "capabilities": {
      "contractVersion": 2,
      "deviceId": "dev:test",
      "localInboxId": "inbox:test",
      "capabilities": [],
      "bootstrapRelays": [],
      "bootstrapSeeds": [],
      "meshMode": "seeded-gossip"
    }
  },
  "v": 2
}
```

