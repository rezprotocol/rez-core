import test from "node:test";
import assert from "node:assert/strict";
import { MemoryStorageProvider } from "../src/storage/memory/MemoryStorageProvider.js";


test("MemoryStorageProvider returns stable stores", async () => {
  const provider = new MemoryStorageProvider();

  const objectStore = provider.getObjectStore();
  const mailboxStore = provider.getMailboxStore();
  const keyValueStore = provider.getKeyValueStore();
  const peerLinkStorage = provider.getPeerLinkStorage();

  assert.equal(provider.getObjectStore(), objectStore);
  assert.equal(provider.getMailboxStore(), mailboxStore);
  assert.equal(provider.getKeyValueStore(), keyValueStore);
  assert.equal(provider.getPeerLinkStorage(), peerLinkStorage);

  const createdPeerLink = await peerLinkStorage.peerLinks.create({
    peerLinkId: "pl_alpha",
    localAccountId: "rez:acct:alice",
    peerAccountId: "rez:acct:bob",
    state: "invite_issued",
  });
  assert.equal(createdPeerLink.version, 1);

  const loadedByPair = await peerLinkStorage.peerLinks.getByPair("rez:acct:alice", "rez:acct:bob");
  assert.equal(loadedByPair.peerLinkId, "pl_alpha");
  const missingReverse = await peerLinkStorage.peerLinks.getByPair("rez:acct:bob", "rez:acct:alice");
  assert.equal(missingReverse, undefined);

  const updatedPeerLink = await peerLinkStorage.peerLinks.update({
    ...loadedByPair,
    state: "invite_validated",
  }, loadedByPair.version);
  assert.equal(updatedPeerLink.version, 2);

  const storedSession = await peerLinkStorage.sessions.put({
    sessionId: "sess_alpha",
    peerLinkId: "pl_alpha",
    localAccountId: "rez:acct:alice",
    peerAccountId: "rez:acct:bob",
    status: "pending",
  });
  assert.equal(storedSession.version, 1);

  const recoverable = await peerLinkStorage.sessions.listRecoverable("rez:acct:alice");
  assert.deepEqual(recoverable.map((item) => item.sessionId), ["sess_alpha"]);

  const createdAttempt = await peerLinkStorage.handshakeAttempts.create({
    handshakeAttemptId: "hs_alpha",
    peerLinkId: "pl_alpha",
    ownerAccountId: "rez:acct:alice",
    status: "sent",
  });
  assert.equal(createdAttempt.version, 1);

  const pending = await peerLinkStorage.handshakeAttempts.listPending("rez:acct:alice");
  assert.deepEqual(pending.map((item) => item.handshakeAttemptId), ["hs_alpha"]);

  await peerLinkStorage.events.append({
    ownerAccountId: "rez:acct:alice",
    eventId: "evt_alpha",
    peerLinkId: "pl_alpha",
    type: "invite_created",
    atMs: 1,
    summary: "invite created",
  });
  const eventPage = await peerLinkStorage.events.listByPeerLinkId("rez:acct:alice", "pl_alpha", { limit: 10 });
  assert.deepEqual(eventPage.items.map((item) => item.eventId), ["evt_alpha"]);
  assert.equal(eventPage.nextCursor, null);

  await peerLinkStorage.keys.putAccountIdentity("rez:acct:alice", { keyId: "id_a" });
  const identity = await peerLinkStorage.keys.getAccountIdentity("rez:acct:alice");
  assert.deepEqual(identity, { keyId: "id_a" });

  await peerLinkStorage.keys.putInvitePreKey("rez:acct:alice", "inv_alpha", { keyId: "pre_1" });
  const invitePreKey = await peerLinkStorage.keys.getInvitePreKey("rez:acct:alice", "inv_alpha");
  assert.deepEqual(invitePreKey, { keyId: "pre_1" });
  const otherInvitePreKey = await peerLinkStorage.keys.getInvitePreKey("rez:acct:bob", "inv_alpha");
  assert.equal(otherInvitePreKey, undefined);
});
