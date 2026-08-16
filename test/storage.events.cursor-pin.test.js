import test from "node:test";
import assert from "node:assert/strict";

import { MemoryStorageProvider } from "../src/storage/memory/MemoryStorageProvider.js";

// DT-002 characterization: rez-core's OWN copy of the peer-link event
// listing/cursor contract (MemoryStorageProvider's KeyValuePeerLinkEventStore
// is a duplicated implementation of the rez-sdk store, not a wrapper —
// characterizing one does not cover the other). Same pins as
// rez-sdk/test/peer-link.events.cursor-pin.test.js; the public contract
// DT-302 must preserve: event-id-string cursor, append order, exclusive
// cursor, unknown-cursor-replays-page-1 (defect), invalid-limit = unbounded.

const OWNER = "rez:acct:core-cursor-pin";
const LINK = "pl_core_cursor_pin";

async function makeEventsWith(count) {
  const provider = new MemoryStorageProvider();
  const events = provider.getPeerLinkStorage().events;
  const ids = [];
  for (let i = 1; i <= count; i++) {
    const eventId = "pev_pin_" + String(i).padStart(2, "0");
    await events.append({
      ownerAccountId: OWNER,
      eventId,
      peerLinkId: LINK,
      type: "pin_event",
      summary: "event " + i,
      details: { i },
      atMs: 1000,
    });
    ids.push(eventId);
  }
  return { events, ids };
}

function itemIds(page) {
  return page.items.map((e) => e.eventId);
}

test("core events cursor pin: append order, event-id-string cursor, exclusive paging", async () => {
  const { events, ids } = await makeEventsWith(5);

  const all = await events.listByPeerLinkId(OWNER, LINK);
  assert.deepEqual(itemIds(all), ids);
  assert.equal(all.nextCursor, null);

  const p1 = await events.listByPeerLinkId(OWNER, LINK, { limit: 2 });
  assert.deepEqual(itemIds(p1), [ids[0], ids[1]]);
  assert.equal(p1.nextCursor, ids[1]);

  const p2 = await events.listByPeerLinkId(OWNER, LINK, { limit: 2, cursor: p1.nextCursor });
  assert.deepEqual(itemIds(p2), [ids[2], ids[3]]);
  assert.equal(p2.nextCursor, ids[3]);

  const p3 = await events.listByPeerLinkId(OWNER, LINK, { limit: 2, cursor: p2.nextCursor });
  assert.deepEqual(itemIds(p3), [ids[4]]);
  assert.equal(p3.nextCursor, null);
});

test("core events cursor pin (defect): unknown cursor replays from page 1; invalid limits are unbounded", async () => {
  const { events, ids } = await makeEventsWith(3);

  const unknown = await events.listByPeerLinkId(OWNER, LINK, { limit: 2, cursor: "pev_never" });
  assert.deepEqual(itemIds(unknown), [ids[0], ids[1]]);

  for (const limit of [0, -1, 10.5, "2"]) {
    const page = await events.listByPeerLinkId(OWNER, LINK, { limit });
    assert.deepEqual(itemIds(page), ids, "limit " + String(limit) + " ignored");
    assert.equal(page.nextCursor, null);
  }
});
