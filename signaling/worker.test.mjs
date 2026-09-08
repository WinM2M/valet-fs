// Regression tests for the SessionHub Durable Object.
//
// Run with:  node --experimental-strip-types worker.test.mjs
//
// These exist because the hub is the one component that is reachable by anyone
// on the internet who learns a session id, and it had two endpoints (delete,
// claim) that took no credential at all.

import assert from "node:assert";
import { SessionHub, tokenEqual } from "./worker.ts";

/** Minimal DurableObjectState stand-in: storage + no live sockets. */
function fakeState() {
  const map = new Map();
  return {
    storage: {
      async get(k) { return map.get(k); },
      async put(k, v) { map.set(k, v); },
      async deleteAll() { map.clear(); },
    },
    getWebSockets() { return []; },
    getTags() { return []; },
    acceptWebSocket() {},
    _map: map,
  };
}

const url = (action) => `https://do/?do=${action}`;

async function create(hub, pub = "PUB") {
  const r = await hub.fetch(new Request(url("create"), {
    method: "POST", body: JSON.stringify({ pub }),
  }));
  return (await r.json()).daemon_token;
}

async function del(hub, token) {
  const headers = token === undefined ? {} : { "X-Valet-Role-Token": token };
  return hub.fetch(new Request(url("delete"), { method: "POST", headers }));
}

let passed = 0;
async function test(name, fn) {
  await fn();
  console.log(`  ok  ${name}`);
  passed++;
}

// --- delete authorisation -------------------------------------------------

await test("delete with no token is refused", async () => {
  const st = fakeState();
  const hub = new SessionHub(st);
  await create(hub);
  assert.strictEqual((await del(hub)).status, 403);
  assert.ok(st._map.has("daemon_token"), "session must survive a refused delete");
});

await test("delete with a wrong token is refused", async () => {
  const hub = new SessionHub(fakeState());
  await create(hub);
  assert.strictEqual((await del(hub, "0".repeat(48))).status, 403);
});

await test("delete with the daemon token succeeds and wipes storage", async () => {
  const st = fakeState();
  const hub = new SessionHub(st);
  const tok = await create(hub);
  assert.strictEqual((await del(hub, tok)).status, 204);
  assert.strictEqual(st._map.size, 0, "storage must be cleared");
});

await test("delete with the vault token succeeds", async () => {
  const hub = new SessionHub(fakeState());
  await create(hub);
  const claim = await hub.fetch(new Request(url("claim"), { method: "POST" }));
  const { controller_token } = await claim.json();
  assert.ok(controller_token, "claim must issue a controller token");
  assert.strictEqual((await del(hub, controller_token)).status, 204);
});

await test("delete on a never-provisioned session stays idempotent", async () => {
  const hub = new SessionHub(fakeState());
  assert.strictEqual((await del(hub)).status, 204);
});

// --- behaviour that must not regress -------------------------------------

await test("claim returns the daemon pubkey and is stable across calls", async () => {
  const hub = new SessionHub(fakeState());
  await create(hub, "DAEMONPUB");
  const a = await (await hub.fetch(new Request(url("claim"), { method: "POST" }))).json();
  const b = await (await hub.fetch(new Request(url("claim"), { method: "POST" }))).json();
  assert.strictEqual(a.daemon_pub, "DAEMONPUB");
  assert.strictEqual(a.controller_token, b.controller_token);
});

await test("setpub is first-writer-wins and needs the daemon token", async () => {
  const hub = new SessionHub(fakeState());
  const tok = await create(hub, "");
  const put = (pub, t) => hub.fetch(new Request(url("setpub"), {
    method: "POST",
    headers: t === undefined ? {} : { "X-Valet-Role-Token": t },
    body: JSON.stringify({ pub }),
  }));
  assert.strictEqual((await put("P1")).status, 403, "no token must be refused");
  assert.strictEqual((await put("P1", tok)).status, 204);
  assert.strictEqual((await put("P2", tok)).status, 409, "pubkey must be immutable");
});

await test("tokenEqual rejects mismatched and empty inputs", () => {
  assert.ok(tokenEqual("abc", "abc"));
  assert.ok(!tokenEqual("abc", "abd"));
  assert.ok(!tokenEqual("abc", "abcd"));
  assert.ok(!tokenEqual("", ""));
});


// --- presence forgery -----------------------------------------------------

import { isSystemFrame } from "./worker.ts";

await test("forged presence frames are never relayed", async () => {
  const forged = [
    '{"sys":"peer_offline","role":"vault"}',
    '{"sys":"peer_online","role":"vault"}',
    '{"sys":"ka"}',
    '{"role":"vault","sys":"peer_offline"}',   // key order is the sender's choice
    '{"pad":"aaaaaaaaaaaaaaaa","sys":"peer_offline"}', // padding buys nothing
    '{"sys":null}',
  ];
  for (const f of forged) {
    assert.ok(isSystemFrame(f), `relayed a forged frame: ${f}`);
    assert.ok(isSystemFrame(new TextEncoder().encode(f).buffer),
      `relayed a forged binary frame: ${f}`);
  }

  const app = [
    '{"v":1,"type":"REQ","method":"STATUS"}',
    '{"enc":"YmFzZTY0"}',
    '{"kx":"hello","pub":"AAAA"}',
    "not json at all",
    "",
  ];
  for (const f of app) {
    assert.ok(!isSystemFrame(f), `dropped a legitimate frame: ${f}`);
  }
});

await test("the relay drops a peer's presence but passes app frames", async () => {
  const st = fakeState();
  const delivered = [];
  st.getWebSockets = (role) => (role === "vault" ? [{ send: (m) => delivered.push(m) }] : []);
  st.getTags = () => ["daemon"];
  const hub = new SessionHub(st);

  await hub.webSocketMessage({}, '{"sys":"peer_offline","role":"vault"}');
  assert.strictEqual(delivered.length, 0, "a forged presence frame reached the peer");

  await hub.webSocketMessage({}, '{"enc":"YmFzZTY0"}');
  assert.strictEqual(delivered.length, 1, "a legitimate app frame was dropped");
});

console.log(`\nSessionHub: ${passed}/${passed} 통과`);
