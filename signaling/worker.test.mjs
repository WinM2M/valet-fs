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

async function create(hub, pub = "PUB", versions = [1], claimSecret = "") {
  const r = await hub.fetch(new Request(url("create"), {
    method: "POST", body: JSON.stringify({ pub, versions, claim_secret: claimSecret }),
  }));
  return (await r.json()).daemon_token;
}

function claimReq(secret) {
  const headers = secret === undefined ? {} : { "X-Valet-Claim-Secret": secret };
  return new Request(url("claim"), { method: "POST", headers });
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

import { isKeepalive, isSystemFrame } from "./worker.ts";

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

// --- protocol versions ----------------------------------------------------

await test("claim relays the daemon's version list verbatim", async () => {
  const hub = new SessionHub(fakeState());
  await create(hub, "PUB", [1, 2]);
  const claim = await (await hub.fetch(new Request(url("claim"), { method: "POST" }))).json();
  assert.deepStrictEqual(claim.versions, [1, 2]);
});

await test("a session with no version list claims cleanly", async () => {
  const hub = new SessionHub(fakeState());
  await create(hub, "PUB", []);
  const claim = await (await hub.fetch(new Request(url("claim"), { method: "POST" }))).json();
  assert.deepStrictEqual(claim.versions, []);
});

await test("setpub can carry versions for a joining daemon", async () => {
  const hub = new SessionHub(fakeState());
  const tok = await create(hub, "", []);
  const r = await hub.fetch(new Request(url("setpub"), {
    method: "POST",
    headers: { "X-Valet-Role-Token": tok },
    body: JSON.stringify({ pub: "JOINED", versions: [1] }),
  }));
  assert.strictEqual(r.status, 204);
  const claim = await (await hub.fetch(new Request(url("claim"), { method: "POST" }))).json();
  assert.strictEqual(claim.daemon_pub, "JOINED");
  assert.deepStrictEqual(claim.versions, [1]);
});

// --- claim secret ---------------------------------------------------------
//
// The session id used to be the whole credential, and it is printed to a
// terminal, so it turns up in logs, screenshots and agent transcripts. These
// cover the credential that replaced it.

const SECRET = "s".repeat(43);

await test("a session with a claim secret cannot be claimed without it", async () => {
  const hub = new SessionHub(fakeState());
  await create(hub, "PUB", [1], SECRET);
  assert.strictEqual((await hub.fetch(claimReq())).status, 403, "no secret");
  assert.strictEqual((await hub.fetch(claimReq(""))).status, 403, "empty secret");
  assert.strictEqual((await hub.fetch(claimReq("x".repeat(43)))).status, 403, "wrong secret");
});

await test("the right claim secret claims the session", async () => {
  const hub = new SessionHub(fakeState());
  await create(hub, "PUB", [1], SECRET);
  const r = await hub.fetch(claimReq(SECRET));
  assert.strictEqual(r.status, 200);
  const body = await r.json();
  assert.ok(body.controller_token, "a token must be issued");
  assert.strictEqual(body.first_claim, true);
});

await test("a second claim is reported as not the first", async () => {
  const hub = new SessionHub(fakeState());
  await create(hub, "PUB", [1], SECRET);
  const a = await (await hub.fetch(claimReq(SECRET))).json();
  const b = await (await hub.fetch(claimReq(SECRET))).json();
  // The token stays stable so the rightful owner can reconnect, but the second
  // caller is told a claim already happened — a photographed screen should not
  // pass unnoticed.
  assert.strictEqual(a.controller_token, b.controller_token);
  assert.strictEqual(b.first_claim, false);
  assert.ok(b.claimed_at > 0);
});

await test("the hub stores only a hash of the claim secret", async () => {
  const st = fakeState();
  const hub = new SessionHub(st);
  await create(hub, "PUB", [1], SECRET);
  const stored = [...st._map.values()].map(String);
  assert.ok(!stored.includes(SECRET), "the secret itself must never be stored");
  assert.ok(st._map.has("claim_hash"), "a hash must be stored");
  assert.strictEqual(st._map.get("claim_hash").length, 64);
});

await test("a legacy session with no claim secret still claims", async () => {
  const hub = new SessionHub(fakeState());
  await create(hub, "PUB", [1]);
  assert.strictEqual((await hub.fetch(claimReq())).status, 200);
});

await test("a newer socket replaces an older one for the same role", async () => {
  const st = fakeState();
  const hub = new SessionHub(st);
  await create(hub, "PUB", [1], SECRET);
  const { controller_token } = await (await hub.fetch(claimReq(SECRET))).json();

  const connect = (role, token) => hub.fetch(new Request(
    `https://do/?do=connect&role=${role}&token=${token}`, { method: "GET" }));

  // A stale vault socket must not block the real phone's return. Refusing the
  // newcomer meant a handset that lost signal locked itself out of its own
  // vault; the claim secret is what keeps an impostor out of this role.
  let closed = 0;
  st.getWebSockets = (role) => (role === "vault" ? [{ close: () => { closed += 1; } }] : []);
  await assert.rejects(
    () => connect("vault", controller_token),
    /WebSocketPair/,
    "a second vault connection must proceed, not be refused",
  );
  assert.strictEqual(closed, 1, "the stale socket must be closed, not left to linger");

  // Per role, not global: a daemon attaching must not disturb the vault.
  closed = 0;
  const daemonToken = await st.storage.get("daemon_token");
  await assert.rejects(() => connect("daemon", daemonToken), /WebSocketPair/);
  assert.strictEqual(closed, 0, "attaching one role must not close the other's socket");
});

// A daemon's keepalive is write-only, and a write to a half-open socket keeps
// succeeding — so it would believe it was connected while everything relayed to
// it vanished. Answering gives it something to miss.
await test("the hub answers a keepalive and relays nothing onward", async () => {
  assert.ok(isKeepalive('{"sys":"ka"}'));
  assert.ok(isKeepalive(new TextEncoder().encode('{"sys":"ka"}').buffer));
  for (const not of ['{"sys":"peer_online","role":"vault"}', '{"enc":"x"}', "nope", '{"sys":"kax"}']) {
    assert.ok(!isKeepalive(not), `should not be a keepalive: ${not}`);
  }

  const st = fakeState();
  const relayed = [];
  st.getWebSockets = (role) => (role === "vault" ? [{ send: (m) => relayed.push(m) }] : []);
  st.getTags = () => ["daemon"];
  const hub = new SessionHub(st);

  const answers = [];
  await hub.webSocketMessage({ send: (m) => answers.push(m) }, '{"sys":"ka"}');
  assert.deepStrictEqual(answers, ['{"sys":"ka_ack"}'], "the sender must get an answer");
  assert.strictEqual(relayed.length, 0, "a keepalive must never reach the peer");
});

console.log(`\nSessionHub: ${passed}/${passed} 통과`);
