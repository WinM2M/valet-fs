// signaling/worker.ts
//
// Minimal Cloudflare Worker that brokers WebRTC SDP exchange between a
// ValetFS desktop daemon (offerer) and a mobile app (answerer). Sessions
// are short-lived and stored in a Workers KV namespace bound as VALETFS_KV.
//
// Endpoints:
//   POST   /sessions               body {offer}        -> {session_id}
//   GET    /sessions/:id/offer                          -> {offer}
//   POST   /sessions/:id/answer    body {answer}        -> 204
//   GET    /sessions/:id/answer                         -> {answer} | 404
//
// All payloads are stored verbatim; only the encrypted DataChannel ever
// carries token material, so the Worker never observes secrets.

export interface Env {
  VALETFS_KV: KVNamespace;
  // Durable Object namespace backing the WebSocket control-plane hub.
  SESSION_HUB: DurableObjectNamespace;
  // Legacy HMAC-secret mode (coturn-style auth-secret). Kept for self-hosted
  // deployments. Ignored when METERED_API_KEY is present.
  TURN_DOMAIN?: string;
  TURN_SECRET?: string;
  // Preferred: Metered REST API pass-through. The Worker calls
  //   https://{METERED_APP}.metered.live/api/v1/turn/credentials?apiKey=...
  // and returns the iceServers array verbatim. This is the only mode that
  // is guaranteed to interoperate with Metered's production TURN cluster
  // (standard.relay.metered.ca et al.) because credentials are minted by
  // Metered itself rather than computed via shared-secret HMAC.
  METERED_APP?: string;
  METERED_API_KEY?: string;
}

const TTL_SECONDS = 300; // 5 minutes

async function shortIPHash(ip: string): Promise<string> {
  const raw = (ip || "").trim();
  if (!raw) return "unknown";
  const enc = new TextEncoder().encode(raw);
  const dig = await crypto.subtle.digest("SHA-256", enc);
  const b = new Uint8Array(dig);
  return Array.from(b.slice(0, 6), (x) => x.toString(16).padStart(2, "0")).join("");
}

async function audit(req: Request, event: string, sessionID = "-"): Promise<void> {
  const ip = req.headers.get("CF-Connecting-IP") || "";
  const ua = req.headers.get("User-Agent") || "";
  const iph = await shortIPHash(ip);
  const uash = await shortIPHash(ua);
  console.log(`audit event=${event} sid=${sessionID} iph=${iph} uah=${uash}`);
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      "access-control-allow-origin": "*",
    },
  });
}

type CandidateEntry = { seq: number; candidate: unknown };

async function loadCandidates(env: Env, key: string): Promise<CandidateEntry[]> {
  const raw = await env.VALETFS_KV.get(key);
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as CandidateEntry[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function randomID(): string {
  const buf = new Uint8Array(16);
  crypto.getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}

function randomToken(): string {
  const buf = new Uint8Array(24);
  crypto.getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function getToken(env: Env, id: string, role: "daemon" | "controller"): Promise<string | null> {
  return env.VALETFS_KV.get(`tok:${role}:${id}`);
}

async function requireRoleToken(req: Request, env: Env, id: string, role: "daemon" | "controller"): Promise<Response | null> {
  const header = req.headers.get("X-Valet-Role-Token") || "";
  const token = await getToken(env, id, role);
  if (!token || !header || token !== header) {
    return json({ error: "forbidden" }, 403);
  }
  return null;
}

async function makeTurnCredential(secret: string, username: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(username));
  const bytes = new Uint8Array(sig);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

async function buildIceServers(env: Env): Promise<Array<Record<string, unknown>>> {
  const out: Array<Record<string, unknown>> = [
    { urls: ["stun:stun.l.google.com:19302"] },
  ];

  // Preferred path: Metered REST API. Returns iceServers minted by Metered
  // for the correct production TURN cluster, with credentials that the
  // server will actually accept.
  const app = (env.METERED_APP || "").trim();
  const apiKey = (env.METERED_API_KEY || "").trim();
  if (app && apiKey) {
    try {
      const r = await fetch(
        `https://${app}.metered.live/api/v1/turn/credentials?apiKey=${encodeURIComponent(apiKey)}`,
      );
      if (r.ok) {
        const arr = (await r.json()) as Array<Record<string, unknown>>;
        if (Array.isArray(arr) && arr.length > 0) {
          for (const s of arr) out.push(s);
          return out;
        }
      }
    } catch (_e) {
      // fall through to legacy HMAC path
    }
  }

  // Legacy: coturn-style auth-secret HMAC. Only works when TURN_DOMAIN is a
  // real TURN server (e.g. a self-hosted coturn) configured with the same
  // shared secret.
  const domain = (env.TURN_DOMAIN || "").trim();
  const secret = (env.TURN_SECRET || "").trim();
  if (!domain || !secret) return out;
  const expiry = Math.floor(Date.now() / 1000) + 10 * 60;
  const username = `${expiry}:valetfs`;
  const credential = await makeTurnCredential(secret, username);
  out.push({
    urls: [
      `stun:${domain}:80`,
      `turn:${domain}:80?transport=udp`,
      `turn:${domain}:80?transport=tcp`,
      `turn:${domain}:443?transport=tcp`,
      `turns:${domain}:443?transport=tcp`,
    ],
    username,
    credential,
  });
  return out;
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const parts = url.pathname.split("/").filter(Boolean);

    if (req.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "access-control-allow-origin": "*",
          "access-control-allow-methods": "GET,POST,DELETE,OPTIONS",
          "access-control-allow-headers": "content-type,x-valet-role-token",
        },
      });
    }

    // --- WebSocket / Durable Object control plane (/ws/...) ---
    // Kept under a distinct prefix so it never collides with the legacy WebRTC
    // signaling endpoints below. The DO only relays opaque frames + presence;
    // it never observes token material (E2EE is a peer-to-peer concern).
    if (parts[0] === "ws") {
      // POST /ws/sessions  {role:"daemon"} -> {session_id, daemon_token}
      if (req.method === "POST" && parts.length === 2 && parts[1] === "sessions") {
        await audit(req, "ws.sessions.create");
        const body = (await req.json().catch(() => ({}))) as { role?: string; pub?: string };
        if (body.role !== "daemon") return json({ error: "role must be daemon" }, 400);
        const sid = randomID();
        const stub = env.SESSION_HUB.get(env.SESSION_HUB.idFromName(sid));
        const r = await stub.fetch("https://do/?do=create", {
          method: "POST",
          body: JSON.stringify({ pub: body.pub || "" }),
        });
        const { daemon_token } = (await r.json()) as { daemon_token: string };
        return json({ session_id: sid, daemon_token });
      }
      // POST /ws/sessions/:id/claim -> {controller_token}
      if (req.method === "POST" && parts.length === 4 && parts[1] === "sessions" && parts[3] === "claim") {
        const sid = parts[2];
        await audit(req, "ws.sessions.claim", sid);
        const stub = env.SESSION_HUB.get(env.SESSION_HUB.idFromName(sid));
        const r = await stub.fetch("https://do/?do=claim", { method: "POST" });
        return new Response(r.body, { status: r.status, headers: { "content-type": "application/json" } });
      }
      // GET /ws/connect?sid=&role=&token=  -> websocket upgrade (routed to DO)
      if (parts[1] === "connect") {
        const sid = url.searchParams.get("sid") || "";
        if (!sid) return new Response("missing sid", { status: 400 });
        const stub = env.SESSION_HUB.get(env.SESSION_HUB.idFromName(sid));
        const fwd = new URL("https://do/");
        fwd.searchParams.set("do", "connect");
        fwd.searchParams.set("role", url.searchParams.get("role") || "");
        fwd.searchParams.set("token", url.searchParams.get("token") || "");
        return stub.fetch(new Request(fwd.toString(), req));
      }
      // GET /ws/sessions/:id/presence -> {daemon:bool, vault:bool, exists:bool}
      // Read-only liveness probe for the app's daemon list. Does NOT open a
      // socket, so it never touches the daemon's grace timer.
      if (req.method === "GET" && parts.length === 4 && parts[1] === "sessions" && parts[3] === "presence") {
        const sid = parts[2];
        const stub = env.SESSION_HUB.get(env.SESSION_HUB.idFromName(sid));
        return stub.fetch("https://do/?do=presence");
      }
      // DELETE /ws/sessions/:id  -> tear down the session (frees DO storage +
      // closes any open sockets). Used by the app's "Forget daemon".
      if (req.method === "DELETE" && parts.length === 3 && parts[1] === "sessions") {
        const sid = parts[2];
        await audit(req, "ws.sessions.delete", sid);
        const stub = env.SESSION_HUB.get(env.SESSION_HUB.idFromName(sid));
        return stub.fetch("https://do/?do=delete", { method: "POST" });
      }
      return new Response("not found", { status: 404 });
    }

    if (req.method === "POST" && parts.length === 1 && parts[0] === "sessions") {
      await audit(req, "sessions.create");
      const body = (await req.json().catch(() => ({}))) as { offer?: unknown; role?: string; init?: boolean };
      const { offer, role, init } = body;
      if (role !== "daemon") return json({ error: "role must be daemon" }, 400);
      const id = randomID();
      const daemonToken = randomToken();
      // Init mode: allocate session id + token + iceServers without an
      // offer. The daemon constructs its PeerConnection knowing the TURN
      // servers up-front (avoiding any later SetConfiguration race), then
      // POSTs the real offer via /sessions/:id/offer.
      if (init === true) {
        await env.VALETFS_KV.put(`owner:${id}`, "daemon", { expirationTtl: TTL_SECONDS });
        await env.VALETFS_KV.put(`tok:daemon:${id}`, daemonToken, { expirationTtl: TTL_SECONDS });
        const iceServers = await buildIceServers(env);
        return json({ session_id: id, daemon_token: daemonToken, ttl: TTL_SECONDS, iceServers });
      }
      if (!offer) return json({ error: "missing offer" }, 400);
      await env.VALETFS_KV.put(`offer:${id}`, JSON.stringify(offer), {
        expirationTtl: TTL_SECONDS,
      });
      await env.VALETFS_KV.put(`owner:${id}`, "daemon", { expirationTtl: TTL_SECONDS });
      await env.VALETFS_KV.put(`tok:daemon:${id}`, daemonToken, { expirationTtl: TTL_SECONDS });
      return json({ session_id: id, daemon_token: daemonToken, ttl: TTL_SECONDS });
    }

    if (req.method === "POST" && parts[0] === "sessions" && parts.length === 3 && parts[2] === "claim") {
      const id = parts[1];
      await audit(req, "sessions.claim", id);
      const offerRaw = await env.VALETFS_KV.get(`offer:${id}`);
      if (!offerRaw) return new Response("not found", { status: 404 });
      const claimed = await env.VALETFS_KV.get(`tok:controller:${id}`);
      if (claimed) {
        return json({ controller_token: claimed, offer: JSON.parse(offerRaw) });
      }
      const controllerToken = randomToken();
      await env.VALETFS_KV.put(`tok:controller:${id}`, controllerToken, { expirationTtl: TTL_SECONDS });
      return json({ controller_token: controllerToken, offer: JSON.parse(offerRaw) });
    }

    if (parts[0] === "sessions" && parts.length === 3 && parts[2] !== "candidates") {
      const [, id, kind] = parts;
      if (kind === "turn" || kind === "answer" || kind === "offer") {
        await audit(req, `sessions.${kind}.${req.method.toLowerCase()}`, id);
      }
      if (kind === "turn" && req.method === "GET") {
        const dTok = await getToken(env, id, "daemon");
        const cTok = await getToken(env, id, "controller");
        const hdr = req.headers.get("X-Valet-Role-Token") || "";
        if (!hdr || (hdr !== dTok && hdr !== cTok)) return json({ error: "forbidden" }, 403);
        const iceServers = await buildIceServers(env);
        return json({ iceServers, ttl_seconds: 600 });
      }
      const key = `${kind}:${id}`;
      if (req.method === "GET") {
        if (kind === "answer") {
          const forbidden = await requireRoleToken(req, env, id, "daemon");
          if (forbidden) return forbidden;
        }
        const v = await env.VALETFS_KV.get(key);
        if (!v) return new Response("not found", { status: 404 });
        return json({ [kind]: JSON.parse(v) });
      }
      if (req.method === "POST" && kind === "answer") {
        const forbidden = await requireRoleToken(req, env, id, "controller");
        if (forbidden) return forbidden;
        const { answer } = (await req.json()) as { answer: unknown };
        if (!answer) return json({ error: "missing answer" }, 400);
        await env.VALETFS_KV.put(key, JSON.stringify(answer), {
          expirationTtl: TTL_SECONDS,
        });
        return new Response(null, { status: 204 });
      }
      if (req.method === "POST" && kind === "offer") {
        // Allow the daemon to replace its stored offer once it has fetched
        // TURN credentials and rebuilt its PeerConnection. Only the daemon
        // role may overwrite the offer.
        const forbidden = await requireRoleToken(req, env, id, "daemon");
        if (forbidden) return forbidden;
        const { offer } = (await req.json()) as { offer: unknown };
        if (!offer) return json({ error: "missing offer" }, 400);
        await env.VALETFS_KV.put(`offer:${id}`, JSON.stringify(offer), {
          expirationTtl: TTL_SECONDS,
        });
        return new Response(null, { status: 204 });
      }
    }

    if (parts[0] === "sessions" && parts.length === 3 && parts[2] === "candidates") {
      const id = parts[1];
      if (req.method === "GET" || req.method === "POST") {
        await audit(req, `sessions.candidates.${req.method.toLowerCase()}`, id);
      }
      const daemonToken = await getToken(env, id, "daemon");
      const ctrlToken = await getToken(env, id, "controller");
      const header = req.headers.get("X-Valet-Role-Token") || "";
      // POST is allowed as soon as the caller's own role token exists. The
      // daemon starts trickling candidates *before* the controller claims
      // the session; gating POST on both tokens caused every daemon
      // candidate to be rejected with 409 until the controller joined,
      // by which time gathering had already finished and the candidates
      // were lost. GET still requires both tokens (otherwise there is no
      // remote peer to read from).
      let role = "";
      if (header && header === daemonToken) role = "daemon";
      else if (header && header === ctrlToken) role = "controller";
      if (!role) return json({ error: "forbidden" }, 403);

      if (req.method === "POST") {
        const body = (await req.json()) as { candidates?: unknown[] };
        const list = Array.isArray(body.candidates) ? body.candidates : [];
        const key = `ice:${role}:${id}`;
        const existing = await loadCandidates(env, key);
        let seq = existing.length > 0 ? existing[existing.length - 1].seq : 0;
        for (const c of list) {
          seq += 1;
          existing.push({ seq, candidate: c });
        }
        await env.VALETFS_KV.put(key, JSON.stringify(existing), { expirationTtl: TTL_SECONDS });
        return json({ accepted: list.length, next: seq });
      }

      if (req.method === "GET") {
        if (!daemonToken || !ctrlToken) return json({ error: "session not ready" }, 409);
        const otherRole = role === "daemon" ? "controller" : "daemon";
        const key = `ice:${otherRole}:${id}`;
        const since = Number(url.searchParams.get("since") || "0");
        const started = Date.now();
        while (Date.now() - started < 25000) {
          const all = await loadCandidates(env, key);
          const filtered = all.filter((e) => e.seq > since);
          if (filtered.length > 0) {
            const next = all[all.length - 1].seq;
            return json({ candidates: filtered.map((e) => e.candidate), next });
          }
          await new Promise((resolve) => setTimeout(resolve, 3000));
        }
        return json({ candidates: [], next: since });
      }
    }

    if (parts[0] === "sessions" && parts.length === 2 && req.method === "DELETE") {
      const id = parts[1];
      const hdr = req.headers.get("X-Valet-Role-Token") || "";
      const dTok = (await getToken(env, id, "daemon")) || "";
      const cTok = (await getToken(env, id, "controller")) || "";
      if (!hdr || (hdr !== dTok && hdr !== cTok)) return json({ error: "forbidden" }, 403);
      await env.VALETFS_KV.delete(`offer:${id}`);
      await env.VALETFS_KV.delete(`answer:${id}`);
      await env.VALETFS_KV.delete(`owner:${id}`);
      await env.VALETFS_KV.delete(`tok:daemon:${id}`);
      await env.VALETFS_KV.delete(`tok:controller:${id}`);
      return new Response(null, { status: 204 });
    }

    return new Response("not found", {
      status: 404,
      headers: { "access-control-allow-origin": "*" },
    });
  },
};

// SessionHub is the Durable Object that hosts one logical session. Both the
// daemon and the vault connect OUTBOUND via WebSocket; the DO relays opaque
// frames between them and emits presence frames so the daemon can drive its
// grace timer. It uses the WebSocket Hibernation API so idle sessions incur no
// duration charges (see control-plane-do-ws-design.md §6).
function presence(sys: string, role: string): string {
  return JSON.stringify({ sys, role });
}

function otherRole(role: string): string {
  return role === "daemon" ? "vault" : "daemon";
}

export class SessionHub {
  state: DurableObjectState;

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const action = url.searchParams.get("do");

    if (action === "create") {
      const token = randomToken();
      let pub = "";
      try {
        const b = (await req.json()) as { pub?: string };
        pub = b.pub || "";
      } catch {
        // no body
      }
      await this.state.storage.put("daemon_token", token);
      if (pub) await this.state.storage.put("daemon_pub", pub);
      return new Response(JSON.stringify({ daemon_token: token }), {
        headers: { "content-type": "application/json" },
      });
    }

    if (action === "presence") {
      // getWebSockets is hibernation-aware: it reports connected sockets even
      // if the DO was evicted from memory. exists reflects a live pairing.
      const daemon = this.state.getWebSockets("daemon").length > 0;
      const vault = this.state.getWebSockets("vault").length > 0;
      const exists = !!(await this.state.storage.get<string>("daemon_token"));
      return new Response(JSON.stringify({ daemon, vault, exists }), {
        headers: { "content-type": "application/json" },
      });
    }

    if (action === "delete") {
      // Close any live sockets and wipe all session storage, releasing the
      // Durable Object's resources.
      for (const ws of this.state.getWebSockets()) {
        try {
          ws.close(1000, "session deleted");
        } catch {
          // ignore
        }
      }
      await this.state.storage.deleteAll();
      return new Response(null, { status: 204 });
    }

    if (action === "claim") {
      let token = (await this.state.storage.get<string>("vault_token")) || "";
      if (!token) {
        token = randomToken();
        await this.state.storage.put("vault_token", token);
      }
      const pub = (await this.state.storage.get<string>("daemon_pub")) || "";
      return new Response(JSON.stringify({ controller_token: token, daemon_pub: pub }), {
        headers: { "content-type": "application/json" },
      });
    }

    if (action === "connect") {
      const role = url.searchParams.get("role") || "";
      const token = url.searchParams.get("token") || "";
      if (role !== "daemon" && role !== "vault") {
        return new Response("bad role", { status: 400 });
      }
      const want = await this.state.storage.get<string>(
        role === "daemon" ? "daemon_token" : "vault_token",
      );
      if (!want || token !== want) {
        return new Response("forbidden", { status: 403 });
      }
      const pair = new WebSocketPair();
      const client = pair[0];
      const server = pair[1];
      // Hibernatable accept, tagged by role so we can find the peer later.
      this.state.acceptWebSocket(server, [role]);
      // Presence: tell the existing peer we are online, and learn about it.
      const peers = this.state.getWebSockets(otherRole(role));
      for (const p of peers) {
        try {
          p.send(presence("peer_online", role));
          server.send(presence("peer_online", otherRole(role)));
        } catch {
          // ignore broken peer
        }
      }
      return new Response(null, { status: 101, webSocket: client });
    }

    return new Response("not found", { status: 404 });
  }

  // Relay every frame to the other role verbatim.
  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const tags = this.state.getTags(ws);
    const role = tags[0] || "";
    for (const p of this.state.getWebSockets(otherRole(role))) {
      try {
        p.send(message);
      } catch {
        // ignore
      }
    }
  }

  async webSocketClose(ws: WebSocket): Promise<void> {
    this.notifyOffline(ws);
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    this.notifyOffline(ws);
  }

  private notifyOffline(ws: WebSocket): void {
    const role = this.state.getTags(ws)[0] || "";
    for (const p of this.state.getWebSockets(otherRole(role))) {
      try {
        p.send(presence("peer_offline", role));
      } catch {
        // ignore
      }
    }
  }
}
