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

// tokenEqual compares two secrets without leaking their contents through
// timing. Written in plain JS rather than crypto.subtle.timingSafeEqual, which
// is a Cloudflare-only extension: a security check that cannot run outside the
// Workers runtime cannot be unit tested, and would throw at request time if the
// runtime ever dropped it. Length is compared up front because timing-safe
// comparison needs equal lengths and token length is not secret.
export function tokenEqual(a: string, b: string): boolean {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * SHA-256 hex. The hub stores only the hash of a claim secret, so a dump of its
 * storage does not hand anyone the ability to claim a session.
 */
async function sha256Hex(input: string): Promise<string> {
  const dig = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return Array.from(new Uint8Array(dig), (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * How long a session may sit unclaimed. The session id is printed to a terminal
 * and travels through logs and transcripts, so leaving an unclaimed session
 * valid forever means one stray screenshot stays useful indefinitely.
 */
const UNCLAIMED_TTL_MS = 30 * 60 * 1000;

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
          "access-control-allow-headers": "content-type,x-valet-role-token,x-valet-claim-secret",
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
        const body = (await req.json().catch(() => ({}))) as {
          role?: string; pub?: string; pub_v2?: string; versions?: number[]; claim_secret?: string;
        };
        if (body.role !== "daemon") return json({ error: "role must be daemon" }, 400);
        const sid = randomID();
        const stub = env.SESSION_HUB.get(env.SESSION_HUB.idFromName(sid));
        const r = await stub.fetch("https://do/?do=create", {
          method: "POST",
          body: JSON.stringify({
            pub: body.pub || "",
            pub_v2: body.pub_v2 || "",
            versions: body.versions ?? [],
            claim_secret: body.claim_secret || "",
          }),
        });
        const { daemon_token } = (await r.json()) as { daemon_token: string };
        return json({ session_id: sid, daemon_token });
      }
      // POST /ws/sessions/:id/claim -> {controller_token}
      if (req.method === "POST" && parts.length === 4 && parts[1] === "sessions" && parts[3] === "claim") {
        const sid = parts[2];
        await audit(req, "ws.sessions.claim", sid);
        const stub = env.SESSION_HUB.get(env.SESSION_HUB.idFromName(sid));
        // The secret travels in a header, not the query string: URLs are the
        // one part of a request that reliably ends up in somebody's log.
        const fwd = new URL("https://do/");
        fwd.searchParams.set("do", "claim");
        const r = await stub.fetch(new Request(fwd.toString(), {
          method: "POST",
          headers: { "X-Valet-Claim-Secret": req.headers.get("X-Valet-Claim-Secret") || "" },
        }));
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
      // POST /ws/sessions/:id/pub  {pub}   header X-Valet-Role-Token: daemon_token
      // A daemon that JOINS an app-provisioned session publishes its E2EE public
      // key here (the forward flow publishes it at create time instead).
      if (req.method === "POST" && parts.length === 4 && parts[1] === "sessions" && parts[3] === "pub") {
        const sid = parts[2];
        const stub = env.SESSION_HUB.get(env.SESSION_HUB.idFromName(sid));
        const fwd = new URL("https://do/");
        fwd.searchParams.set("do", "setpub");
        return stub.fetch(new Request(fwd.toString(), req));
      }
      // DELETE /ws/sessions/:id  -> tear down the session (frees DO storage +
      // closes any open sockets). Used by the app's "Forget daemon".
      //
      // Requires X-Valet-Role-Token. Deleting a session makes the daemon
      // self-lock (unmount + wipe) once its reconnect window expires, so an
      // unauthenticated delete is a remote wipe of somebody else's secrets by
      // anyone who learns the session id. The header must be forwarded to the
      // DO explicitly; stub.fetch with a bare URL drops it.
      if (req.method === "DELETE" && parts.length === 3 && parts[1] === "sessions") {
        const sid = parts[2];
        await audit(req, "ws.sessions.delete", sid);
        const stub = env.SESSION_HUB.get(env.SESSION_HUB.idFromName(sid));
        const fwd = new URL("https://do/");
        fwd.searchParams.set("do", "delete");
        return stub.fetch(new Request(fwd.toString(), {
          method: "POST",
          headers: { "X-Valet-Role-Token": req.headers.get("X-Valet-Role-Token") || "" },
        }));
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

/**
 * True if a frame a peer sent claims to be a presence/system frame.
 *
 * Presence drives the daemon's grace timer: peer_offline starts the countdown
 * that unmounts and wipes, peer_online cancels it. The hub emits those itself,
 * but the relay used to forward frames verbatim, so either peer could forge
 * them — sending peer_offline to destroy the other side's secrets, or a steady
 * drip of peer_online to stop a daemon ever auto-locking. Peers do not get to
 * speak the hub's language.
 *
 * Everything is parsed rather than prefix-matched, because the sender chooses
 * the key order and any cheaper check is one the forger simply routes around.
 */
export function isSystemFrame(message: string | ArrayBuffer): boolean {
  let text: string;
  if (typeof message === "string") {
    text = message;
  } else {
    try {
      text = new TextDecoder().decode(message);
    } catch {
      return false;
    }
  }
  try {
    const parsed = JSON.parse(text);
    return !!parsed && typeof parsed === "object" && "sys" in parsed;
  } catch {
    return false; // not JSON: opaque app payload, relay it
  }
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
      let pubV2 = "";
      let versions: number[] = [];
      let claimSecret = "";
      // Server clock, deliberately. A caller-supplied timestamp would let the
      // holder of a stale session id claim it was created a moment ago and walk
      // straight past the expiry.
      const createdAt = Date.now();
      try {
        const b = (await req.json()) as {
          pub?: string; pub_v2?: string; versions?: number[]; claim_secret?: string;
        };
        pub = b.pub || "";
        pubV2 = b.pub_v2 || "";
        versions = Array.isArray(b.versions) ? b.versions : [];
        claimSecret = b.claim_secret || "";
      } catch {
        // no body
      }
      await this.state.storage.put("daemon_token", token);
      await this.state.storage.put("created_at", createdAt);
      if (pub) await this.state.storage.put("daemon_pub", pub);
      if (pubV2) await this.state.storage.put("daemon_pub_v2", pubV2);
      if (versions.length) await this.state.storage.put("versions", versions);
      // Only the hash. The secret itself exists in the QR or the connection key
      // and nowhere on this server.
      if (claimSecret) {
        await this.state.storage.put("claim_hash", await sha256Hex(claimSecret));
      }
      return new Response(JSON.stringify({ daemon_token: token }), {
        headers: { "content-type": "application/json" },
      });
    }

    if (action === "setpub") {
      const token = await this.state.storage.get<string>("daemon_token");
      const hdr = req.headers.get("X-Valet-Role-Token") || "";
      if (!token || hdr !== token) return new Response("forbidden", { status: 403 });
      let pub = "";
      let pubV2 = "";
      let versions: number[] = [];
      try {
        const b = (await req.json()) as { pub?: string; pub_v2?: string; versions?: number[] };
        pub = b.pub || "";
        pubV2 = b.pub_v2 || "";
        versions = Array.isArray(b.versions) ? b.versions : [];
      } catch {
        // no body
      }
      // Same first-writer-wins rule as daemon_pub: a party that later obtains
      // the token cannot swap the identity a client is about to authenticate.
      if (pubV2) {
        const existingV2 = await this.state.storage.get<string>("daemon_pub_v2");
        if (existingV2 && existingV2 !== pubV2) {
          return new Response("daemon_pub_v2 already set", { status: 409 });
        }
        await this.state.storage.put("daemon_pub_v2", pubV2);
      }
      // Relayed verbatim and never interpreted here. Clients treat this list as
      // an unauthenticated hint and re-check it against what the daemon reports
      // inside the encrypted channel, precisely because this hub could edit it.
      if (versions.length) await this.state.storage.put("versions", versions);
      if (pub) {
        // First-writer-wins: the pubkey is immutable once set, so a party that
        // later obtains the token cannot swap the E2EE key mid-session.
        const existing = await this.state.storage.get<string>("daemon_pub");
        if (existing && existing !== pub) {
          return new Response("daemon_pub already set", { status: 409 });
        }
        await this.state.storage.put("daemon_pub", pub);
      }
      return new Response(null, { status: 204 });
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
      const hdr = req.headers.get("X-Valet-Role-Token") || "";
      const dTok = (await this.state.storage.get<string>("daemon_token")) || "";
      const vTok = (await this.state.storage.get<string>("vault_token")) || "";
      if (!dTok && !vTok) {
        // Nothing was ever provisioned here, so there is nothing to protect and
        // nothing to tear down. Stay idempotent for the app's "forget" flow.
        return new Response(null, { status: 204 });
      }
      if (!tokenEqual(hdr, dTok) && !tokenEqual(hdr, vTok)) {
        return new Response("forbidden", { status: 403 });
      }
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
      // The session id used to be the whole credential: anyone who learned it
      // could claim, connect as the vault, and read the entire vault with
      // MANIFEST and PULL. It is printed to a terminal and ends up in logs,
      // screenshots and agent transcripts, so it is an identifier, not a secret.
      //
      // The claim secret is the credential now. It travels only out of band —
      // inside the QR, or inside the connection key the user carries — which is
      // what finally makes "I scanned this screen" mean something to the daemon
      // rather than only to the person holding the phone.
      const claimHash = await this.state.storage.get<string>("claim_hash");
      const offered = req.headers.get("X-Valet-Claim-Secret") || "";
      if (claimHash) {
        if (!offered || !tokenEqual(await sha256Hex(offered), claimHash)) {
          return new Response("forbidden", { status: 403 });
        }
      }

      const now = Date.now();
      const createdAt = (await this.state.storage.get<number>("created_at")) || 0;
      const existing = await this.state.storage.get<string>("vault_token");
      if (!existing && claimHash && createdAt && now - createdAt > UNCLAIMED_TTL_MS) {
        return new Response("session expired", { status: 410 });
      }

      let token = existing || "";
      if (!token) {
        token = randomToken();
        await this.state.storage.put("vault_token", token);
        // One shot. A second holder of the secret — someone who photographed
        // the screen — gets nothing, and the first claimant is told a claim
        // already happened so a stolen scan does not pass unnoticed.
        await this.state.storage.put("claimed_at", now);
      }
      const pub = (await this.state.storage.get<string>("daemon_pub")) || "";
      const pubV2 = (await this.state.storage.get<string>("daemon_pub_v2")) || "";
      const versions = (await this.state.storage.get<number[]>("versions")) || [];
      const claimedAt = (await this.state.storage.get<number>("claimed_at")) || 0;
      return new Response(JSON.stringify({
        controller_token: token, daemon_pub: pub, daemon_pub_v2: pubV2, versions,
        // Surfaces "somebody already claimed this" to whoever asks second.
        first_claim: existing ? false : true,
        claimed_at: claimedAt,
      }), { headers: { "content-type": "application/json" } });
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
      // One socket per role, with the newest winning rather than the oldest.
      //
      // Refusing the newcomer looked safer and was not. A phone that loses
      // signal, or is backgrounded before it can close cleanly, leaves a socket
      // the hub still counts — and then blocks its own return, which is what a
      // user sees as a session that will not connect. The thing that stops an
      // impostor taking the vault role is the claim secret, not this; by the
      // time execution reaches here the caller has already proved it holds the
      // role token.
      for (const stale of this.state.getWebSockets(role)) {
        try {
          stale.close(1000, "replaced by a newer connection");
        } catch {
          // already gone
        }
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

  // Relay every frame to the other role, except the ones only the hub may send.
  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (isSystemFrame(message)) return;
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
