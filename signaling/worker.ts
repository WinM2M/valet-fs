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
  TURN_DOMAIN?: string;
  TURN_SECRET?: string;
}

const TTL_SECONDS = 300; // 5 minutes

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
  const domain = (env.TURN_DOMAIN || "").trim();
  const secret = (env.TURN_SECRET || "").trim();
  if (!domain || !secret) return out;
  const expiry = Math.floor(Date.now() / 1000) + 10 * 60;
  const username = String(expiry);
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

    if (req.method === "POST" && parts.length === 1 && parts[0] === "sessions") {
      const { offer, role } = (await req.json()) as { offer: unknown; role?: string };
      if (role !== "daemon") return json({ error: "role must be daemon" }, 400);
      if (!offer) return json({ error: "missing offer" }, 400);
      const id = randomID();
      const daemonToken = randomToken();
      await env.VALETFS_KV.put(`offer:${id}`, JSON.stringify(offer), {
        expirationTtl: TTL_SECONDS,
      });
      await env.VALETFS_KV.put(`owner:${id}`, "daemon", { expirationTtl: TTL_SECONDS });
      await env.VALETFS_KV.put(`tok:daemon:${id}`, daemonToken, { expirationTtl: TTL_SECONDS });
      return json({ session_id: id, daemon_token: daemonToken, ttl: TTL_SECONDS });
    }

    if (req.method === "POST" && parts[0] === "sessions" && parts.length === 3 && parts[2] === "claim") {
      const id = parts[1];
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

    if (parts[0] === "sessions" && parts.length === 3) {
      const [, id, kind] = parts;
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
    }

    if (parts[0] === "sessions" && parts.length === 3 && parts[2] === "candidates") {
      const id = parts[1];
      const daemonToken = await getToken(env, id, "daemon");
      const ctrlToken = await getToken(env, id, "controller");
      if (!daemonToken || !ctrlToken) return json({ error: "session not ready" }, 409);
      const header = req.headers.get("X-Valet-Role-Token") || "";
      const role = header === daemonToken ? "daemon" : header === ctrlToken ? "controller" : "";
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
          await new Promise((resolve) => setTimeout(resolve, 250));
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
