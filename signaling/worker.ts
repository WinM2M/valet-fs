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
}

const TTL_SECONDS = 300; // 5 minutes

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function randomID(): string {
  const buf = new Uint8Array(16);
  crypto.getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const parts = url.pathname.split("/").filter(Boolean);

    if (req.method === "POST" && parts.length === 1 && parts[0] === "sessions") {
      const { offer } = (await req.json()) as { offer: unknown };
      if (!offer) return json({ error: "missing offer" }, 400);
      const id = randomID();
      await env.VALETFS_KV.put(`offer:${id}`, JSON.stringify(offer), {
        expirationTtl: TTL_SECONDS,
      });
      return json({ session_id: id });
    }

    if (parts[0] === "sessions" && parts.length === 3) {
      const [, id, kind] = parts;
      const key = `${kind}:${id}`;
      if (req.method === "GET") {
        const v = await env.VALETFS_KV.get(key);
        if (!v) return new Response("not found", { status: 404 });
        return json({ [kind]: JSON.parse(v) });
      }
      if (req.method === "POST" && kind === "answer") {
        const { answer } = (await req.json()) as { answer: unknown };
        if (!answer) return json({ error: "missing answer" }, 400);
        await env.VALETFS_KV.put(key, JSON.stringify(answer), {
          expirationTtl: TTL_SECONDS,
        });
        return new Response(null, { status: 204 });
      }
    }

    return new Response("not found", { status: 404 });
  },
};
