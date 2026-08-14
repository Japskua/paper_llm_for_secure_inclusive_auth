/**
 * HARNESS — not part of any evaluated artifact.
 *
 * The six artifacts are Bun servers that serve HTTPS only and, in three cases,
 * accept state-changing requests only from a localhost origin. Cloudflare
 * reaches a container over plain HTTP on one port, from a public hostname, so
 * without this shim the artifacts would either refuse to speak (no TLS) or
 * reject every POST (origin check).
 *
 * This process therefore:
 *   1. listens on plain HTTP for Cloudflare, on PROXY_PORT (8080),
 *   2. forwards to the artifact's HTTPS port, ignoring its self-signed cert,
 *   3. presents the request to the artifact as if it came from
 *      https://localhost:<APP_PORT>, which is the only origin three of the
 *      artifacts trust.
 *
 * app.ts is never modified. Its SHA-256 still matches batch_manifest.json.
 * The origin check itself is intact in the source the security experts read;
 * only this deployment shim satisfies it from outside.
 */

const APP_PORT = Number(process.env.APP_PORT || 8443);
const PROXY_PORT = Number(process.env.PROXY_PORT || 8080);
const LOCAL_ORIGIN = `https://localhost:${APP_PORT}`;

// Headers that must not be copied verbatim between hops.
const HOP_BY_HOP = new Set([
  "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
  "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length",
]);

function toArtifact(request: Request) {
  const incoming = new URL(request.url);
  const target = new URL(incoming.pathname + incoming.search, LOCAL_ORIGIN);

  const headers = new Headers();
  for (const [k, v] of request.headers) {
    if (!HOP_BY_HOP.has(k.toLowerCase())) headers.set(k, v);
  }
  headers.set("host", `localhost:${APP_PORT}`);

  // Present every request as same-origin against the artifact's own view of
  // itself. Only rewrite headers that were actually sent, so a request with no
  // Origin still looks like one with no Origin.
  if (request.headers.has("origin")) headers.set("origin", LOCAL_ORIGIN);
  if (request.headers.has("referer")) {
    try {
      const ref = new URL(request.headers.get("referer")!);
      headers.set("referer", LOCAL_ORIGIN + ref.pathname + ref.search);
    } catch {
      headers.set("referer", LOCAL_ORIGIN + "/");
    }
  }
  headers.set("x-forwarded-proto", "https");
  headers.set("x-forwarded-host", incoming.host);

  return [target, {
    method: request.method,
    headers,
    body: request.body,
    redirect: "manual",
    // Bun-specific: the artifact's certificate is self-signed, and this hop
    // never leaves the container.
    tls: { rejectUnauthorized: false },
    duplex: "half",
  }] as const;
}

function toClient(response: Response, publicHost: string): Response {
  const headers = new Headers(response.headers);
  // Any absolute redirect the artifact issues points at its localhost origin;
  // send the browser back to the public host instead.
  const location = headers.get("location");
  if (location) {
    try {
      const url = new URL(location, LOCAL_ORIGIN);
      if (url.host === `localhost:${APP_PORT}`) {
        headers.set("location", url.pathname + url.search);
      }
    } catch { /* leave a malformed Location alone */ }
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

Bun.serve({
  port: PROXY_PORT,
  hostname: "0.0.0.0",
  idleTimeout: 120,
  async fetch(request) {
    try {
      const [url, init] = toArtifact(request);
      const upstream = await fetch(url, init as RequestInit);
      return toClient(upstream, new URL(request.url).host);
    } catch (error) {
      console.error("[proxy] upstream failed:", error);
      return new Response("The evaluated application is not responding.", {
        status: 502,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }
  },
});

console.log(`[proxy] http://0.0.0.0:${PROXY_PORT} -> ${LOCAL_ORIGIN}`);
