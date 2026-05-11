// VPS wrapper for exit_node.ts — used when you run the exit node on your
// own server (any platform that can run Deno or Bun) instead of on a
// platform that auto-invokes the default export (Deno Deploy, Val.town,
// Cloudflare Workers, etc.).
//
// Pick ONE runtime + matching command:
//
//   Deno (recommended, comes with HTTPS support out of the box):
//     deno run --allow-net --allow-env wrapper.ts
//
//   Bun (also works, slightly faster cold start):
//     bun run wrapper.ts
//
//   Node 22+ (no extra runtime; needs `--experimental-fetch` only on <22):
//     node wrapper.ts                # if your Node has fetch + Bun's
//                                    # global Request/Response (22+)
//
// ENV VARS (all optional):
//   PORT       — TCP port to bind. Default 8443.
//   HOST       — bind address. Default 0.0.0.0 (all interfaces).
//   CERT_FILE  — path to TLS cert PEM. Omit for plain HTTP (use a reverse
//                proxy like Caddy / nginx / Cloudflare Tunnel for TLS).
//   KEY_FILE   — path to TLS key PEM (must be set together with CERT_FILE).
//
// Behind a reverse proxy (Caddy, nginx, Cloudflare Tunnel) you typically
// run this on plain HTTP and let the proxy terminate TLS — that's the
// simpler setup if you already have a domain. Set PORT=8443 and point
// your reverse proxy at http://localhost:8443.
//
// Standalone TLS (rare but supported): set CERT_FILE + KEY_FILE to
// matching PEM-encoded files and Deno will terminate TLS itself. Use
// Let's Encrypt's certbot / acme.sh to fetch a real cert; self-signed
// will not work (Apps Script's UrlFetchApp validates the chain).
//
// EDIT exit_node.ts FIRST: replace the placeholder PSK with a strong
// secret. The wrapper imports the handler from exit_node.ts directly,
// so changing the constant in exit_node.ts is all you need.

import handler from "./exit_node.ts";

// Deno (preferred)
if (typeof (globalThis as any).Deno !== "undefined") {
  const Deno = (globalThis as any).Deno;
  const port = Number(Deno.env.get("PORT") ?? 8443);
  const hostname = Deno.env.get("HOST") ?? "0.0.0.0";
  const certFile = Deno.env.get("CERT_FILE");
  const keyFile = Deno.env.get("KEY_FILE");

  if (certFile && keyFile) {
    Deno.serve(
      {
        port,
        hostname,
        cert: Deno.readTextFileSync(certFile),
        key: Deno.readTextFileSync(keyFile),
      },
      handler,
    );
    console.log(`exit_node listening on https://${hostname}:${port}`);
  } else {
    Deno.serve({ port, hostname }, handler);
    console.log(
      `exit_node listening on http://${hostname}:${port} ` +
        `(no TLS — terminate it with a reverse proxy like Caddy/nginx)`,
    );
  }
}
// Bun
else if (typeof (globalThis as any).Bun !== "undefined") {
  const Bun = (globalThis as any).Bun;
  const port = Number(process.env.PORT ?? 8443);
  const hostname = process.env.HOST ?? "0.0.0.0";

  Bun.serve({
    port,
    hostname,
    fetch: handler,
    tls: process.env.CERT_FILE && process.env.KEY_FILE
      ? {
          cert: Bun.file(process.env.CERT_FILE),
          key: Bun.file(process.env.KEY_FILE),
        }
      : undefined,
  });
  console.log(`exit_node listening on ${hostname}:${port}`);
}
// Node 22+ — uses the built-in `node:http` module + globalThis.Request/Response
else if (typeof (globalThis as any).process !== "undefined") {
  const { createServer } = await import("node:http");
  const port = Number(process.env.PORT ?? 8443);
  const hostname = process.env.HOST ?? "0.0.0.0";

  createServer(async (req, res) => {
    // Build a web-standard Request from Node's IncomingMessage.
    const chunks: Uint8Array[] = [];
    for await (const c of req) chunks.push(c as Uint8Array);
    const body = chunks.length ? Buffer.concat(chunks) : undefined;

    const url = `http://${req.headers.host ?? hostname}${req.url ?? "/"}`;
    const webReq = new Request(url, {
      method: req.method,
      headers: req.headers as Record<string, string>,
      body,
    });

    const webRes = await handler(webReq);

    res.statusCode = webRes.status;
    webRes.headers.forEach((v: string, k: string) => res.setHeader(k, v));
    const buf = new Uint8Array(await webRes.arrayBuffer());
    res.end(buf);
  }).listen(port, hostname, () => {
    console.log(`exit_node listening on http://${hostname}:${port}`);
  });
} else {
  throw new Error(
    "No supported runtime detected. Run this file with Deno, Bun, or Node 22+.",
  );
}
