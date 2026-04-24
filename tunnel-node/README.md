# Tunnel Node

HTTP tunnel bridge server for MasterHttpRelayVPN "full" mode. Bridges HTTP tunnel requests (from Apps Script) to real TCP connections.

## Architecture

```
Phone → mhrv-rs → [domain-fronted TLS] → Apps Script → [HTTP] → Tunnel Node → [real TCP] → Internet
```

The tunnel node manages persistent TCP sessions. Each session is a real TCP connection to a destination server. Data flows through a JSON protocol:

- **connect** — open TCP to host:port, return session ID
- **data** — write client data, return server response
- **close** — tear down session
- **batch** — process multiple ops in one HTTP request (reduces round trips)

## Deployment

### Cloud Run

```bash
cd tunnel-node
gcloud run deploy tunnel-node \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars TUNNEL_AUTH_KEY=$(openssl rand -hex 24) \
  --memory 256Mi \
  --cpu 1 \
  --max-instances 1
```

### Docker (any VPS)

```bash
cd tunnel-node
docker build -t tunnel-node .
docker run -p 8080:8080 -e TUNNEL_AUTH_KEY=your-secret tunnel-node
```

### Direct binary

```bash
cd tunnel-node
cargo build --release
TUNNEL_AUTH_KEY=your-secret PORT=8080 ./target/release/tunnel-node
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TUNNEL_AUTH_KEY` | Yes | `changeme` | Shared secret — must match `TUNNEL_AUTH_KEY` in CodeFull.gs |
| `PORT` | No | `8080` | Listen port (Cloud Run sets this automatically) |

## Protocol

### Single op: `POST /tunnel`

```json
{"k":"auth","op":"connect","host":"example.com","port":443}
{"k":"auth","op":"data","sid":"uuid","data":"base64"}
{"k":"auth","op":"close","sid":"uuid"}
```

### Batch: `POST /tunnel/batch`

```json
{
  "k": "auth",
  "ops": [
    {"op":"data","sid":"uuid1","d":"base64"},
    {"op":"data","sid":"uuid2","d":"base64"},
    {"op":"close","sid":"uuid3"}
  ]
}
→ {"r": [{...}, {...}, {...}]}
```

### Health check: `GET /health` → `ok`

## Performance: deployment count and pipeline depth

The mhrv-rs client runs a pipelined batch multiplexer in full mode. Each Apps Script round-trip takes ~2s, so the client fires multiple batch requests concurrently — the pipeline depth equals the number of configured script deployment IDs (minimum 2, no upper cap).

More deployments = more concurrent batches hitting the tunnel-node = lower per-session latency. With 6 deployments, a new batch arrives every ~0.3s instead of every 2s.

The tunnel-node itself is stateless per-request (sessions are keyed by UUID), so it handles concurrent batches naturally. For best results, deploy 3–12 Apps Script instances across separate Google accounts and list all their deployment IDs in the client config.
