# Tunnel Node

HTTP tunnel bridge server for MasterHttpRelayVPN "full" mode. Bridges HTTP tunnel requests (from Apps Script) to real TCP connections.

## Architecture

```
Phone → mhrv-rs → [domain-fronted TLS] → Apps Script → [HTTP] → Tunnel Node → [real TCP] → Internet
```

The tunnel node manages persistent TCP and UDP sessions. TCP sessions are real TCP connections to a destination server; UDP sessions are connected UDP sockets to one destination host:port. Data flows through a JSON protocol:

- **connect** — open TCP to host:port, return session ID
- **data** — write client data, return server response
- **udp_open** — open UDP to host:port, optionally send the first datagram
- **udp_data** — send one UDP datagram, or poll for returned datagrams when `d` is omitted
- **close** — tear down session
- **batch** — process multiple ops in one HTTP request (reduces round trips)

## Deployment

> **Cloud Run vs VPS**: Cloud Run works for TCP-only traffic but **does not support UDP responses** — outbound UDP packets are sent but replies never reach the container. If you need UDP forwarding (udpgw for Telegram calls, QUIC, DNS-over-UDP, etc.), deploy on a **VPS** instead. The Docker and direct-binary methods below all work on any VPS with full UDP support.

### Cloud Run (TCP only)

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

Cloud Run is the easiest deployment path but UDP-based features (udpgw) will not work. Use a VPS if you need UDP.

### Docker — prebuilt image (any VPS)

The fastest path. Pull a prebuilt image and run it; no Rust toolchain needed on the VPS.

```bash
# Generate a strong secret. Save it — you'll paste the same value into CodeFull.gs.
SECRET=$(openssl rand -hex 24)
echo "Your TUNNEL_AUTH_KEY: $SECRET"

# Pull + run.
docker run -d \
  --name mhrv-tunnel \
  --restart unless-stopped \
  -p 8080:8080 \
  -e TUNNEL_AUTH_KEY="$SECRET" \
  ghcr.io/therealaleph/mhrv-tunnel-node:latest
```

The `:latest` tag tracks the most recent release. To pin a specific version (recommended for production), use `ghcr.io/therealaleph/mhrv-tunnel-node:v1.5.0` (or whatever release you're on). Image is available for `linux/amd64` and `linux/arm64`.

**docker-compose.yml** if you prefer:

```yaml
services:
  tunnel:
    image: ghcr.io/therealaleph/mhrv-tunnel-node:latest
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      TUNNEL_AUTH_KEY: ${TUNNEL_AUTH_KEY}
```

Then `TUNNEL_AUTH_KEY=your-secret docker compose up -d`.

### Docker — build from source

If you'd rather build the image yourself (or add custom changes):

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
    {"op":"udp_data","sid":"uuid2","d":"base64"},
    {"op":"close","sid":"uuid3"}
  ]
}
→ {"r": [{...}, {...}, {...}]}
```

### Health check: `GET /health` → `ok`

## UDP forwarding (udpgw)

The tunnel-node includes a native implementation of the [tun2proxy udpgw](https://github.com/tun2proxy/tun2proxy) wire protocol. When the client opens a tunnel session to the magic address `198.18.0.1:7300`, the tunnel-node creates a virtual session that speaks the udpgw binary protocol instead of raw TCP passthrough. This enables UDP traffic (DNS, QUIC, Telegram VoIP, etc.) to flow through the existing HTTP tunnel.

**Requirements:**
- **VPS deployment** — Cloud Run does not support inbound UDP responses. Deploy on a VPS (Docker or direct binary) for udpgw to work.
- **Android client** — the forked tun2proxy with udpgw JNI support passes `--udpgw-server 198.18.0.1:7300` when in full mode. Desktop clients can use any tun2socks/tun2proxy binary with `--udpgw-server`.

**How it works:**
1. tun2proxy captures a UDP packet and opens a TCP connection to `198.18.0.1:7300` through the SOCKS5 proxy
2. The TCP connection flows through the tunnel pipeline (mhrv-rs → Apps Script → tunnel-node)
3. The tunnel-node detects the magic address and creates an in-process udpgw session (no real TCP connection)
4. UDP datagrams are encapsulated in udpgw frames, sent as real UDP from the VPS, and responses flow back the same path

## Performance: deployment count and pipeline depth

The mhrv-rs client runs a pipelined batch multiplexer in full mode. Each Apps Script round-trip takes ~2s, so the client fires multiple batch requests concurrently — the pipeline depth equals the number of configured script deployment IDs (minimum 2, no upper cap).

More deployments = more concurrent batches hitting the tunnel-node = lower per-session latency. With 6 deployments, a new batch arrives every ~0.3s instead of every 2s.

The tunnel-node itself is stateless per-request (sessions are keyed by UUID), so it handles concurrent batches naturally. For best results, deploy 3–12 Apps Script instances across separate Google accounts and list all their deployment IDs in the client config.
