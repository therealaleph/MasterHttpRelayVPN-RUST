# cloudflared Quick Tunnel

Run a Full tunnel for 6 hours with **zero account setup** beyond GitHub.
Cloudflare's free Quick Tunnel service provides a temporary public URL — no
Cloudflare account, no API token, no configuration files required.

## Prerequisites

- A GitHub account (free)
- `CodeFull.gs` deployed as a Google Apps Script Web App
- No Cloudflare account or ngrok account needed

## Setup

### Step 1: Create the Repository

1. Go to [github.com](https://github.com) and sign in
2. Click the **+** icon in the top-right corner, then **New repository**
3. Enter a repository name (e.g., `my-tunnel`)
4. Select **Private** (recommended — keeps your secrets secure)
5. Click **Create repository**

### Step 2: Add the Secret

1. In your new repository, go to **Settings > Secrets and variables > Actions**
2. Click **New repository secret**
3. Set **Name** to `TUNNEL_AUTH_KEY`
4. Set **Value** to a strong password of your choice
5. Click **Add secret**

You will use this same password later in `CodeFull.gs`.

### Step 3: Add the Workflow

1. In your repository, go to the **Actions** tab
2. Click **New workflow** (or go to the next step)
3. Click the **set up a workflow yourself** link
4. Delete the default content (if exists) and paste the contents of `cloudflared-quick.yml` [[here]]
5. Click **Commit changes...**, add a commit message, then click **Commit changes**

The workflow file will be saved to `.github/workflows/main.yml`.
(name does not matter and you can change it to anything)

### Step 4: Run the Workflow

1. Go to the **Actions** tab
2. Select **Full Tunnel (cloudflared Quick)** from the left sidebar
3. Click **Run workflow > Run workflow**

The workflow will start immediately.

### Step 5: Get the Tunnel URL

1. Click on the running workflow to see live logs
2. Wait for the **Expose tunnel** step to complete (about 15 seconds)
3. Look for the `::notice::Tunnel URL:` line in the log output
4. Copy the URL — it will look like `https://random-name.trycloudflare.com`

### Step 6: Configure CodeFull.gs

Open `CodeFull.gs` in the Google Apps Script editor and update these constants:

```javascript
const TUNNEL_SERVER_URL = "https://random-name.trycloudflare.com";
const TUNNEL_AUTH_KEY = "the-secret-you-set-in-step-2";
```

Deploy: **Deploy > New Deployment > Web App**.
Copy the new Deployment ID and update your `mhrv-rs` config.

### Step 7: Verify

Use `mhrv-rs test` or visit `https://ipleak.net` through your proxy.

## How It Works

1. GitHub Actions starts a Docker container running `mhrv-tunnel-node` on port
   `8080`
2. `cloudflared` creates a free Quick Tunnel — a temporary `*.trycloudflare.com`
   subdomain that routes to `localhost:8080` on the runner
3. The workflow extracts this URL from the `cloudflared` logs and displays it
4. `CodeFull.gs` forwards tunnel operations to this URL over HTTPS
5. The runner stays alive for 6 hours, then shuts down automatically

No DNS configuration, no SSL certificates, no port forwarding — `cloudflared`
handles everything.

## Renewing the Tunnel

The tunnel shuts down after 6 hours. To start a new session:

1. Go to the **Actions** tab
2. Select **Full Tunnel (cloudflared Quick)**
3. Click **Run workflow > Run workflow**
4. Copy the **new** tunnel URL from the logs (it changes each time)
5. Update `TUNNEL_SERVER_URL` in `CodeFull.gs` and redeploy

## Limitations

- The `*.trycloudflare.com` URL changes every time the workflow runs
- `CodeFull.gs` must be updated and redeployed each session
- 6-hour maximum per session (GitHub Actions limit)

## Troubleshooting

| Problem | Solution |
|---|---|
| Workflow fails at Docker step | GitHub Actions may be pulling the image for the first time. Wait 2-3 minutes and retry. |
| No tunnel URL appears in logs | Check that the **Expose tunnel** step completed. The URL is extracted from `cloudflared` output — allow 15 seconds for the tunnel to establish. |
| `CodeFull.gs` returns 502 or timeout | Verify the tunnel URL is correct and the workflow is still running. Check that `TUNNEL_AUTH_KEY` matches in both the secret and `CodeFull.gs`. |

[here]: cloudflared-quick.yml
