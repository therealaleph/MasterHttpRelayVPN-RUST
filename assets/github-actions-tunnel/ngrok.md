# ngrok Tunnel

Run a Full tunnel for 6 hours using an ngrok account (free tier). ngrok provides
a public URL that exposes the tunnel-node running on GitHub Actions.

## Prerequisites

- A GitHub account (free)
- An ngrok account (free — sign up at [ngrok.com](https://ngrok.com))
- `CodeFull.gs` deployed as a Google Apps Script Web App

## Setup

### Step 1: Get Your ngrok Authtoken

1. Go to [dashboard.ngrok.com](https://dashboard.ngrok.com) and sign in
2. Copy your authtoken from the **Getting Started** or **Your Authtoken** section

### Step 2: Create the Repository

If you already have a repository from another method, you can reuse it.
Otherwise:

1. Go to [github.com](https://github.com) and sign in
2. Click the **+** icon in the top-right corner, then **New repository**
3. Enter a repository name (e.g., `my-tunnel`)
4. Select **Private** (recommended — keeps your secrets secure)
5. Click **Create repository**

### Step 3: Add the Secrets

1. In your repository, go to **Settings > Secrets and variables > Actions**
2. Click **New repository secret** and add:

   | Name | Value |
   |---|---|
   | `TUNNEL_AUTH_KEY` | A strong password. You will also set this in `CodeFull.gs`. |
   | `NGROK_AUTH_TOKEN` | Your ngrok authtoken from Step 1. |

3. Click **Add secret** for each

### Step 4: Add the Workflow

1. In your repository, go to the **Actions** tab
2. Click **New workflow**
3. Click the **set up a workflow yourself** link
4. Delete the default content and paste the contents of `ngrok.yml`
5. Click **Commit changes...**, add a commit message, then click **Commit changes**

The workflow file will be saved to `.github/workflows/ngrok.yml`.

### Step 5: Run the Workflow

1. Go to the **Actions** tab
2. Select **Full Tunnel (ngrok)** from the left sidebar
3. Click **Run workflow > Run workflow**

The workflow will start immediately.

### Step 6: Get the Tunnel URL

1. Click on the running workflow to see live logs
2. Wait for the **Expose tunnel** step to complete (about 10 seconds)
3. Look for the `::notice::Tunnel URL:` line in the log output
4. Copy the URL — it will look like `https://abc123.ngrok-free.app`

### Step 7: Configure CodeFull.gs

Open `CodeFull.gs` in the Google Apps Script editor and update these constants:

```javascript
const TUNNEL_SERVER_URL = "https://abc123.ngrok-free.app";
const TUNNEL_AUTH_KEY = "the-secret-you-set-in-step-3";
```

Deploy: **Deploy > New Deployment > Web App**.
Copy the new Deployment ID and update your `mhrv-rs` config.

### Step 8: Verify

Use `mhrv-rs test` or visit `https://ipleak.net` through your proxy.
You should see a GitHub Actions or ngrok IP address.

## How It Works

1. GitHub Actions starts a Docker container running `mhrv-tunnel-node` on port
   `8080`
2. `ngrok` creates a secure tunnel using your authtoken, assigning a temporary
   `*.ngrok-free.app` URL that routes to `localhost:8080` on the runner
3. The workflow extracts this URL from the ngrok API and displays it
4. `CodeFull.gs` forwards tunnel operations to this URL over HTTPS
5. The runner stays alive for 6 hours, then shuts down automatically

## Renewing the Tunnel

The tunnel shuts down after 6 hours. To start a new session:

1. Go to the **Actions** tab
2. Select **Full Tunnel (ngrok)**
3. Click **Run workflow > Run workflow**
4. Copy the **new** tunnel URL from the logs (it changes each time)
5. Update `TUNNEL_SERVER_URL` in `CodeFull.gs` and redeploy

## Limitations

- Requires an ngrok account (free tier: 1 online tunnel, limited connections
  per minute)
- The `*.ngrok-free.app` URL changes every time the workflow runs
- `CodeFull.gs` must be updated and redeployed each session
- 6-hour maximum per session (GitHub Actions limit)
- Slightly higher latency than cloudflared methods (extra hop through ngrok's
  relay servers)

## Troubleshooting

| Problem | Solution |
|---|---|
| ngrok authentication fails | Verify `NGROK_AUTH_TOKEN` matches the token in your [ngrok dashboard](https://dashboard.ngrok.com). |
| Workflow fails at Docker step | GitHub Actions may be pulling the image for the first time. Wait 2-3 minutes and retry. |
| No tunnel URL appears in logs | Check that the **Expose tunnel** step completed. The URL is fetched from the ngrok API — allow 10 seconds for the tunnel to establish. |
| Connection limit reached | ngrok's free tier limits connections per minute. Wait a moment and retry. |
| `CodeFull.gs` returns 502 or timeout | Verify the tunnel URL is correct and the workflow is still running. Check that `TUNNEL_AUTH_KEY` matches in both the secret and `CodeFull.gs`. |
