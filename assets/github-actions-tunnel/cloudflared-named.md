# cloudflared Named Tunnel

Run a Full tunnel with a **permanent, unchanging URL** using a Cloudflare
account and a custom domain. The tunnel URL never changes between restarts —
configure `CodeFull.gs` once and only re-trigger the workflow when needed.

## Prerequisites

- A GitHub account (free)
- A Cloudflare account with a domain
- `cloudflared` installed on your local machine for one-time setup
- `CodeFull.gs` deployed as a Google Apps Script Web App

## One-Time Local Setup

These steps are performed **once** on your local machine. They create a named
tunnel on Cloudflare and route your domain to it.

### Step 1: Install cloudflared

**Linux (Debian/Ubuntu):**
```bash
curl -L --output cloudflared.deb \
  https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared.deb
```

**macOS:**
```bash
brew install cloudflared
```

**Windows:**
Download the installer from the [cloudflared releases page](https://github.com/cloudflare/cloudflared/releases).

### Step 2: Authenticate with Cloudflare

```bash
cloudflared tunnel login
```

This opens a browser window. Select your domain and authorize.

### Step 3: Create a Named Tunnel

```bash
cloudflared tunnel create my-tunnel
```

This outputs a tunnel ID (a UUID) and creates a credentials file at:
```
~/.cloudflared/<TUNNEL_ID>.json
```

Copy the tunnel ID — you will need it later.

### Step 4: Route Your Domain

```bash
cloudflared tunnel route dns my-tunnel tunnel.yourdomain.com
```

Replace `tunnel.yourdomain.com` with the actual subdomain you want to use.
This creates a DNS record on Cloudflare pointing to your tunnel.

### Step 5: Get the Credentials File

```bash
cat ~/.cloudflared/<TUNNEL_ID>.json
```

Copy the entire JSON output. You will use this as the
`CLOUDFLARE_TUNNEL_CREDENTIALS` secret in GitHub Actions.

## GitHub Setup

### Step 6: Create the Repository

If you already have a repository from another method, you can reuse it.
Otherwise:

1. Go to [github.com](https://github.com) and sign in
2. Click the **+** icon in the top-right corner, then **New repository**
3. Enter a repository name (e.g., `my-tunnel`)
4. Select **Private** (recommended — keeps your secrets secure)
5. Click **Create repository**

### Step 7: Add the Secrets

1. In your repository, go to **Settings > Secrets and variables > Actions**
2. Click **New repository secret** and add each of the following:

   | Name | Value |
   |---|---|
   | `TUNNEL_AUTH_KEY` | A strong password. You will also set this in `CodeFull.gs`. |
   | `CLOUDFLARE_TUNNEL_ID` | The tunnel ID from Step 3. |
   | `CLOUDFLARE_TUNNEL_HOSTNAME` | The subdomain you configured in Step 4 (e.g., `tunnel.yourdomain.com`). |
   | `CLOUDFLARE_TUNNEL_CREDENTIALS` | The entire JSON contents of the credentials file from Step 5. |

3. Click **Add secret** for each

### Step 8: Add the Workflow

1. In your repository, go to the **Actions** tab
2. Click **New workflow**
3. Click the **set up a workflow yourself** link
4. Delete the default content and paste the contents of `cloudflared-named.yml` [[here]]
5. Click **Commit changes...**, add a commit message, then click **Commit changes**

The workflow file will be saved to `.github/workflows/cloudflared-named.yml`.

### Step 9: Run the Workflow

1. Go to the **Actions** tab
2. Select **Full Tunnel (cloudflared Named)** from the left sidebar
3. Click **Run workflow > Run workflow**

The workflow will start immediately.

### Step 10: Configure CodeFull.gs

Open `CodeFull.gs` in the Google Apps Script editor and update these constants:

```javascript
const TUNNEL_SERVER_URL = "https://tunnel.yourdomain.com";
const TUNNEL_AUTH_KEY = "the-secret-you-set-in-step-7";
```

Deploy: **Deploy > New Deployment > Web App**.
Copy the new Deployment ID and update your `mhrv-rs` config.

**This step is performed only once.** The tunnel URL never changes between
restarts.

### Step 11: Verify

Use `mhrv-rs test` or visit `https://ipleak.net` through your proxy.
You should see a Cloudflare IP address.

## How It Works

1. GitHub Actions starts a Docker container running `mhrv-tunnel-node` on port
   `8080`
2. `cloudflared` connects to Cloudflare using the named tunnel credentials
3. Cloudflare routes traffic from your custom domain to the runner through a
   secure, persistent tunnel
4. `CodeFull.gs` forwards tunnel operations to your custom domain over HTTPS
5. The runner stays alive for 6 hours, then shuts down automatically
6. On restart, the same domain routes to the new runner — no configuration
   changes needed

## Restarting the Tunnel

The tunnel shuts down after 6 hours. To start a new session:

1. Go to the **Actions** tab
2. Select **Full Tunnel (cloudflared Named)**
3. Click **Run workflow > Run workflow**

That is all — the URL is permanent so `CodeFull.gs` does not need to be updated.

For automatic restarts every 6 hours, add a `schedule` trigger to the workflow:

```yaml
on:
  workflow_dispatch:
  schedule:
    - cron: '0 */6 * * *'
```

## Limitations

- Requires a one-time local setup with `cloudflared` CLI
- Requires a Cloudflare account with a domain
- 6-hour maximum per session (GitHub Actions limit)

## Troubleshooting

| Problem | Solution |
|---|---|
| `cloudflared tunnel login` fails | Ensure your browser can reach `dash.cloudflare.com`. You may need to use a proxy or alternative network for this step. |
| `cloudflared tunnel create` fails | Verify you are authenticated. Run `cloudflared tunnel login` again. |
| Workflow fails at Docker step | GitHub Actions may be pulling the image for the first time. Wait 2-3 minutes and retry. |
| `cloudflared` fails to connect | Verify all four secrets are set correctly. Check that `CLOUDFLARE_TUNNEL_CREDENTIALS` contains valid JSON. |
| `CodeFull.gs` returns 502 or timeout | Verify the workflow is still running. Check that `TUNNEL_AUTH_KEY` matches in both the secret and `CodeFull.gs`. Ensure the DNS record was created in Step 4. |

[here]: cloudflared-named.yml
