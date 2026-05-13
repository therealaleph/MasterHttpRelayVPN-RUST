# mhrv-rs Apps Script Helper (Chrome extension)

English | [فارسی](README.fa.md)

A small **Chrome extension (Manifest V3)** that speeds up **Google Apps Script** setup for **[mhrv-rs](https://github.com/therealaleph/MasterHttpRelayVPN-RUST)** when you use **Apps Script relay mode**. It does not replace the proxy or tunnel; it only helps you generate secrets, pull the canonical `Code.gs`, and build a local `config.json` snippet.

**Maintainer / standalone source:** [ardalan-ab/mhrv-helper-extension](https://github.com/ardalan-ab/mhrv-helper-extension) (recommended).  
**Upstream project:** [therealaleph/MasterHttpRelayVPN-RUST](https://github.com/therealaleph/MasterHttpRelayVPN-RUST).

**Step-by-step for users:** [HOW_TO_USE.md](HOW_TO_USE.md) · [راهنمای فارسی](HOW_TO_USE.fa.md)

---

## What it does

| Step | What you get                                                                                                                                                                                                    |
| ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0    | Opens the latest **mhrv-rs** release asset for your OS (via GitHub API).                                                                                                                                        |
| 1    | Generates a strong random **AUTH_KEY** in the browser (`crypto.getRandomValues`).                                                                                                                               |
| 2    | Loads **Code.gs** from `raw.githubusercontent.com` (canonical path in the main repo), with a **bundled fallback** if the network blocks GitHub. Optional **Check latest Code.gs** compares upstream vs bundled. |
| 3    | Builds a **JSON config snippet** (`apps_script` mode) once you paste your **Deployment ID**.                                                                                                                    |

The popup is available in **English** and **Persian (فارسی)** with **RTL** layout for Persian.

---

## Permissions (why they exist)

- **`storage`**: reserved for future settings; the extension does not need it for core flow today.
- **`clipboardWrite`**: copy auth key, `Code.gs`, and config snippet to the clipboard when you click the copy buttons.
- **Host access**: `script.google.com` (open Apps Script), `raw.githubusercontent.com` (fetch `Code.gs`), `api.github.com` (resolve latest release for downloads).

The **AUTH_KEY** is generated locally. It is **not** sent to any server by this extension; automated smoke tests assert it does not appear in captured network traffic or extension storage during the test run.

---

## Install (load unpacked)

[click here](HOW_TO_USE.md)

Use **View app docs** / **Open setup guide** in the popup for links to the main repository README and guide.

---

## Development and testing

### JSON and script sanity (local)

```bash
python3 -m json.tool manifest.json
python3 -m json.tool messages.json
node --check popup.js
```

### Manual UI (no Chrome APIs)

From this folder:

```bash
python3 -m http.server 8000
```

Open `http://localhost:8000/test.html` in a normal tab (clipboard and `chrome.*` APIs differ from the real extension).

### Automated smoke test (Playwright)

Requires Node.js and a one-time browser install for Playwright:

```bash
npm install
npx playwright install chromium
npm run test:smoke
```

On Linux without a display, use `xvfb-run npm run test:smoke` (as in CI).

### CI — bundled `Code.gs` matches upstream main

- **Standalone extension repo** (this folder is the git root): workflow [`.github/workflows/sync-codegs.yml`](.github/workflows/sync-codegs.yml) downloads `assets/apps_script/Code.gs` from `therealaleph/MasterHttpRelayVPN-RUST` `main` and `cmp`s it to the bundled `Code.gs`.
- **Inside the full monorepo**: the root workflow [`.github/workflows/chrome-extension.yml`](../../.github/workflows/chrome-extension.yml) compares `chrome-extension/Code.gs` with `assets/apps_script/Code.gs` on the same commit.

The popup **Check latest Code.gs** button calls the **GitHub Contents API** for that file, then compares bytes to your bundle and shows the API result (blob short SHA, size, or the API error `message`).

---

## Version

See **`manifest.json`** → `version` (currently aligned with extension releases, e.g. **0.2.0**).

---

## License and upstream

Behavior and `Code.gs` content are defined by the **MasterHttpRelayVPN-RUST** project. Use and distribute this helper in line with the licenses and policies of the upstream repository and the Chrome Web Store if you publish there.
