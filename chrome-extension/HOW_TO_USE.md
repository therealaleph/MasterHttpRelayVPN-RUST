# How to use the mhrv-rs Apps Script Helper (Chrome)

[فارسی](HOW_TO_USE.fa.md)

This guide is for **end users** who want the extension to help with Apps Script setup for [mhrv-rs](https://github.com/therealaleph/MasterHttpRelayVPN-RUST). You still deploy the script in **your** Google account and run **mhrv-rs** on your computer; the extension only prepares text and opens links.

---

## 1. Install the extension (unpacked)

1. Get the extension folder (the directory that contains `manifest.json`):
   - **Recommended:** clone [ardalan-ab/mhrv-helper-extension](https://github.com/ardalan-ab/mhrv-helper-extension) and use the **repo root**.

2. Go to ( chrome://extensions/ )
3. Click on **Devloper mode** 
4. Click **Load unpacked** and select that folder.
5. (Optional) Pin the extension from the puzzle icon so it stays in the toolbar.

---

## 2. Open the popup and pick a language

1. Click the extension icon.
2. In the header, choose **English** or **فارسی**. Persian uses RTL layout.

---

## 3. Download mhrv-rs (optional but useful)

In **Step 0**:

- Click **Download mhrv-rs** — Chrome opens the release asset the extension picks for your OS (from GitHub).
- Or use **View all releases** if you want to choose another build (Android, musl, etc.).

Unzip the archive and keep the folder somewhere you will run the app from (see the main project README).

---

## 4. Generate the auth key

In **Step 1**:

1. Click **Generate auth key**. A 64-character hex string appears in the box.
2. Click **Copy key** if you want it on the clipboard.

Use this same value in two places:

- Inside **Apps Script** as `AUTH_KEY` in `Code.gs` (the extension’s **Copy Code.gs** step will embed it for you when you copy).
- In **mhrv-rs** as the auth key field when you save config.

Treat it like a password. The extension generates it in the browser; it is not sent to a server by the extension.

---

## 5. Get Code.gs into Google Apps Script

In **Step 2**:

1. Wait until the spinner disappears and the script has loaded (from GitHub, or bundled fallback if GitHub is blocked).
2. (Optional) Click **Check latest Code.gs** to see if the bundled copy matches the latest file on GitHub.
3. Click **Open Apps Script** if you need a new project tab.
4. In Apps Script: **New project** (or open an existing project), delete the default `Code.gs` content.
5. Back in the extension, click **Copy Code.gs** (or **Download Code.gs** and open the file).
6. Paste into the Apps Script editor and **Save**.

Deploy as a **Web app** (see the main README Quick Start): **Execute as: Me**, **Who has access: Anyone** (unless your setup requires something else). Finish authorization if Google asks.

Copy the **Deployment ID** Google shows you (you will paste it in Step 3 of the extension).

---

## 6. Build your local config snippet

In **Step 3**:

1. Paste the **Deployment ID** into the **Deployment ID** field.
2. Click **Copy config snippet**.
3. Merge the JSON into your **`config.json`** for `mhrv-rs` (or paste into the app’s config UI if you use the graphical mode).

Typical shape:

```json
{
  "mode": "apps_script",
  "script_id": "YOUR_DEPLOYMENT_ID",
  "auth_key": "YOUR_AUTH_KEY",
  "listen_port": 8085
}
```

The extension fills `script_id` and `auth_key` from what you entered and generated.

---

## 7. Run mhrv-rs and point the browser at the proxy

Follow the **main project README** from “First run” onward: save config, start the proxy, set Firefox or Chrome to `127.0.0.1:8085` (or use SwitchyOmega as documented there).

Use **View app docs** / **Open setup guide** in the extension footer for links to the official README and guide.

---

## Troubleshooting (short)

| Problem | What to try |
|--------|-------------|
| Script never loads | GitHub raw may be blocked; the extension falls back to bundled `Code.gs`. Use **Check latest Code.gs** after the network improves. |
| Copy buttons do nothing | Some contexts block clipboard; try focusing the popup first or use **Download Code.gs** instead. |
| Wrong binary downloaded | Use **View all releases** and pick the archive for your OS manually. |

For deeper issues (CAPTCHA, Telegram, full tunnel), use [docs/guide.md](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/blob/main/docs/guide.md) in the main repo.