# mhrv-rs Apps Script Helper Chrome Extension

This Chrome extension is a lightweight helper for the `MasterHttpRelayVPN-RUST` project. It automates the first-time Apps Script setup by generating a strong `AUTH_KEY`, fetching the latest `Code.gs` source from the repository, and producing a local config snippet.

## What it does

- Generates a strong random `AUTH_KEY`
- Fetches the latest `Code.gs` from the GitHub repository (with local fallback)
- Creates a ready-to-deploy `Code.gs` file with the same relay protocol used by the repo
- Opens Google Apps Script in a new tab
- Builds a JSON config snippet for `config.json`
- Links to the repo documentation for setup and troubleshooting

## Installation

1. Open Chrome and go to `chrome://extensions`.
2. Enable **Developer mode**.
3. Click **Load unpacked**.
4. Select the `chrome-extension` folder in this repository.
5. The extension icon should appear in your toolbar.

## Usage

1. Click the extension icon.
2. Tap **Generate auth key**.
3. The extension will fetch the latest `Code.gs` from GitHub.
4. Tap **Copy Code.gs** or **Download Code.gs**.
5. In `https://script.google.com`, create a new Apps Script project and paste the generated contents.
6. Deploy as a Web App with:
   - **Execute as:** Me
   - **Who has access:** Anyone
7. Copy the deployment ID and paste it into the Deployment ID field in the extension.
8. Tap **Copy config snippet** and paste the result into your local `config.json`.

## Automation Level

The extension automates as much as possible within Chrome extension limitations:

- ✅ Generates secure keys
- ✅ Fetches latest script code from repo
- ✅ Prepares deployment-ready code
- ✅ Generates config snippets
- ❌ Cannot automatically deploy to Google Apps Script (requires manual paste and deploy due to OAuth/security restrictions)

Full automation of Apps Script deployment would require:
- Google OAuth integration
- Apps Script API access
- Publishing as a verified Chrome extension
- User consent for Google account access

This is beyond the scope of a simple helper extension.

## Notes

- The extension fetches `Code.gs` from GitHub on load, ensuring you always get the latest version.
- If GitHub is blocked, it falls back to the bundled local copy.
- The extension does not store secret values persistently in Chrome storage.
- If your network does not allow `script.google.com`, use the project in `direct` mode first and then follow the guide.

## Recommended workflow

- Use the extension to avoid manual editing mistakes.
- Keep the generated `AUTH_KEY` secret.
- If you need full tunnel mode later, use the repo docs to deploy `CodeFull.gs` or `Code.cfw.gs`.

## Limitations

This helper is intentionally minimal and does not perform OAuth on behalf of your Google account. It simplifies the code generation and setup flow but still requires a manual Apps Script deployment step inside Google.
