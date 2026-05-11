# mhrv-rs Apps Script Helper Chrome Extension

This Chrome extension is a lightweight helper for the `MasterHttpRelayVPN-RUST` project. It automates the first-time Apps Script setup by generating a strong `AUTH_KEY`, preparing the `Code.gs` source, and producing a local config snippet.

## What it does

- Generates a strong random `AUTH_KEY`
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
3. Tap **Copy Code.gs** or **Download Code.gs**.
4. In `https://script.google.com`, create a new Apps Script project and paste the generated contents.
5. Deploy as a Web App with:
   - **Execute as:** Me
   - **Who has access:** Anyone
6. Copy the deployment ID and paste it into the Deployment ID field in the extension.
7. Tap **Copy config snippet** and paste the result into your local `config.json`.

## Notes

- The extension does not deploy Apps Script automatically; it only generates the code and configuration.
- The extension stores no secret values persistently in Chrome storage.
- If your network does not allow `script.google.com`, use the project in `direct` mode first and then follow the guide.

## Recommended workflow

- Use the extension to avoid manual editing mistakes.
- Keep the generated `AUTH_KEY` secret.
- If you need full tunnel mode later, use the repo docs to deploy `CodeFull.gs` or `Code.cfw.gs`.

## Limitations

This helper is intentionally minimal and does not perform OAuth on behalf of your Google account. It simplifies the code generation and setup flow but still requires a manual Apps Script deployment step inside Google.
