# mhrv-rs Apps Script Helper Chrome Extension

This Chrome extension is a lightweight helper for the `MasterHttpRelayVPN-RUST` project. It automates the first-time Apps Script setup by generating a strong `AUTH_KEY`, fetching the latest `Code.gs` source from the repository, and producing a local config snippet.

## ✨ New Features (v0.2.0)
- 🌐 **Multilingual Support**: English and Persian (فارسی) interface
- 🎨 **Modern UI**: Improved design with icons, animations, and better UX
- 📱 **RTL Support**: Proper right-to-left layout for Persian
- 🔄 **Loading Indicators**: Visual feedback during script fetching
- 📦 **Auto-Updates**: Always fetches latest Code.gs from repository
- 🏗️ **Better Architecture**: Modular code with i18n support

## What it does

- Downloads the latest `mhrv-rs` binary for your platform
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
2. Select your preferred language (English/Persian) from the dropdown.
3. Tap **Download mhrv-rs** to get the latest binary for your platform.
4. Tap **Generate auth key**.
5. The extension will fetch the latest `Code.gs` from GitHub (shows loading indicator).
6. Tap **Copy Code.gs** or **Download Code.gs**.
7. In `https://script.google.com`, create a new Apps Script project and paste the generated contents.
7. Deploy as a Web App with:
   - **Execute as:** Me
   - **Who has access:** Anyone
8. Copy the deployment ID and paste it into the Deployment ID field in the extension.
9. Tap **Copy config snippet** and paste the result into your local `config.json`.

## Testing the Extension

### Manual Testing
1. Load the extension in Chrome as described in Installation
2. Click the extension icon
3. Test language switching (English ↔ Persian)
4. Generate an auth key and verify it's 64 characters
5. Test copying functionality (key, script, config)
6. Test download buttons (should open new tabs)
7. Verify RTL layout works in Persian mode

### Automated Testing
Open `test.html` in a browser to test the UI without Chrome extension restrictions:
```bash
# In chrome-extension folder
python3 -m http.server 8000
# Then open http://localhost:8000/test.html
```

### Validation Checks
```bash
# Check JSON syntax
python3 -m json.tool manifest.json
python3 -m json.tool messages.json

# Check JavaScript syntax
node -c popup.js

# Verify file structure
ls -la
# Should show: Code.gs, manifest.json, messages.json, popup.css, popup.html, popup.js, README.md, test.html
```
