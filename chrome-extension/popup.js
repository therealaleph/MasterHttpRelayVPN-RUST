const AUTH_KEY_PLACEHOLDER = 'CHANGE_ME_TO_A_STRONG_SECRET';
const CODE_FILE = 'Code.gs';
let codeTemplate = '';
let messages = {};

const elements = {
  languageSelect: document.getElementById('language-select'),
  authKey: document.getElementById('auth-key'),
  deploymentId: document.getElementById('deployment-id'),
  configJson: document.getElementById('config-json'),
  message: document.getElementById('message'),
  generateKey: document.getElementById('generate-key'),
  copyKey: document.getElementById('copy-key'),
  copyScript: document.getElementById('copy-script'),
  downloadScript: document.getElementById('download-script'),
  openScript: document.getElementById('open-script'),
  copyConfig: document.getElementById('copy-config'),
  openReadme: document.getElementById('open-readme'),
  openGuide: document.getElementById('open-guide'),
  downloadRust: document.getElementById('download-rust'),
  openReleases: document.getElementById('open-releases'),
  scriptProgress: document.getElementById('script-progress'),
};

async function loadMessages() {
  try {
    const response = await fetch(chrome.runtime.getURL('messages.json'));
    messages = await response.json();
  } catch (err) {
    console.error('Failed to load messages:', err);
    // Fallback messages
    messages = {
      en: {
        keyGenerated: "Auth key generated. Paste it into Apps Script and config.",
        copied: "Copied {item}.",
        scriptDownloaded: "Downloaded Code.gs for Apps Script deployment.",
        codeLoaded: "Code.gs loaded from repository.",
        codeLoadedFallback: "Failed to load Code.gs from repository. Using local fallback.",
        downloadError: "Failed to fetch latest release. Opening releases page.",
        downloadSuccess: "Opening download page for latest mhrv-rs binary.",
        scriptNotLoaded: "Script template not loaded yet.",
        generateKeyFirst: "Generate an auth key first.",
        copyError: "Could not copy {item}.",
        fetchError: "Failed to load Code.gs at all."
      }
    };
  }
}

function getMessage(key, params = {}) {
  const lang = elements.languageSelect.value;
  let message = messages[lang]?.[key] || messages.en?.[key] || key;
  
  // Replace placeholders
  Object.keys(params).forEach(param => {
    message = message.replace(`{${param}}`, params[param]);
  });
  
  return message;
}

function updateUILanguage() {
  const lang = elements.languageSelect.value;
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === 'fa' ? 'rtl' : 'ltr';
  
  // Update all elements with data-i18n attributes
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    el.textContent = getMessage(key);
  });
  
  // Update placeholders
  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    const key = el.getAttribute('data-i18n-placeholder');
    el.placeholder = getMessage(key);
  });
  
  // Update title
  document.title = getMessage('appName');
  
  // Re-render config to update any language-specific text
  renderConfig();
}

function randomHex(length = 32) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Array.from(array)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function showMessage(text, isError = false) {
  elements.message.textContent = text;
  elements.message.className = isError ? 'error' : '';
}

function renderConfig() {
  const authKey = elements.authKey.value.trim();
  const deploymentId = elements.deploymentId.value.trim();
  const config = {
    mode: 'apps_script',
    script_id: deploymentId || 'YOUR_APPS_SCRIPT_DEPLOYMENT_ID',
    auth_key: authKey || 'PASTE_YOUR_AUTH_KEY_HERE',
    listen_port: 8085,
  };
  elements.configJson.value = JSON.stringify(config, null, 2);
}

function renderScript() {
  if (!codeTemplate) {
    return;
  }
  const authKey = elements.authKey.value.trim() || AUTH_KEY_PLACEHOLDER;
  const replaced = codeTemplate.replace(
    /const\s+AUTH_KEY\s*=\s*"[^"]*";/,
    `const AUTH_KEY = "${authKey}";`
  );
  document.getElementById('code-preview')?.remove();
  const preview = document.createElement('textarea');
  preview.id = 'code-preview';
  preview.readOnly = true;
  preview.value = replaced;
  preview.style.marginTop = '8px';
  preview.style.height = '220px';
  preview.style.fontFamily = 'monospace';
  preview.style.whiteSpace = 'pre';
  preview.style.overflow = 'auto';
  preview.style.width = '100%';
  preview.style.border = '1px solid #cbd5e1';
  preview.style.borderRadius = '10px';
  const step = elements.copyScript.closest('.step');
  const existing = step.querySelector('#code-preview');
  if (existing) existing.remove();
  step.appendChild(preview);
}

function setAuthKey(key) {
  elements.authKey.value = key;
  renderConfig();
  renderScript();
}

async function loadTemplate() {
  elements.scriptProgress.style.display = 'block';
  try {
    const response = await fetch(CODE_FILE_URL);
    if (!response.ok) throw new Error('Failed to fetch Code.gs');
    codeTemplate = await response.text();
    renderScript();
    showMessage(getMessage('codeLoaded'));
  } catch (err) {
    showMessage(getMessage('codeLoadedFallback'), true);
    console.error(err);
    // Fallback to local if fetch fails
    try {
      const localResponse = await fetch(chrome.runtime.getURL('Code.gs'));
      codeTemplate = await localResponse.text();
      renderScript();
    } catch (localErr) {
      showMessage(getMessage('fetchError'), true);
    }
  } finally {
    elements.scriptProgress.style.display = 'none';
  }
}

function copyText(text, label) {
  return navigator.clipboard.writeText(text).then(
    () => showMessage(getMessage('copied', { item: label })),
    (err) => {
      console.error(err);
      showMessage(getMessage('copyError', { item: label }), true);
    }
  );
}

async function downloadLatestRust() {
  try {
    const response = await fetch('https://api.github.com/repos/therealaleph/MasterHttpRelayVPN-RUST/releases/latest');
    if (!response.ok) throw new Error('Failed to fetch releases');
    const release = await response.json();
    const assets = release.assets;
    // Detect platform
    const platform = navigator.platform.toLowerCase();
    let assetName;
    if (platform.includes('win')) {
      assetName = assets.find(a => a.name.includes('windows') && a.name.endsWith('.exe'));
    } else if (platform.includes('mac')) {
      assetName = assets.find(a => a.name.includes('macos') || a.name.includes('darwin'));
    } else {
      assetName = assets.find(a => a.name.includes('linux'));
    }
    if (!assetName) {
      showMessage('No suitable binary found for your platform.', true);
      return;
    }
    window.open(assetName.browser_download_url, '_blank');
    showMessage(getMessage('downloadSuccess'));
  } catch (err) {
    console.error(err);
    showMessage(getMessage('downloadError'), true);
    window.open('https://github.com/therealaleph/MasterHttpRelayVPN-RUST/releases', '_blank');
  }
}

function initListeners() {
  elements.languageSelect.addEventListener('change', updateUILanguage);
  
  elements.generateKey.addEventListener('click', () => {
    setAuthKey(randomHex(32));
    showMessage(getMessage('keyGenerated'));
  });

  elements.copyKey.addEventListener('click', () => {
    const key = elements.authKey.value.trim();
    if (!key) {
      showMessage(getMessage('generateKeyFirst'), true);
      return;
    }
    copyText(key, 'auth key');
  });

  elements.copyScript.addEventListener('click', () => {
    if (!codeTemplate) {
      showMessage(getMessage('scriptNotLoaded'), true);
      return;
    }
    const authKey = elements.authKey.value.trim() || AUTH_KEY_PLACEHOLDER;
    const scriptText = codeTemplate.replace(
      /const\s+AUTH_KEY\s*=\s*"[^"]*";/,
      `const AUTH_KEY = "${authKey}";`
    );
    copyText(scriptText, 'Apps Script');
  });

  elements.downloadScript.addEventListener('click', () => {
    if (!codeTemplate) {
      showMessage(getMessage('scriptNotLoaded'), true);
      return;
    }
    const authKey = elements.authKey.value.trim() || AUTH_KEY_PLACEHOLDER;
    const scriptText = codeTemplate.replace(
      /const\s+AUTH_KEY\s*=\s*"[^"]*";/,
      `const AUTH_KEY = "${authKey}";`
    );
    const blob = new Blob([scriptText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'Code.gs';
    anchor.click();
    URL.revokeObjectURL(url);
    showMessage(getMessage('scriptDownloaded'));
  });

  elements.openScript.addEventListener('click', () => {
    window.open('https://script.google.com/home/projects', '_blank');
  });

  elements.copyConfig.addEventListener('click', () => {
    copyText(elements.configJson.value, 'config snippet');
  });

  elements.openReadme.addEventListener('click', () => {
    window.open('https://github.com/therealaleph/MasterHttpRelayVPN-RUST/blob/main/README.md', '_blank');
  });

  elements.openGuide.addEventListener('click', () => {
    window.open('https://github.com/therealaleph/MasterHttpRelayVPN-RUST/blob/main/docs/guide.md', '_blank');
  });

  elements.downloadRust.addEventListener('click', () => downloadLatestRust());
  elements.openReleases.addEventListener('click', () => window.open('https://github.com/therealaleph/MasterHttpRelayVPN-RUST/releases', '_blank'));

  elements.deploymentId.addEventListener('input', renderConfig);
}

async function init() {
  await loadMessages();
  loadTemplate();
  initListeners();
  renderConfig();
  updateUILanguage();
}

init();
