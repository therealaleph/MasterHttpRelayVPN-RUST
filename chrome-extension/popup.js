const AUTH_KEY_PLACEHOLDER = 'CHANGE_ME_TO_A_STRONG_SECRET';
const CODE_FILE = 'Code.gs';
let codeTemplate = '';

const elements = {
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
};

function randomHex(length = 32) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Array.from(array)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function showMessage(text, isError = false) {
  elements.message.textContent = text;
  elements.message.style.color = isError ? '#b91c1c' : '#0f172a';
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
  try {
    const response = await fetch(CODE_FILE_URL);
    if (!response.ok) throw new Error('Failed to fetch Code.gs');
    codeTemplate = await response.text();
    renderScript();
    showMessage('Code.gs loaded from repository.');
  } catch (err) {
    showMessage('Failed to load Code.gs from repository. Using local fallback.', true);
    console.error(err);
    // Fallback to local if fetch fails
    try {
      const localResponse = await fetch(chrome.runtime.getURL('Code.gs'));
      codeTemplate = await localResponse.text();
      renderScript();
    } catch (localErr) {
      showMessage('Could not load Code.gs at all.', true);
    }
  }
}

function copyText(text, label) {
  return navigator.clipboard.writeText(text).then(
    () => showMessage(`Copied ${label}.`),
    (err) => {
      console.error(err);
      showMessage(`Could not copy ${label}.`, true);
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
    showMessage('Opening download page for latest mhrv-rs binary.');
  } catch (err) {
    console.error(err);
    showMessage('Failed to fetch latest release. Opening releases page.', true);
    window.open('https://github.com/therealaleph/MasterHttpRelayVPN-RUST/releases', '_blank');
  }
}

function initListeners() {
  elements.generateKey.addEventListener('click', () => {
    setAuthKey(randomHex(32));
    showMessage('Auth key generated. Paste it into Apps Script and config.');
  });

  elements.copyKey.addEventListener('click', () => {
    const key = elements.authKey.value.trim();
    if (!key) {
      showMessage('Generate an auth key first.', true);
      return;
    }
    copyText(key, 'auth key');
  });

  elements.copyScript.addEventListener('click', () => {
    if (!codeTemplate) {
      showMessage('Script template not loaded yet.', true);
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
      showMessage('Script template not loaded yet.', true);
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
    showMessage('Downloaded Code.gs for Apps Script deployment.');
  });

  elements.openScript.addEventListener('click', () => {
    window.open('https://script.google.com/home/projects', '_blank');
  });

  elements.copyConfig.addEventListener('click', () => {
    copyText(elements.configJson.value, 'config snippet');
  });

  elements.openReadme.addEventListener('click', () => {
    window.open('https://github.com/therealaleph/MasterHttpRelayVPN-RUST/blob/main/assets/apps_script/README.md', '_blank');
  });

  elements.openGuide.addEventListener('click', () => {
    window.open('https://github.com/therealaleph/MasterHttpRelayVPN-RUST/blob/main/README.md', '_blank');
  });

  elements.downloadRust.addEventListener('click', () => downloadLatestRust());
  elements.openReleases.addEventListener('click', () => window.open('https://github.com/therealaleph/MasterHttpRelayVPN-RUST/releases', '_blank'));

  elements.deploymentId.addEventListener('input', renderConfig);
}

function init() {
  loadTemplate();
  initListeners();
  renderConfig();
}

init();
