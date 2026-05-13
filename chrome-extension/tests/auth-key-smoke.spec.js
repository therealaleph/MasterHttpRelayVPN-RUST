const { test, expect, chromium } = require('@playwright/test');
const path = require('path');

function containsSecret(value, secret) {
  return typeof value === 'string' && value.includes(secret);
}

test('AUTH_KEY stays local to popup scope', async () => {
  const extensionPath = path.resolve(__dirname, '..');
  const context = await chromium.launchPersistentContext('', {
    channel: 'chromium',
    headless: false,
    args: [
      `--disable-extensions-except=${extensionPath}`,
      `--load-extension=${extensionPath}`,
    ],
  });

  const requestSnapshots = [];
  const consoleMessages = [];
  let generatedKey = '';

  context.on('request', (req) => {
    requestSnapshots.push({
      url: req.url(),
      postData: req.postData() || '',
      headers: JSON.stringify(req.headers()),
    });
  });

  try {
    let [worker] = context.serviceWorkers();
    if (!worker) {
      worker = await context.waitForEvent('serviceworker');
    }

    const extensionId = worker.url().split('/')[2];
    const page = await context.newPage();

    page.on('console', (msg) => {
      consoleMessages.push(msg.text());
    });

    await page.goto(`chrome-extension://${extensionId}/popup.html`);

    await page.getByRole('button', { name: /Generate auth key|تولید کلید/ }).click();
    generatedKey = await page.locator('#auth-key').inputValue();
    expect(generatedKey).toMatch(/^[a-f0-9]{64}$/);

    await page.getByRole('button', { name: /Copy key|کپی کلید/ }).click();
    await page.getByRole('button', { name: /Copy Code\.gs|کپی Code\.gs/ }).click();
    await page.getByRole('button', { name: /Copy config snippet|کپی قطعه پیکربندی/ }).click();

    const [localStorageData, syncStorageData] = await Promise.all([
      page.evaluate(() => new Promise((resolve) => chrome.storage.local.get(null, resolve))),
      page.evaluate(() => new Promise((resolve) => chrome.storage.sync.get(null, resolve))),
    ]);

    expect(JSON.stringify(localStorageData)).not.toContain(generatedKey);
    expect(JSON.stringify(syncStorageData)).not.toContain(generatedKey);

    for (const req of requestSnapshots) {
      expect(containsSecret(req.url, generatedKey)).toBeFalsy();
      expect(containsSecret(req.postData, generatedKey)).toBeFalsy();
      expect(containsSecret(req.headers, generatedKey)).toBeFalsy();
    }

    for (const line of consoleMessages) {
      expect(containsSecret(line, generatedKey)).toBeFalsy();
    }
  } finally {
    await context.close();
  }
});
