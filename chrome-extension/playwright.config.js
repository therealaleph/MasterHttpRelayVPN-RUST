const { defineConfig } = require('@playwright/test');
const path = require('path');

module.exports = defineConfig({
  testDir: './tests',
  timeout: 60_000,
  fullyParallel: false,
  retries: 0,
  reporter: 'list',
  use: {
    headless: false,
  },
  projects: [
    {
      name: 'chromium-extension',
      use: {
        channel: 'chromium',
        launchOptions: {
          args: [
            `--disable-extensions-except=${path.resolve(__dirname)}`,
            `--load-extension=${path.resolve(__dirname)}`,
          ],
        },
      },
    },
  ],
});
