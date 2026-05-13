# کمک‌کنندهٔ Apps Script برای mhrv-rs (افزونهٔ کروم)

[English](README.md) | فارسی

این یک **افزونهٔ سبک کروم (Manifest V3)** است که راه‌اندازی اولیهٔ **Google Apps Script** را برای استفاده از **[mhrv-rs](https://github.com/therealaleph/MasterHttpRelayVPN-RUST)** در حالت **رلهٔ Apps Script** ساده‌تر می‌کند. خود پروکسی یا تونل نیست؛ فقط در تولید کلید، گرفتن `Code.gs` و ساختن قطعهٔ `config.json` کمک می‌کند.

**نسخهٔ پیشنهادی برای کلون و توسعه:** [ardalan-ab/mhrv-helper-extension](https://github.com/ardalan-ab/mhrv-helper-extension)  
**پروژهٔ اصلی:** [therealaleph/MasterHttpRelayVPN-RUST](https://github.com/therealaleph/MasterHttpRelayVPN-RUST)

**راهنمای گام‌به‌گام برای کاربر:** [HOW_TO_USE.fa.md](HOW_TO_USE.fa.md) · [English](HOW_TO_USE.md)

---

## این افزونه چه کار می‌کند؟

| مرحله | خروجی                                                                                                                                                                                                                  |
| ----- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ۰     | باز کردن آخرین نسخهٔ **mhrv-rs** متناسب با سیستم‌عامل شما (از طریق API گیت‌هاب).                                                                                                                                       |
| ۱     | تولید **AUTH_KEY** تصادفی و قوی داخل مرورگر (`crypto.getRandomValues`).                                                                                                                                                |
| ۲     | بارگذاری **Code.gs** از `raw.githubusercontent.com` (مسیر رسمی در مخزن اصلی)، با **نسخهٔ پشتیبان داخل بسته** اگر گیت‌هاب در دسترس نباشد. دکمهٔ **بررسی آخرین نسخه Code.gs** وضعیت هم‌خوانی با upstream را نشان می‌دهد. |
| ۳     | ساخت **قطعهٔ JSON پیکربندی** (حالت `apps_script`) پس از وارد کردن **شناسهٔ استقرار (Deployment ID)**.                                                                                                                  |

رابط کاربری به **انگلیسی** و **فارسی** است و برای فارسی چیدمان **راست‌به‌چپ (RTL)** درست شده است.

---

## مجوزها (چرا لازم‌اند)

- **`storage`**: برای تنظیمات احتمالی آینده؛ در جریان فعلی اصلی افزونه الزامی نیست.
- **`clipboardWrite`**: کپی کردن کلید، `Code.gs` و قطعهٔ config با کلیک روی دکمه‌های کپی.
- **دسترسی به میزبان‌ها:** `script.google.com` (باز کردن Apps Script)، `raw.githubusercontent.com` (گرفتن `Code.gs`)، `api.github.com` (پیدا کردن آخرین ریلیز برای دانلود).

**AUTH_KEY** فقط روی دستگاه شما ساخته می‌شود و توسط این افزونه به هیچ سروری ارسال نمی‌شود؛ تست‌های خودکار (Playwright) بررسی می‌کنند که در ترافیک شبکهٔ ثبت‌شده و storage افزونه دیده نشود.

---

## نصب (بارگذاری unpacked)

[اینجا کلیک کنید](HOW_TO_USE.fa.md)

## توسعه و تست

### بررسی سریع syntax

```bash
python3 -m json.tool manifest.json
python3 -m json.tool messages.json
node --check popup.js
```

### تست دستی UI (بدون APIهای کروم)

از همین پوشه:

```bash
python3 -m http.server 8000
```

در مرورگر `http://localhost:8000/test.html` را باز کنید (رفتار کلیپ‌بورد و `chrome.*` با افزونهٔ واقعی فرق دارد).

### تست خودکار smoke (Playwright)

```bash
npm install
npx playwright install chromium
npm run test:smoke
```

روی لینوکس بدون نمایشگر: `xvfb-run npm run test:smoke` (مثل CI).

### CI — هم‌خوانی `Code.gs` با upstream

- **مخزن فقط افزونه** (ریشهٔ git همین پوشه است): workflow [`.github/workflows/sync-codegs.yml`](.github/workflows/sync-codegs.yml) فایل canonical را از `main` پروژهٔ `therealaleph/MasterHttpRelayVPN-RUST` می‌گیرد و با `Code.gs` داخل بسته مقایسه می‌کند.
- **داخل مونوریپوی کامل**: workflow ریشهٔ مخزن [`.github/workflows/chrome-extension.yml`](../../.github/workflows/chrome-extension.yml) `chrome-extension/Code.gs` را با `assets/apps_script/Code.gs` همان commit مقایسه می‌کند.

دکمهٔ **بررسی آخرین نسخه Code.gs** از **GitHub Contents API** برای همان مسیر استفاده می‌کند، بعد محتوا را با بسته مقایسه می‌کند و نتیجهٔ API (blob کوتاه، اندازه، یا متن خطای API) را نشان می‌دهد.

---

## نسخه

مقدار `version` در **`manifest.json`** (مثلاً **0.2.0**).

---

## مجوز upstream

رفتار و محتوای `Code.gs` توسط پروژهٔ **MasterHttpRelayVPN-RUST** تعیین می‌شود. انتشار در **Chrome Web Store** باید با قوانین گوگل و مجوزهای مخزن اصلی سازگار باشد.
