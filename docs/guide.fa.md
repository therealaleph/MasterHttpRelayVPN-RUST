<div dir="rtl">

# mhrv-rs — راهنمای کامل

این نسخهٔ کامل و فنی است — همهٔ گزینه‌های کانفیگ، همهٔ حالت‌های پیشرفته، همهٔ راه‌های رفع اشکال. برای راه‌اندازی ۵ دقیقه‌ای، [README اصلی](../README.md) را ببین.

[English version](guide.md)

## فهرست

- [نگاه دقیق به نحوهٔ کارکرد](#نگاه-دقیق-به-نحوهٔ-کارکرد)
- [پلتفرم‌ها و فایل‌های اجرایی](#پلتفرم‌ها-و-فایل‌های-اجرایی)
- [محل ذخیرهٔ فایل‌ها](#محل-ذخیرهٔ-فایل‌ها)
- [دیپلوی Apps Script](#دیپلوی-apps-script)
  - [نسخهٔ Cloudflare Worker (سریع‌تر)](#نسخهٔ-cloudflare-worker)
  - [حالت direct (وقتی ISP خود `script.google.com` را بسته)](#حالت-direct)
- [مرجع CLI](#مرجع-cli)
  - [حالت scan-ips با API](#حالت-scan-ips-با-api)
- [تلگرام با xray](#تلگرام-با-xray)
- [حالت تونل کامل](#حالت-تونل-کامل)
  - [تأثیر تعداد Deployment](#تأثیر-تعداد-deployment)
  - [راه‌اندازی سریع](#راه‌اندازی-سریع-حالت-full)
- [Exit node — برای ChatGPT / Claude / Grok](#exit-node)
- [اشتراک‌گذاری از طریق هات‌اسپات](#اشتراک‌گذاری-هات‌اسپات)
- [اجرا روی OpenWRT](#اجرا-روی-openwrt)
- [ابزارهای تشخیص](#ابزارهای-تشخیص)
  - [ویرایشگر SNI pool](#ویرایشگر-sni-pool)
- [چه چیز پیاده شده و چه چیز نه](#چه-چیز-پیاده-شده-و-چه-چیز-نه)
- [محدودیت‌های شناخته‌شده](#محدودیت‌های-شناخته‌شده)
- [امنیت](#امنیت)
- [سؤالات رایج](#سؤالات-رایج)

## نگاه دقیق به نحوهٔ کارکرد

```
مرورگر / تلگرام / xray
        |
        | HTTP proxy (8085)  یا  SOCKS5 (8086)
        v
mhrv-rs (محلی)
        |
        | TLS به IP گوگل، SNI = www.google.com
        v                       ^
   DPI می‌بیند: www.google.com   |
        |                       | Host: script.google.com (داخل TLS)
        v                       |
  لبهٔ گوگل ----------------------+
        |
        v
  رلهٔ Apps Script (حساب رایگان شما)
        |
        v
  مقصد واقعی
```

DPI سانسورگر فقط SNI داخل TLS را می‌بیند و اجازه می‌دهد `www.google.com` رد شود. لبهٔ گوگل هم `www.google.com` و هم `script.google.com` را روی یک IP سرو می‌کند و بر اساس هدر HTTP `Host` داخل تونل رمزشده آن‌ها را تفکیک می‌کند.

برای دامنه‌های متعلق به گوگل (`google.com`, `youtube.com`, `fonts.googleapis.com`, …) همان تونل مستقیم استفاده می‌شود — بدون رلهٔ Apps Script. این کار سهمیهٔ هر-fetch را دور می‌زند و مشکل قفل‌بودنِ User-Agent روی `Google-Apps-Script` را برای آن سایت‌ها برطرف می‌کند. برای اضافه کردن دامنه‌های دیگر از فیلد `hosts` در `config.json` استفاده کن.

## پلتفرم‌ها و فایل‌های اجرایی

لینوکس (x86_64، aarch64)، مک (x86_64، aarch64)، ویندوز (x86_64)، **اندروید ۷.۰ به بالا** (APK جهانی شامل arm64، armv7، x86_64، x86). فایل‌های آماده در [صفحهٔ releases](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/releases).

**اندروید:** فایل `mhrv-rs-android-universal-v*.apk` را دانلود کن. راهنمای کامل در [docs/android.fa.md](android.fa.md) (فارسی) یا [docs/android.md](android.md) (انگلیسی). نسخهٔ اندروید همان `mhrv-rs` Rust دسکتاپ را اجرا می‌کند (از طریق JNI) به‌علاوهٔ پل TUN با `tun2proxy` تا تمام برنامه‌های دستگاه بدون نیاز به تنظیم per-app از پروکسی رد شوند.

> **نکتهٔ مهم اندروید (issueهای [#74](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/74) و [#81](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/81)):** TUN تمام ترافیک IP را می‌گیرد، اما HTTPS از برنامه‌های third-party فقط برای برنامه‌هایی کار می‌کند که به CAهای نصب‌شدهٔ کاربر اعتماد می‌کنند. از اندروید ۷ به بعد، برنامه‌ها باید با `networkSecurityConfig` صراحتاً اعلام کنند. **کروم و فایرفاکس می‌کنند**؛ **تلگرام، واتس‌اَپ، اینستاگرام، یوتیوب، برنامه‌های بانکی، بازی‌ها** نمی‌کنند. برای آن‌ها: حالت `PROXY_ONLY` و در داخل برنامه `127.0.0.1:1081` (SOCKS5)، یا حالت `google_only` (بدون CA، فقط سرویس‌های گوگل)، یا `upstream_socks5` به یک VPS خارجی. این طراحی امنیتی اندروید است نه باگ این برنامه.

### محتوای هر release

هر آرشیو شامل:

| فایل | کاربرد |
|---|---|
| `mhrv-rs` / `mhrv-rs.exe` | CLI. استفادهٔ headless، سرور، اتوماسیون. روی مک / ویندوز بدون وابستگی سیستمی. |
| `mhrv-rs-ui` / `mhrv-rs-ui.exe` | UI دسکتاپ (egui). فرم کانفیگ، دکمه‌های Start / Stop / Test، آمار زنده، پنل log. |
| `run.sh` / `run.command` / `run.bat` | راه‌انداز پلتفرم: گواهی MITM را نصب می‌کند (نیاز به sudo / admin) و UI را باز می‌کند. در اولین اجرا از این استفاده کن. |

آرشیوهای مک شامل `mhrv-rs.app` (در `*-app.zip`) هم هستند — در Finder دو بار کلیک کن. یک‌بار `mhrv-rs --install-cert` یا `run.command` را اجرا کن تا CA نصب شود.

<p align="center"><img src="ui-screenshot.png" alt="UI دسکتاپ mhrv-rs شامل فرم کانفیگ، آمار ترافیک زنده، دکمه‌های Start/Stop/Test و پنل log" width="420"></p>

UI لینوکس به این کتابخانه‌ها نیاز دارد: `libxkbcommon`, `libwayland-client`, `libxcb`, `libgl`, `libx11`, `libgtk-3`. روی اکثر توزیع‌های دسکتاپی از قبل نصب‌اند؛ روی سیستم headless یا با package manager نصب کن یا از CLI استفاده کن.

## محل ذخیرهٔ فایل‌ها

کانفیگ و گواهی MITM در دایرکتوری user-data سیستم‌عامل قرار می‌گیرند:

- مک: `~/Library/Application Support/mhrv-rs/`
- لینوکس: `~/.config/mhrv-rs/`
- ویندوز: `%APPDATA%\mhrv-rs\`

داخل آن دایرکتوری:

- `config.json` — تنظیمات تو (با دکمهٔ Save در UI نوشته می‌شود یا دستی)
- `ca/ca.crt`, `ca/ca.key` — گواهی root MITM. کلید خصوصی فقط در دست توست.

CLI همچنین برای سازگاری با راه‌اندازی‌های قدیمی، روی `./config.json` در دایرکتوری جاری هم fallback دارد.

## دیپلوی Apps Script

نسخهٔ ۵ دقیقه‌ای در [README اصلی](../README.md#مرحلهٔ-۱--ساخت-اسکریپت-گوگل-یک‌بار) است. این بخش به نسخه‌های جایگزین می‌پردازد.

### نسخهٔ Cloudflare Worker

یک نسخهٔ جایگزین در [`assets/apps_script/Code.cfw.gs`](../assets/apps_script/Code.cfw.gs) به‌همراه [`assets/cloudflare/worker.js`](../assets/cloudflare/worker.js) وجود دارد که Apps Script را به یک رلهٔ نازک تبدیل می‌کند و کار `fetch` واقعی را به یک Cloudflare Worker که خودت دیپلوی می‌کنی می‌سپارد. **سود روز اول:** کاهش تأخیر (~۱۰ تا ۵۰ میلی‌ثانیه روی لبهٔ CF در مقابل ۲۵۰ تا ۵۰۰ میلی‌ثانیه Apps Script — برای مرور وب و تلگرام محسوس).

سهمیهٔ روزانهٔ ۲۰٬۰۰۰ `UrlFetchApp` را کاهش **نمی‌دهد**، چون امروز mhrv-rs همیشه درخواست تک‌URL می‌فرستد؛ مسیر دسته‌ای روی GAS+Worker سیم‌کشی شده (`ceil(N/40)` سهمیه به‌ازای دستهٔ N) ولی هیچ کلاینتی فعلاً تولیدش نمی‌کند.

**مبادلات:**
- ویدیوی طولانی یوتیوب بدتر است (دیوار ۳۰ ثانیه به جای ۶ دقیقه)
- ضدبات Cloudflare را حل نمی‌کند
- **با `mode: "full"` سازگار نیست** (پشتیبانی tunnel-ops ندارد → برای واتس‌اَپ / مسنجرها روی اندروید Full mode کمک نمی‌کند)

راهنمای کامل و جدول مبادلات در [`assets/cloudflare/README.fa.md`](../assets/cloudflare/README.fa.md). در mhrv-rs هیچ تنظیمی تغییر نمی‌کند — همان `mode: "apps_script"`، همان `script_id`، همان `auth_key`.

### حالت direct

اگر ISP تو از قبل Apps Script (یا کل گوگل) را مسدود کرده، باید مرحلهٔ ۱ **اول** موفق شود — قبل از این‌که رله‌ای داشته باشی. mhrv-rs یک حالت `direct` دقیقاً برای این دارد — فقط تونل بازنویسی SNI، بدون رلهٔ Apps Script. (قبل از v1.9 نام `google_only` داشت — نام قدیمی هم پذیرفته می‌شود.)

۱. فایل اجرایی را دانلود کن (طبق [مرحلهٔ ۲ در README](../README.md#مرحلهٔ-۲--دانلود-mhrv-rs))
۲. فایل [`config.direct.example.json`](../config.direct.example.json) را در کنار فایل اجرا با نام `config.json` کپی کن — نه `script_id` نیاز است نه `auth_key`
۳. `mhrv-rs serve` را اجرا کن و HTTP proxy مرورگرت را روی `127.0.0.1:8085` بگذار
۴. در حالت `direct`، پروکسی فقط `*.google.com`، `*.youtube.com` و سایر میزبان‌های لبهٔ گوگل (به‌علاوهٔ هر [`fronting_groups`](fronting-groups.md) که تنظیم کرده باشی) را از تونل بازنویسی SNI رد می‌کند. بقیه راو می‌رود — هنوز رله‌ای در کار نیست.
۵. حالا مرحلهٔ ۱ را در مرورگر انجام بده (اتصال به `script.google.com` با SNI فرونت می‌شود). `Code.gs` را دیپلوی کن، Deployment ID را کپی کن.
۶. در UI / اپ اندروید / یا با ویرایش `config.json`، حالت را به `apps_script` برگردان، Deployment ID و auth key را پیست کن، و دوباره استارت کن.

برای بررسی دسترسی قبل از استارت پروکسی: `mhrv-rs test-sni` دامنه‌های `*.google.com` را مستقیم تست می‌کند و فقط به `google_ip` و `front_domain` نیاز دارد.

## مرجع CLI

تمام کاری که UI می‌کند را CLI هم می‌کند. `config.example.json` را به `config.json` کپی کن:

```json
{
  "mode": "apps_script",
  "google_ip": "216.239.38.120",
  "front_domain": "www.google.com",
  "script_id": "PASTE_YOUR_DEPLOYMENT_ID_HERE",
  "auth_key": "same-secret-as-in-code-gs",
  "listen_host": "127.0.0.1",
  "listen_port": 8085,
  "socks5_port": 8086,
  "log_level": "info",
  "verify_ssl": true
}
```

سپس:

```bash
./mhrv-rs                   # اجرای پروکسی (پیش‌فرض)
./mhrv-rs test              # تست یک درخواست کامل
./mhrv-rs scan-ips          # رتبه‌بندی IPهای گوگل بر اساس سرعت
./mhrv-rs test-sni          # تست نام‌های SNI روی google_ip
./mhrv-rs --install-cert    # نصب مجدد گواهی
./mhrv-rs --remove-cert     # حذف کامل: trust store + پوشهٔ ca/
./mhrv-rs --help
```

`--remove-cert` گواهی را از trust store سیستم پاک می‌کند، با بررسی نام تأیید می‌کند که حذف انجام شد، و پوشهٔ `ca/` روی دیسک را حذف می‌کند. پاک‌سازی NSS (فایرفاکس و کروم لینوکس) best-effort است: اگر `certutil` نباشد یا یکی از مرورگرها پایگاه داده NSS را قفل کرده باشد، ابزار راهنمای پاک‌سازی دستی نشان می‌دهد. `config.json` و دیپلوی Apps Script دست‌نخورده می‌مانند، پس CA تازه نیازی به دیپلوی مجدد `Code.gs` ندارد.

`script_id` می‌تواند JSON array باشد: `["id1", "id2", "id3"]`.

### حالت scan-ips با API

به‌طور پیش‌فرض، `scan-ips` از یک لیست ثابت استفاده می‌کند. کشف پویای IP را در `config.json` فعال کن:

```json
{
  "fetch_ips_from_api": true,
  "max_ips_to_scan": 100,
  "scan_batch_size": 100,
  "google_ip_validation": true
}
```

وقتی فعال است:
- فایل `goog.json` را از API محدوده‌های IP عمومی گوگل می‌گیرد
- CIDRها را به IP تک‌تک گسترش می‌دهد
- به IPهای دامنه‌های معروف گوگل اولویت می‌دهد (google.com، youtube.com، …)
- به‌طور تصادفی تا `max_ips_to_scan` کاندید انتخاب می‌کند (اولویت‌داران اول)
- فقط کاندیدها را برای اتصال و اعتبارسنجی frontend تست می‌کند

ممکن است IPهایی پیدا کنی که سریع‌تر از لیست ثابت‌اند، اما تضمینی نیست همه کار کنند.

## تلگرام با xray

رلهٔ Apps Script فقط HTTP request/response می‌فهمد، پس پروتکل‌های غیر-HTTP (MTProto تلگرام، IMAP، SSH، TCP خام) نمی‌توانند از آن رد شوند. بدون چیز دیگری، این جریان‌ها به fallback مستقیم TCP می‌خورند — یعنی واقعاً tunnel نشده‌اند، و ISP که تلگرام را بسته همچنان می‌بندد.

**راه‌حل:** یک [xray](https://github.com/XTLS/Xray-core) (یا v2ray / sing-box) محلی با outbound VLESS / Trojan / Shadowsocks به VPS شخصی خودت اجرا کن، و mhrv-rs را با فیلد **Upstream SOCKS5** (یا کلید `upstream_socks5`) به SOCKS5 inbound آن xray وصل کن. وقتی تنظیم شد، جریان‌های TCP خام که از SOCKS5 listener mhrv-rs می‌آیند به xray → تونل واقعی زنجیر می‌شوند.

```
تلگرام  ┐                                                    ┌─ Apps Script ── HTTP/HTTPS
        ├─ SOCKS5 :8086 ─┤ mhrv-rs ├─ بازنویسی SNI ───────── google.com, youtube.com, …
مرورگر  ┘                                                    └─ upstream SOCKS5 ─ xray ── VLESS ── VPS تو   (تلگرام، IMAP، SSH، TCP خام)
```

قطعهٔ کانفیگ:

```json
{
  "upstream_socks5": "127.0.0.1:50529"
}
```

HTTP / HTTPS مثل قبل از Apps Script می‌رود (تغییری نمی‌کند)، تونل بازنویسی SNI برای `google.com` / `youtube.com` همچنان از هر دو دور می‌زند — یوتیوب به سرعت قبل می‌ماند و تلگرام هم تونل واقعی پیدا می‌کند.

## حالت تونل کامل

`"mode": "full"` **تمام** ترافیک را end-to-end از Apps Script و یک [tunnel-node](../tunnel-node/) راه دور رد می‌کند — بدون نیاز به نصب گواهی MITM. TCP به‌صورت سشن‌های پایدار تونل، و UDP از کلاینت‌های اندروید / TUN از طریق SOCKS5 `UDP ASSOCIATE` به tunnel-node که UDP واقعی را از سمت سرور منتشر می‌کند. مبادله: تأخیر بیشتر هر درخواست (هر بایت Apps Script → tunnel-node → مقصد می‌رود)، اما برای هر پروتکل و هر برنامه‌ای بدون نصب CA کار می‌کند.

### تأثیر تعداد Deployment

هر دور بَچ Apps Script حدود ۲ ثانیه طول می‌کشد. در Full mode، mhrv-rs یک **مالتی‌پلکسر بَچ پیپلاین‌شده** اجرا می‌کند که چند بَچ همزمان می‌فرستد بدون اینکه منتظر پاسخ قبلی بماند. هر Deployment ID (= یک حساب گوگل) حوضچهٔ همزمانی مخصوص خودش با **۳۰ درخواست فعال** دارد — مطابق سقف اجرای همزمان Apps Script per-account.

```
حداکثر همزمانی = ۳۰ × تعداد Deployment IDها
```

| Deployment | همزمانی | |
|---|---|---|
| ۱ | ۳۰ | یک حساب — برای مرور سبک کافی |
| ۳ | ۹۰ | مناسب استفادهٔ روزانه |
| ۶ | ۱۸۰ | توصیه‌شده برای استفادهٔ سنگین |
| ۱۲ | ۳۶۰ | چند حساب — حداکثر توان |

بیشتر Deployment = همزمانی بیشتر = تأخیر کمتر هر سشن. هر بَچ بین IDها چرخش می‌کند و بار به‌طور یکنواخت توزیع می‌شود، احتمال رسیدن به سقف سهمیهٔ یک Deployment کاهش می‌یابد.

**محافظ‌های منابع:**
- **حداکثر ۵۰ op** در هر بَچ — اگر سشن‌های فعال بیشتر باشند، مالتی‌پلکسر چند بَچ می‌فرستد
- **سقف payload ۴ مگابایت** در هر بَچ — خیلی کمتر از ۵۰ مگابایت Apps Script
- **timeout ۳۰ ثانیه** هر بَچ — مقصد کند / مرده نمی‌تواند سایر سشن‌ها را گیر بیاندازد

### راه‌اندازی سریع حالت full

۱. [`CodeFull.gs`](../assets/apps_script/CodeFull.gs) را به‌عنوان Web App روی **هر حساب گوگل** دیپلوی کن (همان مراحل `Code.gs`، اما با اسکریپت full-mode که به tunnel-node تو forward می‌کند). یک Deployment per account — سقف ۳۰ همزمان per account است، چند Deployment روی یک حساب سهمیه را زیاد نمی‌کند. برای مقیاس، حساب‌های بیشتر:
   - **استفادهٔ تنها** → ۱-۲ حساب
   - **اشتراک با ~۳ نفر** → ۳ حساب
   - **اشتراک با گروه** → یک حساب per کاربر سنگین

۲. [tunnel-node](../tunnel-node/) را روی VPS دیپلوی کن. سریع‌ترین راه ایمیج Docker آماده:
   ```bash
   docker run -d --name mhrv-tunnel --restart unless-stopped \
     -p 8080:8080 -e TUNNEL_AUTH_KEY=رمز_قوی_تو \
     ghcr.io/therealaleph/mhrv-tunnel-node:latest
   ```
   Multi-arch (linux/amd64 + linux/arm64)، اجرا با کاربر غیر root، حدود ۳۲ مگابایت فشرده. برای production نسخهٔ مشخص (`:1.5.0`) را pin کن. راهنمای کامل (شامل Cloud Run، docker-compose، بیلد از سورس) در [tunnel-node/README.fa.md](../tunnel-node/README.fa.md).

۳. در کانفیگت `"mode": "full"` با همهٔ Deployment IDها بگذار:
   ```json
   {
     "mode": "full",
     "script_id": ["id1", "id2", "id3", "id4", "id5", "id6"],
     "auth_key": "secret-تو"
   }
   ```

## Exit node

سرویس‌های پشت Cloudflare (chatgpt.com، claude.ai، grok.com، x.com، openai.com) ترافیک از IPهای دیتاسنتر گوگل را به‌عنوان bot شناسایی می‌کنند و چالش Turnstile / CAPTCHA می‌فرستند. راه‌حل exit node یک handler کوچک TypeScript است که روی یک host serverless (Deno Deploy، fly.io، یا VPS شخصی خودت) دیپلوی می‌کنی و بین Apps Script و مقصد قرار می‌گیرد:

```
کلاینت → Apps Script (IP گوگل) → exit node خودت (IP غیر گوگل) → سایت پشت CF
```

مقصد IP خروجی exit node را می‌بیند نه IP گوگل، پس heuristic ضدبات شلیک نمی‌کند.

**راه‌اندازی:** [`assets/exit_node/README.fa.md`](../assets/exit_node/README.fa.md). ۵ دقیقه، سهمیهٔ رایگان.

## اشتراک‌گذاری هات‌اسپات

mhrv-rs به‌طور پیش‌فرض روی `0.0.0.0` گوش می‌دهد، پس هر دستگاه روی همان شبکه می‌تواند ازش استفاده کند. سناریوی رایج: اشتراک تونل از گوشی اندروید به آیفون / آیپد / لپ‌تاپ از هات‌اسپات:

۱. **اندروید:** هات‌اسپات موبایل را روشن کن + اپ را استارت کن
۲. **دستگاه دیگر:** به Wi-Fi هات‌اسپات اندروید وصل شو
۳. **پروکسی** را روی دستگاه دیگر تنظیم کن:
   - سرور: `192.168.43.1` (IP پیش‌فرض هات‌اسپات اندروید)
   - پورت: `8080` (HTTP) یا `1081` (SOCKS5)

### iOS

Settings → Wi-Fi → روی (i) شبکهٔ هات‌اسپات بزن → Configure Proxy → Manual → سرور `192.168.43.1`، پورت `8080`.

برای پوشش سراسری در iOS، از [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118) یا [Potatso](https://apps.apple.com/app/potatso/id1239860606) استفاده کن — به SOCKS5 (`192.168.43.1:1081`) وصلش کن، تمام ترافیک از تونل می‌رود.

### مک / ویندوز

HTTP proxy سیستم را روی `192.168.43.1:8080` بگذار، یا per-app SOCKS5 روی `192.168.43.1:1081`.

> اگر `listen_host` در کانفیگت `127.0.0.1` است، به `0.0.0.0` تغییرش بده تا اتصال از دستگاه‌های دیگر را بپذیرد.

## اجرا روی OpenWRT

آرشیوهای `*-linux-musl-*` یک CLI کاملاً استاتیک می‌فرستند که روی OpenWRT، Alpine، و هر لینوکس بدون libc اجرا می‌شود. فایل را روی روتر بگذار و به‌صورت سرویس استارت کن:

```sh
# از کامپیوتری که به روترت دسترسی دارد:
scp mhrv-rs root@192.168.1.1:/usr/bin/mhrv-rs
scp mhrv-rs.init root@192.168.1.1:/etc/init.d/mhrv-rs
scp config.json root@192.168.1.1:/etc/mhrv-rs/config.json

# روی روتر (ssh):
chmod +x /usr/bin/mhrv-rs /etc/init.d/mhrv-rs
/etc/init.d/mhrv-rs enable
/etc/init.d/mhrv-rs start
logread -e mhrv-rs -f       # تمام لاگ
```

دستگاه‌های LAN HTTP proxy را روی IP روتر (پورت پیش‌فرض `8085`) یا SOCKS5 روی `<router-ip>:8086` تنظیم می‌کنند. در `/etc/mhrv-rs/config.json` مقدار `listen_host` را به `0.0.0.0` بگذار تا روتر اتصال LAN را بپذیرد.

مصرف حافظه ~۱۵–۲۰ مگابایت — روی هر روتری با ۱۲۸ مگابایت RAM به بالا اجرا می‌شود. UI روی musl نیست (روترها headlessاند).

## ابزارهای تشخیص

- **`mhrv-rs test`** — یک درخواست از طریق رله می‌فرستد، موفقیت / تأخیر گزارش می‌دهد. اولین کاری که باید بکنی وقتی چیزی خراب است — جدا می‌کند "رله سالم است" از "کانفیگ کلاینت غلط است".
- **`mhrv-rs scan-ips`** — تست TLS موازی روی ۲۸ IP frontend شناخته‌شدهٔ گوگل، مرتب‌شده بر اساس تأخیر. بهترین را در `google_ip` بگذار. UI همان را پشت دکمهٔ **scan** دارد.
- **`mhrv-rs test-sni`** — تست TLS موازی هر نام SNI در pool روی `google_ip`. می‌گوید کدام نام‌ها از DPI ISP رد می‌شوند. UI در پنجرهٔ **SNI pool…** همان را با چک‌باکس، دکمهٔ **Test** هر ردیف، و **Keep ✓ only** برای trim خودکار دارد.
- **آمار دوره‌ای** هر ۶۰ ثانیه در سطح `info` لاگ می‌شود (تماس‌های رله، نرخ hit کش، بایت رله شده، اسکریپت‌های فعال در مقابل blacklisted). UI آن را زنده نشان می‌دهد.

### ویرایشگر SNI pool

به‌طور پیش‌فرض mhrv-rs بین `{www, mail, drive, docs, calendar}.google.com` روی TLS خروجی به `google_ip` می‌چرخد، تا اثر انگشت ترافیک یکنواخت نباشد. بعضی‌ها ممکن است محلی مسدود شوند (مثلاً `mail.google.com` در ایران چند بار هدف بوده).

یا:

- UI → **SNI pool…** → **Test all** → **Keep ✓ only** برای trim خودکار. نام جدید را در فیلد پایین اضافه کن. Save.
- یا `config.json` را مستقیم ویرایش کن:

```json
{
  "sni_hosts": ["www.google.com", "drive.google.com", "docs.google.com"]
}
```

اگر `sni_hosts` تنظیم نشود، pool خودکار پیش‌فرض استفاده می‌شود. `mhrv-rs test-sni` را اجرا کن تا قبل از ذخیره ببینی چه چیزی از شبکه‌ات کار می‌کند.

## چه چیز پیاده شده و چه چیز نه

این پورت روی **حالت `apps_script`** تمرکز دارد — تنها حالتی که در سال ۲۰۲۶ مقابل سانسورگر مدرن قابل اتکاست.

### پیاده‌شده

| ویژگی | توضیح |
|---|---|
| HTTP proxy محلی | CONNECT برای HTTPS، forwarding ساده برای HTTP |
| SOCKS5 محلی | dispatch هوشمند TLS / HTTP / TCP خام (تلگرام، xray، …) |
| MITM | تولید گواهی per-domain روی پرواز با `rcgen` |
| نصب CA | تولید + نصب خودکار روی مک / لینوکس / ویندوز |
| پشتیبانی فایرفاکس | نصب گواهی NSS با `certutil` (best-effort) |
| رلهٔ JSON | پروتکل سازگار با `Code.gs` |
| Connection pool | TTL ۴۵ ثانیه، حداکثر ۲۰ idle |
| رمزگشایی gzip | اتوماتیک |
| چند اسکریپت | چرخش round-robin |
| Blacklist خودکار | روی خطای 429 / quota، با cooldown ۱۰ دقیقه |
| کش پاسخ | ۵۰ مگابایت، FIFO + TTL، آگاه از `Cache-Control: max-age`، heuristic برای static asset |
| Coalescing | GETهای یکسان همزمان یک fetch upstream را به اشتراک می‌گذارند |
| تونل بازنویسی SNI | مستقیم به لبهٔ گوگل (بدون رله) برای `google.com`، `youtube.com`، `youtu.be`، `youtube-nocookie.com`، `fonts.googleapis.com` — دامنه‌های اضافی از فیلد `hosts` |
| هندل ریدایرکت | اتوماتیک: `/exec` → `googleusercontent.com` |
| فیلتر هدر | حذف connection-specific و brotli |
| Subcommand‌ها | `test` و `scan-ips` و `test-sni` |
| ماسک Script ID | به‌صورت `prefix…suffix` در لاگ، تا Deployment ID افشا نشود |
| UI دسکتاپ | egui — کراس‌پلتفرم، بدون bundler |
| چِین SOCKS5 upstream | اختیاری برای ترافیک غیر-HTTP (MTProto تلگرام، IMAP، SSH …) |
| Pre-warm pool | اولین درخواست TLS handshake به لبهٔ گوگل را skip می‌کند |
| چرخش SNI per-connection | بین `{www, mail, drive, docs, calendar}.google.com` |
| Parallel relay | اختیاری: fan-out به N اسکریپت همزمان، اولین موفقیت برمی‌گردد |
| Drill-down آمار per-site | در UI: درخواست‌ها، نرخ کش، بایت، تأخیر متوسط هر host |
| ویرایشگر pool SNI | UI + فیلد `sni_hosts` با probe دسترسی |
| بیلد musl | OpenWRT / Alpine / محیط‌های بدون libc — باینری استاتیک، با procd init |
| **Exit node** | برای سایت‌های پشت Cloudflare (v1.9.4+) |
| **Unwrap goog.script.init** | دفاع‌در‌عمق در مقابل Deploymentهایی که پاسخ HtmlService-wrapped می‌فرستند (v1.9.6+) |

### عمداً پیاده نشده

| ویژگی | چرا نه |
|---|---|
| HTTP/2 multiplexing | state machine کریت `h2` (stream IDs، flow control، GOAWAY) موارد hang ظریف زیادی دارد؛ coalescing + pool ۲۰-conn بیشتر فایده را می‌گیرد |
| Batch (`q:[...]` در apps_script) | connection pool + tokio async از قبل خوب موازی‌سازی می‌کند؛ batch ~۲۰۰ خط مدیریت state اضافه می‌کند با سود نامشخص |
| Range-based parallel download | edge case‌های واقعی (سرورهای بدون Range، chunked وسط stream)؛ ویدیوی یوتیوب از قبل با تونل بازنویسی SNI، Apps Script را دور می‌زند |
| حالت‌های `domain_fronting` / `google_fronting` / `custom_domain` | Cloudflare در ۲۰۲۴ domain fronting عمومی را کشت؛ Cloud Run پلن پولی می‌خواهد |

## محدودیت‌های شناخته‌شده

این محدودیت‌ها ذاتی روش Apps Script + domain fronting هستند، نه باگ این کلاینت. نسخهٔ پایتون اصلی هم همین مشکلات را دارد.

### User-Agent ثابت روی `Google-Apps-Script`

برای ترافیکی که از رله رد می‌شود، `UrlFetchApp.fetch()` اجازهٔ override کردن User-Agent را نمی‌دهد. سایت‌هایی که bot detect می‌کنند (جست‌وجوی گوگل، بعضی CAPTCHAها) نسخهٔ no-JS برمی‌گردانند.

**راه‌حل:** دامنه را به فیلد `hosts` اضافه کن تا از تونل بازنویسی SNI با User-Agent واقعی مرورگرت برود. این دامنه‌ها پیش‌فرض داخل‌اند: `google.com`، `youtube.com`، `fonts.googleapis.com`.

### پخش ویدیو کند و quota-محدود

HTML یوتیوب سریع می‌آید (از تونل بازنویسی SNI)، اما chunkهای ویدیو از `googlevideo.com` از Apps Script رد می‌شوند. سهمیهٔ رایگان: ~۲۰٬۰۰۰ `UrlFetchApp` در روز، سقف بدنهٔ ۵۰ مگابایت per fetch.

برای مرور متنی خوب است، برای ۱۰۸۰p دردناک. چند `script_id` بچرخان برای هد روم بیشتر، یا VPN واقعی برای ویدیو.

### Brotli حذف می‌شود

از هدر `Accept-Encoding` ‏`br` حذف می‌شود. Apps Script gzip را decompress می‌کند ولی Brotli نه؛ forward کردن `br` پاسخ را خراب می‌کند. سربار حجمی جزئی.

### WebSocket کار نمی‌کند

این رله request/response JSON است. سایت‌هایی که به WebSocket upgrade می‌کنند fail می‌شوند (streaming ChatGPT، صدای Discord، …).

### سایت‌های HSTS-preloaded / hard-pinned

گواهی MITM را قبول نمی‌کنند. اکثر سایت‌ها مشکل ندارند؛ تعداد کمی هستند.

### هشدار «دستگاه ناشناس» در ورود حساس گوگل

2FA و ورودهای حساس گوگل / یوتیوب ممکن است هشدار «دستگاه ناشناس» بدهند، چون درخواست‌ها از IPهای Apps Script گوگل می‌آیند نه IP تو. یک‌بار از تونل وارد شو تا این مشکل برطرف شود (دامنهٔ `google.com` در لیست بازنویسی SNI است، پس از همان IP که قبلاً ورود کرده‌ای می‌رود).

## امنیت

- root MITM **فقط روی سیستم تو می‌ماند**. کلید خصوصی `ca/ca.key` محلی تولید می‌شود و هیچ‌وقت از دایرکتوری user-data خارج نمی‌شود.
- `auth_key` رمز اشتراکی است که خودت انتخاب می‌کنی. `Code.gs` سرور هر درخواست بدون این کلید را رد می‌کند.
- ترافیک بین سیستم تو و لبهٔ گوگل TLS 1.3 استاندارد است.
- آنچه گوگل می‌بیند: URL مقصد و هدرهای هر درخواست (چون Apps Script به‌جای تو fetch می‌کند). همان مدل اعتماد هر پروکسی هاست‌شده — اگر قابل قبول نیست، VPN خودمیزبانی استفاده کن.
- **هشدار افشای IP در حالت `apps_script`:** v1.2.9 همهٔ هدرهای `X-Forwarded-For` / `X-Real-IP` / `Forwarded` / `Via` / `CF-Connecting-IP` / `True-Client-IP` / `Fastly-Client-IP` و ~۱۰ هدر مشابه را قبل از رسیدن به Apps Script از خروجی حذف می‌کند ([#104](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/104)). آنچه پوشش **نمی‌دهد**: هر هدری که زیرساخت گوگل ممکن است وقتی Apps Script `UrlFetchApp.fetch()` بعدی را به مقصد می‌فرستد اضافه کند. آن leg دوم سمت سرور است، خارج از کنترل این کلاینت. مقصد IP دیتاسنتر گوگل را می‌بیند، اما تعهد عمومی از گوگل وجود ندارد که IP اصلی کاربر را در زنجیرهٔ هدرهای داخلی منتشر نمی‌کند. اگر مدل تهدیدت اینه که مقصد تحت هیچ شرایطی نباید IP تو را بفهمد، **از Full Tunnel استفاده کن** (ترافیک از VPS شخصی تو خارج می‌شود، فقط IP آن VPS end-to-end دیده می‌شود). حالت `apps_script` برای دور زدن DPI / دسترسی به سایت‌های فیلتر کاملاً مناسب است، اما فرض می‌کند «دیده‌شدن توسط گوگل» قابل قبول است. در [#148](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/148) مطرح شده.
- در v1.9.6+ `Code.gs` و `CodeFull.gs` هم هدرهای `X-Forwarded-*` / `Forwarded` / `Via` را در سمت سرور به‌عنوان لایهٔ دفاع دوم حذف می‌کنند.

## سؤالات رایج

**چند Deployment ID نیاز دارم؟** یکی برای استفادهٔ معمول کافی است. سهمیهٔ رایگان `UrlFetchApp` هر حساب ۲۰٬۰۰۰ fetch در روز است (Workspace پولی ۱۰۰٬۰۰۰)، با سقف بدنهٔ ۵۰ مگابایت per fetch. **یک Deployment per Google account** بساز — سقف ۳۰ همزمان per account است، چند Deployment روی یک حساب همزمانی اضافه نمی‌کند. برای مقیاس، در حساب‌های گوگل دیگر دیپلوی کن. مرجع: <https://developers.google.com/apps-script/guides/services/quotas>

**چرا گاهی جست‌وجوی گوگلم بدون JavaScript نشان داده می‌شود؟** Apps Script مجبور است `User-Agent` را روی `Google-Apps-Script` بگذارد. بعضی سایت‌ها این را به‌عنوان bot شناسایی کرده و نسخهٔ no-JS برمی‌گردانند. دامنه‌هایی که در لیست SNI-rewrite هستند (`google.com`، `youtube.com`، …) از این مشکل امان‌اند چون مستقیم از لبهٔ گوگل می‌آیند، نه از Apps Script.

**ورود به حساب گوگل با این ابزار ایمن است؟** توصیه: یک‌بار **بدون** پروکسی یا با VPN واقعی وارد شو. گوگل ممکن است IP Apps Script را به‌عنوان "دستگاه ناشناس" ببیند و هشدار بدهد. بعد از ورود اولیه، استفاده بی‌مشکل است.

**چطور گواهی را بعداً حذف کنم؟**
- **ساده‌ترین (هر OS):** در UI **Remove CA** را بزن، یا:
  - مک / لینوکس: `sudo ./mhrv-rs --remove-cert`
  - ویندوز (با Run as administrator): `mhrv-rs.exe --remove-cert`
  - از trust store سیستم، NSS (فایرفاکس / کروم لینوکس) حذف می‌کند، و `ca/ca.crt` + `ca/ca.key` روی دیسک پاک می‌کند. `config.json` و دیپلوی Apps Script دست‌نخورده.
- **به‌صورت دستی:** نام گواهی (Common Name) همه‌جا `MasterHttpRelayVPN` است (نه `mhrv-rs` — این نام برنامه است نه نام گواهی).
  - **مک:** Keychain Access → System → دنبال `MasterHttpRelayVPN` بگرد → حذف کن. سپس `rm -rf ~/Library/Application\ Support/mhrv-rs/ca/`
  - **ویندوز:** `certmgr.msc` → Trusted Root Certification Authorities → دنبال `MasterHttpRelayVPN` → حذف
  - **لینوکس:** `/usr/local/share/ca-certificates/MasterHttpRelayVPN.crt` را حذف کن، بعد `sudo update-ca-certificates`

**خطای `GLIBC_2.39 not found` روی لینوکس؟** از `mhrv-rs-linux-musl-amd64.tar.gz` استفاده کن — کاملاً استاتیک، روی هر لینوکس بدون `glibc` کار می‌کند.

## لایسنس

MIT. [LICENSE](../LICENSE) را ببین.

</div>
