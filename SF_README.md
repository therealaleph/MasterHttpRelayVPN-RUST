# Quick Start — mhrv-rs

A short, plain-language version. For the deep technical guide, see the [full README](README.md).

**[Quick Start (English)](#quick-start)** | **[راهنمای کامل English](README.md#setup-guide)** | **[راهنمای خلاصه فارسی](#راهنمای-خلاصه-فارسی)** | **[راهنمای کامل فارسی](README.md#راهنمای-فارسی)**

---

## Quick Start

### What this is

A free way to bypass internet censorship by routing your traffic through your own free Google account. Your ISP only sees you talking to Google; Google fetches the real websites for you.

### What you need

- A Google account (free, the regular one).
- 5–10 minutes the first time.
- The mhrv-rs app — Windows, Mac, Linux, or Android. [Download here](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/releases/latest).

### The 3 steps

**1. Set up the relay in your Google account (one-time).**
Go to <https://script.google.com>, sign in, click **New project**. Delete the sample code, paste in the [Code.gs file from this repo](assets/apps_script/Code.gs), change `AUTH_KEY = "..."` to a password only you know. Click **Deploy → New deployment → Web app**, set "Execute as: Me", "Who has access: Anyone". Copy the long ID from the URL — that's your **Deployment ID**.

> Can't reach `script.google.com` because it's blocked? Run mhrv-rs first in `google_only` mode (use [`config.google-only.example.json`](config.google-only.example.json)). It only relays Google sites and lets you reach the Apps Script editor through the bypass tunnel. Do step 1 in your browser, then switch back to normal mode.

**2. Install and run mhrv-rs.**
Download the package for your system from [Releases](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/releases/latest) and unzip it.

| If you have | Do this |
|---|---|
| Windows | double-click `run.bat` |
| Mac | double-click `run.command` |
| Linux | run `./run.sh` in a terminal |
| Android | install the APK from Releases |

The first run asks for your password — only to install a small local certificate so HTTPS sites work through the tunnel. Nothing is uploaded.

**3. Paste your details and connect.**
In the app, paste:
- **Deployment ID** — from step 1
- **Auth key** — the password you put in `Code.gs`

Click **Connect** (or **Start** on desktop). Done. Your browser, Telegram, etc. will work normally.

> **Browser:** the Connect button on Android sets up a system-wide VPN — every app uses it automatically. On desktop, set your browser HTTP proxy to `127.0.0.1:8085`, or use SOCKS5 on `127.0.0.1:8086`.

### Common issues (most people hit at least one)

**YouTube videos look "restricted" or comments are missing? ([#61](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/61))**
Turn on **"Send YouTube through relay (no SNI rewrite)"** in the desktop UI's Advanced section, or set `youtube_via_relay: true` in `config.json`. YouTube then goes through the Apps Script relay instead of the direct Google tunnel, which avoids YouTube's SafeSearch-on-SNI behaviour. Trade-off: slightly slower video, and it counts against your daily quota.

**"Verify you are human" loop on Cloudflare-protected sites?**
This can't be fixed in this app. Every Apps Script request comes from a different Google datacenter IP, and Cloudflare's challenge cookie is locked to one IP — so the next request fails the check and re-challenges you. Sites that only check once per session work fine. Sites that check every page won't.

**"504 Relay timeout" in the browser?**
Your Apps Script deployment isn't responding. Go back to <https://script.google.com>, **Deploy → Manage deployments → Edit (pencil)**, change "Version" to **New version**, click Deploy. Copy the **new** Deployment ID and paste it into the app.

**Hit your daily limit?**
Free Google accounts get **20,000 relay requests per day**. The desktop and Android apps show a "Usage today" card with how many you've used. Add multiple Deployment IDs (one per line in the UI, or a JSON array in `config.json`) — each ID has its own quota and they're rotated automatically. You can also click "View quota on Google" to see the official number on Google's dashboard.

**App says it's connected but websites don't load?**
- Open the **SNI pool** section and click **Test all**. If everything fails, your `google_ip` value is unreachable from your network — click **Auto-detect google_ip** to fix.
- Make sure you actually installed the certificate (the password prompt on first run). If you skipped it, click **Install MITM certificate** again.

### Want more detail?

- [Full English README](README.md#setup-guide) — every config option, full tunnel mode, OpenWRT, diagnostics, security notes
- [Issue tracker](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues) — search before opening a new one; lots of common questions are already answered

### Support

This project is free and run by volunteers. If it helped you and you can spare anything: **[❤️ sh1n.org/donate](https://sh1n.org/donate)**

---

## راهنمای خلاصه فارسی

نسخهٔ کوتاه و بدون اصطلاحات فنی. برای جزئیات کامل، [راهنمای کامل فارسی](README.md#راهنمای-فارسی) را ببینید.

### این چیست؟

یک ابزار رایگان برای دور زدن سانسور اینترنت از طریق یک ریلهٔ شخصی روی حساب گوگل خودتان. سرویس‌دهندهٔ شما فقط می‌بیند که در حال صحبت با گوگل هستید؛ گوگل بقیهٔ سایت‌ها را برای شما باز می‌کند.

### چه چیزی نیاز دارید؟

- یک حساب گوگل معمولی (رایگان).
- بار اول ۵ تا ۱۰ دقیقه وقت.
- برنامهٔ mhrv-rs برای ویندوز / مک / لینوکس / اندروید — [از اینجا دانلود کنید](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/releases/latest).

### سه مرحله

**۱. ساخت ریله در حساب گوگل (فقط یک بار).**
به <https://script.google.com> بروید، وارد حساب گوگل شوید و روی **New project** بزنید. کد پیش‌فرض را پاک کنید و محتوای [فایل Code.gs](assets/apps_script/Code.gs) همین مخزن را در آن جای‌گذاری کنید. خط `AUTH_KEY = "..."` را به یک رمز دلخواه که فقط خودتان می‌دانید تغییر دهید. سپس **Deploy → New deployment → Web app** را بزنید، گزینهٔ "Execute as: Me" و "Who has access: Anyone" را انتخاب کنید. آی‌دی طولانی توی URL را کپی کنید — این **Deployment ID** شماست.

> اگر `script.google.com` خودش بسته است، اول mhrv-rs را در حالت `google_only` اجرا کنید (از [`config.google-only.example.json`](config.google-only.example.json) استفاده کنید). این حالت فقط سایت‌های گوگل را تونل می‌کند تا بتوانید به ویرایشگر Apps Script برسید. مرحلهٔ ۱ را در مرورگر انجام دهید و بعد به حالت معمولی برگردید.

**۲. نصب و اجرای mhrv-rs.**
بستهٔ مخصوص سیستم خودتان را از [بخش Releases](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/releases/latest) دانلود کنید و از حالت فشرده در بیاورید.

| سیستم | کاری که باید بکنید |
|---|---|
| ویندوز | روی `run.bat` دو بار کلیک کنید |
| مک | روی `run.command` دو بار کلیک کنید |
| لینوکس | در ترمینال `./run.sh` را اجرا کنید |
| اندروید | فایل APK را از Releases نصب کنید |

اولین اجرا رمز عبور شما را می‌خواهد — فقط برای نصب یک گواهی محلی کوچک تا سایت‌های HTTPS از تونل عبور کنند. هیچ چیزی به جایی فرستاده نمی‌شود.

**۳. مشخصاتتان را وارد کنید و وصل شوید.**
در برنامه این دو را وارد کنید:
- **Deployment ID** — از مرحلهٔ ۱
- **Auth key (کلید احراز)** — همان رمزی که در `Code.gs` گذاشتید

روی **اتصال** (در اندروید) یا **Start** (در دسکتاپ) بزنید. تمام شد. مرورگر، تلگرام و بقیهٔ برنامه‌ها مثل قبل کار می‌کنند.

> **مرورگر:** دکمهٔ اتصال در اندروید یک VPN سراسری راه می‌اندازد و همهٔ برنامه‌ها خودکار از آن عبور می‌کنند. در دسکتاپ، باید پروکسی HTTP مرورگر را روی `127.0.0.1:8085` یا SOCKS5 روی `127.0.0.1:8086` تنظیم کنید.

### مشکلات رایج (اکثر کاربران حداقل یکی از این‌ها را می‌بینند)

**ویدیوهای یوتیوب «محدود» نشان داده می‌شوند یا کامنت‌ها دیده نمی‌شوند؟ ([#61](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/61))**
در بخش Advanced دسکتاپ گزینهٔ **«Send YouTube through relay (no SNI rewrite)»** را روشن کنید، یا در `config.json` مقدار `youtube_via_relay: true` بگذارید. در این حالت یوتیوب از مسیر ریلهٔ Apps Script رد می‌شود و فیلتر SafeSearch-on-SNI گوگل دور می‌خورد. تریدآف: ویدیو کمی کندتر و مصرف از سهمیهٔ روزانه.

**روی سایت‌های پشت Cloudflare loop «Verify you are human» می‌خورد؟**
این مشکل در این ابزار قابل حل نیست. هر درخواست Apps Script از یک IP متفاوت دیتاسنتر گوگل خارج می‌شود و کوکی challenge کلودفلر به یک IP خاص قفل است — درخواست بعدی از IP دیگر دوباره چالش می‌خورد. سایت‌هایی که فقط یک‌بار در ابتدای session چک می‌کنند درست کار می‌کنند. سایت‌هایی که هر صفحه چک می‌کنند، نه.

**در مرورگر «504 Relay timeout» نشان می‌دهد؟**
Apps Script شما پاسخ نمی‌دهد. به <https://script.google.com> برگردید، **Deploy → Manage deployments → Edit (آیکن مداد)** را بزنید، گزینهٔ "Version" را روی **New version** بگذارید و Deploy کنید. **آی‌دی جدید** Deployment را کپی کنید و در برنامه جای‌گذاری کنید.

**سهمیهٔ روزانه تمام شده؟**
هر حساب گوگل رایگان روزانه **۲۰٬۰۰۰ درخواست ریله** دارد. کارت «مصرف امروز» در دسکتاپ و اندروید مقدار مصرف فعلی را نشان می‌دهد. می‌توانید چند Deployment ID (هر کدام در یک خط، یا به‌صورت JSON array در `config.json`) اضافه کنید — هر آی‌دی سهمیهٔ خودش را دارد و به‌صورت چرخشی استفاده می‌شوند. دکمهٔ «مشاهدهٔ سهمیه در گوگل» شما را به داشبورد رسمی گوگل می‌برد.

**برنامه می‌گوید وصل است ولی سایت‌ها باز نمی‌شوند؟**
- بخش **SNI pool** را باز کنید و **Test all** بزنید. اگر همه fail شدند، یعنی `google_ip` فعلی از شبکهٔ شما در دسترس نیست — روی **Auto-detect google_ip** بزنید تا اصلاح شود.
- مطمئن شوید گواهی را واقعاً نصب کردید (همان رمزی که اولین اجرا خواست). اگر رد کردید، روی **Install MITM certificate** دوباره بزنید.

### جزئیات بیشتر می‌خواهید؟

- [راهنمای کامل فارسی](README.md#راهنمای-فارسی) — همهٔ گزینه‌های پیکربندی، حالت تونل کامل، OpenWRT، تشخیص خطا، نکات امنیتی
- [بخش Issues](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues) — قبل از ساخت issue جدید جست‌وجو کنید؛ خیلی از سؤالات رایج جواب داده شده‌اند

### حمایت از پروژه

این پروژه رایگان و توسط داوطلبان نگه‌داری می‌شود. اگر کمکتان کرد و چیزی از دستتان برمی‌آید
: **[❤️ sh1n.org/donate](https://sh1n.org/donate)**
