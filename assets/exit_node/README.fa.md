# Exit node — دور زدن CF anti-bot برای ChatGPT / Claude / Grok / X

بسیاری از سرویس‌های پشت Cloudflare، traffic از رنج IP datacenter
گوگل را به‌عنوان bot flag می‌کنن + به‌جای صفحه واقعی یک Turnstile /
CAPTCHA / 502 challenge می‌فرستن. `UrlFetchApp.fetch()` در Apps
Script از همان رنج IP datacenter Google خروج می‌کنه، پس برای سایت‌هایی مانند:

- **chatgpt.com / openai.com**
- **claude.ai**
- **grok.com / x.com**

…مسیر apps_script-mode عادی mhrv-rs ارورهایی مثل
`Relay error: json: key must be a string at line 2 column 1` یا
`502 Relay error` می‌ده چون Code.gs در حال wrap کردن صفحه‌ی HTML
challenge CF است که کلاینت نمی‌تونه parse کنه.

**Exit node** یک endpoint کوچک TypeScript HTTP است که روی یک پلتفرم
serverless (val.town، Deno Deploy، fly.io، …) deploy می‌شه + بین Apps
Script و destination قرار می‌گیره. مسیر traffic این می‌شه:

```
Browser ─┐                                                ┌─→ Destination
         │                                                │   (chatgpt.com)
         ▼                                                │
    mhrv-rs                                               │
       │                                                  │
       │  TLS به Google IP، SNI=www.google.com (DPI cover)│
       ▼                                                  │
   Apps Script (Google datacenter)                        │
       │                                                  │
       │  UrlFetchApp.fetch(EXIT_NODE_URL)                │
       ▼                                                  │
    val.town (non-Google IP)                              │
       │                                                  │
       │  fetch(real_url)                                 │
       └──────────────────────────────────────────────────┘
```

Destination IP val.town رو می‌بینه، نه Google datacenter. heuristic
anti-bot CF نمی‌سوزه + صفحه واقعی برمی‌گرده.

**نکته مهم:** leg user-side (Iran ISP → Apps Script) **بدون تغییر**
است. ISP فقط TLS به Google IP می‌بینه — second hop کاملاً درون
outbound Apps Script اجرا می‌شه، invisible از شبکه‌ی کاربر. پس DPI
evasion property که mhrv-rs براش ساخته شده، دست نمی‌خوره.

## راه‌اندازی

1. **در [val.town](https://val.town) ثبت‌نام کنید** (free tier کافی
   است — bandwidth outbound free tier برای personal use کافی).
2. **یک HTTP val جدید بسازید** (TypeScript). در val.town: New → HTTP.
3. **محتوای `valtown.ts`** از این directory رو paste کنید.
4. **PSK رو در بالای فایل تنظیم کنید**:
   ```ts
   const PSK = "<your-strong-secret>";
   ```
   Strong secret تولید کنید با `openssl rand -hex 32` از terminal.
   **placeholder رو در production نگذارید** — کد val.town عمداً
   fail-closed است (در هر request 503 برمی‌گردونه) تا placeholder
   replace نشده، تا جلوی serve شدن به‌عنوان open relay accidentally
   گرفته بشه.
5. **Save** کنید val رو. URL public val رو copy کنید — به این شکل:
   `https://your-handle-mhrv.web.val.run`.
6. **در `config.json` mhrv-rs**، block `exit_node` اضافه کنید:
   ```json
   "exit_node": {
     "enabled": true,
     "relay_url": "https://your-handle-mhrv.web.val.run",
     "psk": "<همان PSK که در گام 4 گذاشتید>",
     "mode": "selective",
     "hosts": ["chatgpt.com", "claude.ai", "x.com", "grok.com", "openai.com"]
   }
   ```
7. **mhrv-rs رو restart کنید** (Disconnect + Connect، یا `kill` +
   restart binary).
8. **تست کنید** — `chatgpt.com` یا `grok.com` رو از browser pointed به
   mhrv-rs proxy باز کنید. صفحه login واقعی رو می‌بینید، نه CF challenge.

config مثال کامل در
[`config.exit-node.example.json`](../../config.exit-node.example.json)
در root repo.

## انتخاب `selective` vs `full`

| Mode | چی می‌کنه | کی استفاده کنید |
|---|---|---|
| `selective` (default) | فقط hosts در `hosts` از طریق exit node می‌رن؛ بقیه از مسیر Apps Script عادی | توصیه می‌شه. exit-node hop ~۲۰۰-۵۰۰ms به هر request اضافه می‌کنه — برای سایت‌هایی reserve کنید که نیاز به non-Google IP دارن. |
| `full` | همه‌ی request‌ها از طریق exit node می‌رن | فقط زمانی که کل workload شما CF-anti-bot affected است، یا exit node خود از Apps Script سریع‌تر روی مسیر شبکه شما (rare). budget runtime val.town رو برای سایت‌هایی که نیاز ندارن می‌سوزونه. |

## رفتار در صورت failure

اگر exit node در دسترس نباشه، 5xx برمی‌گردونه، یا response malformed
بفرسته، mhrv-rs **به‌طور خودکار به Apps Script relay عادی fallback
می‌کنه**. در log یک خط `warn: exit node failed for ... — falling back
to direct Apps Script` می‌بینید. سایت‌هایی که نیاز به exit node دارن در آن
case fail می‌گیرن (CF challenge)، ولی سایر سایت‌ها کار می‌کنن — یک
exit node down شما رو fully offline نمی‌کنه.

## Security model

PSK تنها چیز است که مانع می‌شه val.town endpoint یک public open proxy
بشه. مثل password برخورد کنید:

- **commit نکنید** PSK رو به source control. منبع val.town به‌طور
  default برای account شما private است؛ همان‌طور نگه دارید.
- **publicly share نکنید** PSK رو. هر کسی که هم URL هم PSK رو داره
  می‌تونه quota val.town شما رو به‌عنوان proxy خود استفاده کنه.
- **rotate** اگر leak مشکوک هست. PSK رو در val.town source تغییر بدید،
  save کنید، سپس `psk` در `config.json` mhrv-rs رو update + restart.

اسکریپت val.town شامل **loop guard** هم هست (refuse می‌کنه fetch host
خود) + **placeholder check** (در صورت `PSK === "CHANGE_ME_TO_A_STRONG_SECRET"`
return 503 می‌کنه) تا یک fresh deploy بدون setup نتونه به‌طور
accidentally به‌عنوان open relay سرو بشه.

## پلتفرم‌های جایگزین

اسکریپت `valtown.ts` plain TypeScript است که از web-standard APIs
(`Request`، `Response`، `fetch`) استفاده می‌کنه. اجرا می‌شه روی:

- **val.town** — ساده‌ترین، free tier کافی برای personal use
- **Deno Deploy** — API مشابه؛ deploy با `deployctl`
- **fly.io** — نیاز به `Dockerfile` wrapper؛ region geographic ثابت
- **Cloudflare Workers** — کمک نمی‌کنه (CF Workers از IP space خود CF
  خروج می‌کنن، که CF anti-bot هنوز به‌عنوان worker-internal flag می‌کنه)

برای اکثر کاربران، val.town انتخاب درست است. Deno Deploy اگر option
non-val.town برای redundancy می‌خواید.

## چرا default-on نیست

- ۲۰۰-۵۰۰ms به هر request اضافه می‌کنه (hop اضافی)
- budget bandwidth free-tier val.town رو می‌سوزونه
- برای سایت‌هایی که CF anti-bot ندارن benefit نداره
- Setup یک account جداگانه روی پلتفرم third-party می‌خواد

پس `enabled: false` default است. کاربرانی که خصوصاً به ChatGPT / Claude /
Grok اهمیت می‌دن opt in؛ همه‌ی دیگران lighter اجرا می‌کنن.

## Troubleshooting

**`exit node refused or errored: unauthorized`** — PSK mismatch.
بررسی کنید `psk` در `config.json` دقیقاً با `PSK` constant در val.town
match هست. whitespace + quoting مهم است.

**`exit node refused or errored: exit_node misconfigured: PSK is still
the placeholder`** — فراموش کردید `CHANGE_ME_TO_A_STRONG_SECRET` رو
در val.town جایگزین کنید. val رو edit + save کنید.

**`exit node failed for ...: connection refused`** — URL val.town
اشتباه است یا val deploy نشده. با hit کردن URL مستقیم از browser
verify کنید — باید `{"e":"method_not_allowed"}` برگردونه (val expects
POST).

**`exit node failed for ...: timeout`** — outbound val.town slow است
یا destination slow. region val.town متفاوت رو امتحان کنید، یا latency
trade-off رو accept کنید.

**سایت همچنان CF challenge نشون می‌ده بعد از enable exit node** — CF
IP val.town رو هم flag می‌کنه. برخی customers CF صراحتاً val.town رو
blocklist کردن. workarounds: Deno Deploy رو امتحان کنید، یا سایت رو
به `passthrough_hosts` اضافه کنید (MITM رو bypass می‌کنه؛ از real
IP ISP شما استفاده می‌کنه).

## همچنین ببینید

- [English version](README.md) of this doc
- [`valtown.ts`](valtown.ts) — منبع val.town (با hardening)
- [`config.exit-node.example.json`](../../config.exit-node.example.json)
  — config مثال کامل
- Issue [#382](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/382)
  — thread tracking canonical Cloudflare anti-bot
- Issue [#309](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/309)
  — roadmap CF WARP integration (approach جایگزین، longer-horizon)
