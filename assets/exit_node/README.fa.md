<div dir="rtl">

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

**Exit node** یک handler کوچک HTTP به زبان TypeScript است که روی یک
پلتفرم serverless TypeScript که خودت تأییدش می‌کنی deploy می‌شه و بین
Apps Script و destination قرار می‌گیره. مسیر traffic این می‌شه:

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
    exit node خودت (IP غیر گوگل)                          │
       │                                                  │
       │  fetch(real_url)                                 │
       └──────────────────────────────────────────────────┘
```

Destination IP خروجی exit node رو می‌بینه، نه IP datacenter گوگل.
Heuristic anti-bot CF نمی‌سوزه + صفحه واقعی برمی‌گرده.

**نکته مهم:** leg user-side (Iran ISP → Apps Script) **بدون تغییر**
است. ISP فقط TLS به Google IP می‌بینه — second hop کاملاً درون
outbound Apps Script اجرا می‌شه، invisible از شبکه‌ی کاربر. پس DPI
evasion property که mhrv-rs براش ساخته شده، دست نمی‌خوره.

## راه‌اندازی

handler در [`exit_node.ts`](exit_node.ts) plain TypeScript است که از
APIهای web-standard (`Request`، `Response`، `fetch`) استفاده می‌کنه و
روی هر پلتفرمی که serverless-fetch runtime داره اجرا می‌شه.

### مراحل عمومی (روی هر host)

۱. فایل [`exit_node.ts`](exit_node.ts) رو باز کنید و PSK پیش‌فرض رو در
ابتدا عوض کنید:
   ```ts
   const PSK = "<your-strong-secret>";
   ```
   Strong secret تولید کنید با `openssl rand -hex 32` از terminal.
   **placeholder رو در production نگذارید** — کد عمداً fail-closed است
   (در هر request 503 برمی‌گردونه) تا placeholder replace نشده، تا
   جلوی serve شدن به‌عنوان open relay accidentally گرفته بشه.
۲. فایل رو روی host انتخابی **deploy** کنید (گزینه‌ها در ادامه).
۳. URL public deployment رو **copy** کنید.
۴. در `config.json` mhrv-rs، block `exit_node` اضافه کنید:
   ```json
   "exit_node": {
     "enabled": true,
     "relay_url": "https://your-deployed-exit-node.example.com",
     "psk": "<همان PSK که در گام ۱ گذاشتید>",
     "mode": "selective",
     "hosts": ["chatgpt.com", "claude.ai", "x.com", "grok.com", "openai.com"]
   }
   ```
۵. mhrv-rs رو **restart** کنید (Disconnect + Connect، یا `kill` +
   restart binary).
۶. **تست** کنید — `chatgpt.com` یا `grok.com` رو از browser pointed به
   mhrv-rs proxy باز کنید. صفحه login واقعی رو می‌بینید، نه CF
   challenge.

config مثال کامل در
[`config.exit-node.example.json`](../../config.exit-node.example.json)
در root repo.

### گزینه‌های hosting

اسکریپت یک فایل self-contained است. هر host که می‌توانید signup کنید +
به‌اش اعتماد دارید رو انتخاب کنید:

| Host | توضیحات |
|---|---|
| **Deno Deploy** ([deno.com/deploy](https://deno.com/deploy)) | free tier برای personal use کافی است. با `deployctl deploy --prod exit_node.ts` یا GitHub Actions deploy کنید. همان web-standard API. |
| **fly.io** | free tier با محدودیت. handler رو در یک server thin بسته‌بندی کنید (`Deno.serve(handler)` برای Deno یا یک Express wrapper برای Node) + Dockerfile اضافه کنید. IP دائم، region جغرافیایی قابل انتخاب. |
| **VPS شخصی خودت** | از فایل آماده [`wrapper.ts`](wrapper.ts) استفاده کن: `deno run --allow-net --allow-env --allow-read wrapper.ts`. خودکار Deno / Bun / Node 22+ تشخیص می‌ده. حداکثر کنترل، ~۳-۵ دلار در ماه. |
| **Cloudflare Workers** | **کمک نمی‌کنه.** CF Workers از IP space خود CF خروج می‌کنن، که CF anti-bot هنوز به‌عنوان worker-internal flag می‌کنه. |

برای اکثر کاربرانی که مسیر local رو اجرا می‌کنن، Deno Deploy
سریع‌ترین setup است. برای deployment طولانی‌مدت تحت کنترل کامل
خودت، VPS کوچک شخصی ایده‌آل است.

## انتخاب `selective` vs `full`

| Mode | چی می‌کنه | کی استفاده کنید |
|---|---|---|
| `selective` (default) | فقط hosts در `hosts` از طریق exit node می‌رن؛ بقیه از مسیر Apps Script عادی | توصیه می‌شه. exit-node hop ~۲۰۰-۵۰۰ms به هر request اضافه می‌کنه — برای سایت‌هایی reserve کنید که نیاز به non-Google IP دارن. |
| `full` | همه‌ی request‌ها از طریق exit node می‌رن | فقط زمانی که کل workload شما CF-anti-bot affected است، یا exit node خود سریع‌تر روی مسیر شبکه شما (rare). budget runtime host رو برای سایت‌هایی که نیاز ندارن می‌سوزونه. |

## رفتار در صورت failure

اگر exit node در دسترس نباشه، 5xx برمی‌گردونه، یا response malformed
بفرسته، mhrv-rs **به‌طور خودکار به Apps Script relay عادی fallback
می‌کنه**. در log یک خط `warn: exit node failed for ... — falling back
to direct Apps Script` می‌بینید. سایت‌هایی که نیاز به exit node دارن در آن
case fail می‌گیرن (CF challenge)، ولی سایر سایت‌ها کار می‌کنن — یک
exit node down شما رو fully offline نمی‌کنه.

## Security model

PSK تنها چیز است که مانع می‌شه endpoint deployed یک public open proxy
بشه. مثل password برخورد کنید:

- **commit نکنید** PSK رو به source control. اکثر hostها به‌طور default
  کد deployed رو private نگه می‌دارن؛ همان‌طور نگه دارید.
- **publicly share نکنید** PSK رو. هر کسی که هم URL هم PSK رو داره
  می‌تونه quota host شما رو به‌عنوان proxy خود استفاده کنه.
- **rotate** اگر leak مشکوک هست. PSK رو در source deployed تغییر بدید،
  redeploy کنید، سپس `psk` در `config.json` mhrv-rs رو update + restart.

اسکریپت همچنین شامل **loop guard** هست (refuse می‌کنه fetch host خود)
+ **placeholder check** (در صورت `PSK === "CHANGE_ME_TO_A_STRONG_SECRET"`
return 503 می‌کنه) تا یک fresh deploy بدون setup نتونه به‌طور
accidentally به‌عنوان open relay سرو بشه.

## چرا default-on نیست

- ۲۰۰-۵۰۰ms به هر request اضافه می‌کنه (hop اضافی)
- budget bandwidth free-tier host رو می‌سوزونه
- برای سایت‌هایی که CF anti-bot ندارن benefit نداره
- Setup یک account جداگانه روی پلتفرم third-party می‌خواد

پس `enabled: false` default است. کاربرانی که خصوصاً به ChatGPT / Claude /
Grok اهمیت می‌دن opt in؛ همه‌ی دیگران lighter اجرا می‌کنن.

## Troubleshooting

**`exit node refused or errored: unauthorized`** — PSK mismatch.
بررسی کنید `psk` در `config.json` دقیقاً با `PSK` constant در source
deployed match هست. whitespace + quoting مهم است.

**`exit node refused or errored: exit_node misconfigured: PSK is still
the placeholder`** — فراموش کردید `CHANGE_ME_TO_A_STRONG_SECRET` رو
در source جایگزین کنید. فایل deployed رو edit + save + redeploy کنید.

**`exit node failed for ...: connection refused`** — URL اشتباه است
یا deployment live نیست. با hit کردن URL مستقیم از browser verify
کنید — باید `{"e":"method_not_allowed"}` برگردونه (handler expects
POST).

**`exit node failed for ...: timeout`** — outbound host slow است
یا destination slow. region متفاوت رو امتحان کنید، یا latency
trade-off رو accept کنید.

**سایت همچنان CF challenge نشون می‌ده بعد از enable exit node** — CF
IP host شما رو هم flag کرده. بعضی hosting provider‌ها outbound IP
space‌شون روی CF bot blocklist است. workarounds: host دیگه امتحان
کنید (VPS شخصی شما clean IP می‌ده)، یا سایت رو به `passthrough_hosts`
اضافه کنید (MITM رو bypass می‌کنه؛ از real IP ISP شما استفاده
می‌کنه).

## همچنین ببینید

- [English version](README.md) of this doc
- [`exit_node.ts`](exit_node.ts) — منبع handler (با hardening)
- [`config.exit-node.example.json`](../../config.exit-node.example.json)
  — config مثال کامل
- Issue [#382](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/382)
  — thread tracking canonical Cloudflare anti-bot
- Issue [#309](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/309)
  — roadmap CF WARP integration (approach جایگزین، longer-horizon)

</div>
