# Persian reply templates

These are starting templates for the highest-frequency Persian-language replies. Don't use them verbatim — adapt to the specific user's log lines, config, and report. They exist to prevent re-deriving common phrasings each time and to keep the project's Persian voice consistent across replies.

The conventions throughout assume:
- Polite professional register (`می‌فرمایید` over `می‌گی`, full pronouns)
- Half-spaces (ZWNJ, `‌`) in compound words
- Latin-script for technical terms inline with Persian particles
- Persian numerals optional in prose (`۲۰،۰۰۰` or `20,000` both fine — match the user)
- Code blocks always in Latin
- Reply marker (Latin) at end

## Template 1: AUTH_KEY mismatch (with redeploy-as-new-version walkthrough)

For users showing the v1.8.x decoy detection log line:

```markdown
این `502` با body `The script completed but did not return anything` دقیقاً همان pattern decoy detection است که در v1.8.x اضافه شد. شش علت ممکن (per v1.8.3 taxonomy) داره ولی محتمل‌ترین برای case شما **AUTH_KEY mismatch** است.

**نکته بسیار مهم که اکثر کاربران نمی‌دونند:**

اگر AUTH_KEY رو در Code.gs ویرایش کرده‌اید **بعد از deployment اولیه**، Apps Script اتومات edit رو در deployment موجود pick-up نمی‌کنه. لازمه که **redeploy as new version** کنید:

1. در Apps Script web editor بازش کنید
2. Deploy → **Manage Deployments** (نه Deploy → New deployment)
3. روی **deployment موجود** کلیک کنید → پنسیل (Edit)
4. در dropdown **Version** → **New version** انتخاب کنید (نه "Head")
5. Description بنویسید (مثلاً "AUTH_KEY update")
6. **Deploy** کلیک کنید

URL deployment همون می‌مونه ولی الان Apps Script کد جدید با AUTH_KEY جدید رو serve می‌کنه.

**Diagnostic سریع برای تأیید AUTH_KEY mismatch:**

در بالای Code.gs این خط رو پیدا کنید:

`const DIAGNOSTIC_MODE = false;`

تغییر دهید به:

`const DIAGNOSTIC_MODE = true;`

سپس **redeploy as new version** کنید (مثل بالا). سپس test:

- اگر **هنوز decoy body همون** برمی‌گرده → علت **NOT** AUTH_KEY mismatch است (یکی از سایر ۵ علت)
- اگر **JSON `{"e":"unauthorized"}` صریح** برمی‌گرده → بله، AUTH_KEY mismatch — fix رو با aligning AUTH_KEY در config.toml با Code.gs انجام دهید + redeploy as new version

بعد از debug کامل، DIAGNOSTIC_MODE رو به `false` برگردونید + redeploy. در production این flag رو false نگه می‌داریم چون decoy body anti-fingerprinting protection محسوب می‌شه.

نتیجه DIAGNOSTIC_MODE flip + پیغام دقیق error بعد از redeploy رو share کنید + می‌تونیم narrow کنیم.

---
<sub>[reply via Anthropic Claude | reviewed by @therealaleph]</sub>
```

## Template 2: TUNNEL_AUTH_KEY exact spelling

For users showing `tunnel_auth_key not set, using defaults` in `docker logs mhrv-tunnel`:

```markdown
مشکلت یادم نرفته! `tunnel_auth_key not set, using defaults` در log‌ها یعنی **اسم env variable هنوز اشتباه است**. می‌خوام دقیق‌تر توضیح بدم چون اسم env vars خیلی sensitive هست:

**اسم env variable باید دقیقاً این باشد** (نه چیز دیگه‌ای، نه شبیه به این):

```
TUNNEL_AUTH_KEY
```

- **همه‌ش حروف بزرگ**
- **با underscore (`_`) بین کلمات** — نه فاصله، نه dash
- **سه قسمت**: `TUNNEL` + `_` + `AUTH` + `_` + `KEY`

**اشتباهات رایج که `tunnel_auth_key not set` می‌ده:**

| اشتباه | چرا کار نمی‌کنه |
|--------|-----------------|
| `Tunnel` یا `tunnel` (تنها) | اسم کامل نیست، tunnel-node این رو نمی‌خونه |
| `Tunnel_Auth_Key` یا `tunnel_auth_key` (lowercase/mixed) | env vars در Linux/Docker case-sensitive هستن |
| `TUNNEL-AUTH-KEY` (با dash) | باید underscore باشه نه dash |
| `MHRV_AUTH_KEY` | اشتباه قدیمی، tunnel-node این رو نمی‌خونه |

**دستور docker run درست — کپی exact:**

```bash
ssh root@your-vps-ip
docker stop mhrv-tunnel
docker rm mhrv-tunnel

docker run -d --name mhrv-tunnel \
  --restart unless-stopped \
  -p 8443:8443 \
  -e TUNNEL_AUTH_KEY="your-secret-here" \
  ghcr.io/therealaleph/mhrv-tunnel-node:latest
```

به‌جای `your-secret-here` همون مقداری که در CodeFull.gs گذاشتید بنویسید.

**verify بعد از start:**

```bash
docker exec mhrv-tunnel env | grep TUNNEL_AUTH_KEY
```

اگر خروجی این باشه:
```
TUNNEL_AUTH_KEY=your-secret-here
```
درسته. اگر هیچ خروجی نداد یا خروجی متفاوت بود، دستور `docker run` با اسم اشتباه اجرا شده.

نتیجه + خروجی `docker exec` رو share کنید + اگر همچنان مشکل بود narrow می‌کنیم.

---
<sub>[reply via Anthropic Claude | reviewed by @therealaleph]</sub>
```

## Template 3: #313 ISP throttle (for "504 timeout" reports)

For users with intermittent timeouts that look like ISP throttle:

```markdown
این الگو با [#313](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/313) (Iran ISP throttle Apps Script outbound) match می‌کنه. throttle این هفته در حال پلاسی بوده — گاهی off می‌شه ساعتی، گاهی روزی.

**Diagnostic سریع — direct curl test:**

```bash
curl -L -X POST 'https://script.google.com/macros/s/YOUR_DEPLOYMENT_ID/exec' \
  -H 'Content-Type: application/json' \
  -d '{"k":"YOUR_AUTH_KEY","u":"https://httpbin.org/get","m":"GET"}' \
  --max-time 30 -w "\ntime: %{time_total}s\n"
```

اجرا کنید ۵-۱۰ بار. اگر:

- اکثرشون timeout/RST می‌گیرن = #313 ISP throttle (شبکه شما Apps Script رو filter می‌کنه)
- اکثرشون JSON برمی‌گردونن = مشکل از path mhrv-rs است (config، auth_key، یا غیره)

**Workaround احتمالی برای ISP throttle:**

۱. **به نسخه v1.8.3 (الان موجود) ارتقا دهید:**
   - دانلود از <https://github.com/therealaleph/MasterHttpRelayVPN-RUST/releases/tag/v1.8.3> یا <https://t.me/mhrv_rs>
   - شامل DoH bypass، H1 keepalive، 6-cause error detection

۲. **`disable_padding: true` در config:**

```toml
[relay]
disable_padding = true
```

~۲۵٪ bandwidth کم‌تر، در شبکه‌های throttle شده compounds رو کم می‌کنه.

۳. **`google_ip` متفاوت تست کنید** — default `216.239.38.120` ممکنه روی شبکه شما filter شده + یکی دیگه از pool reachable است. لیست pool در `src/domain_fronter.rs` `DEFAULT_GOOGLE_SNI_POOL`.

۴. **شبکه عوض کنید** — همراه/MCI کم‌ترین throttle داره معمولاً. اگر روی Wi-Fi مخابرات هستید، با موبایل دیتا تست کنید.

۵. **چند `script_ids` داشته باشید** — اگر یک deployment quota tear گرفته یا throttle شده، rotation کار می‌کنه. حداقل ۳-۵ deployment.

۶. **اگر VPS دارید** — Full mode رو امتحان کنید (راهنما [tunnel-node README فارسی](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/blob/main/tunnel-node/README.fa.md)). ISP throttle Apps Script outbound روی Full mode اعمال نمی‌شه.

نتیجه v1.8.3 + curl test + log رو share کنید + می‌تونیم narrow کنیم.

---
<sub>[reply via Anthropic Claude | reviewed by @therealaleph]</sub>
```

## Template 4: VPS setup (Full mode) walkthrough

For "how do I set up VPS?" questions:

```markdown
**Q: آیا VPS باید مستقیم از Iran قابل دسترسی باشه؟**

**کوتاه: نه.** VPS لازم نیست از Iran direct reachable باشه. این مزیت architectural mhrv-rs Full mode است.

مسیر traffic:

```
Phone (Iran) → mhrv-rs client (Iran) → Apps Script (via Google IP fronting) →
                                       Apps Script's UrlFetchApp →
                                       VPS tunnel-node container →
                                       upstream internet
```

دقت کنید: **مسیر از Iran به VPS از طریق Apps Script می‌گذره**. پس:

- Iran ISP فقط TLS traffic به Google IPها می‌بینه (`216.239.38.120` و سایر) — مثل HTTPS عادی به Google
- Apps Script (در Google data center، US/EU) به VPS شما call می‌کنه
- VPS شما فقط traffic از Google IP می‌گیره (Apps Script's outbound)

پس حتی اگر VPS IP از Iran ISP filter شده باشه، **مهم نیست** چون هیچ Iran connection direct به VPS نمی‌ره.

**Setup گام‌به‌گام:**

**۱. خرید VPS:**

- اگر می‌توانید Hetzner direct: ~€۴.۵۰/ماه از Falkenstein DE — [hetzner.com/cloud](https://www.hetzner.com/cloud)
- اگر VAT ID نیست: Parspack ([parspack.com/vps](https://parspack.com/vps)) واسطه‌ی آلمانی فروش می‌کنه با ~۲۵۰-۵۰۰ هزار تومان/ماه

specs توصیه شده:
- شخصی: 1 vCPU، 1 GB RAM، 25 GB SSD، 50+ Mbps unmetered
- خانوادگی (۵+ device + Instagram smooth): 2-4 GB RAM، 100 Mbps unmetered

**۲. Docker install:**

```bash
ssh root@your-vps-ip
apt update && apt upgrade -y
apt install -y docker.io
systemctl enable --now docker
docker --version  # verify
```

**۳. tunnel-node container run:**

```bash
docker run -d --name mhrv-tunnel \
  --restart unless-stopped \
  -p 8443:8443 \
  -e TUNNEL_AUTH_KEY="your-secret-here" \
  ghcr.io/therealaleph/mhrv-tunnel-node:latest
```

**اسم env var دقیقاً `TUNNEL_AUTH_KEY` ست** — uppercase، با underscore. هر deviation در default `changeme` می‌افته + بعداً mismatch می‌سازه.

برای ساخت secret تصادفی:
```bash
openssl rand -hex 32
```

**۴. firewall:**

```bash
sudo ufw allow 8443/tcp
sudo ufw allow ssh
sudo ufw enable
```

**۵. verify direct از خود VPS:**

```bash
curl -X POST 'http://localhost:8443/tunnel' \
  -H 'Content-Type: application/json' \
  -d '{"k":"YOUR_TUNNEL_SECRET","op":"connect","host":"www.google.com","port":443}' \
  --max-time 10
```

باید JSON success برگرده. اگر نه، tunnel-node container start نشده.

**۶. CodeFull.gs setup:**

در [`assets/apps_script/CodeFull.gs`](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/blob/main/assets/apps_script/CodeFull.gs) محتوا رو copy کنید + در script.google.com یک پروژه جدید ایجاد کنید + paste کنید.

بالای فایل تنظیم کنید:

```js
const AUTH_KEY = "your-mhrv-auth-key";
const TUNNEL_URL = "http://YOUR_VPS_IP:8443/tunnel";
const TUNNEL_AUTH_KEY = "your-tunnel-secret-here";  // match با docker run -e
```

سپس **Deploy → New deployment → Web App → Execute as: Me + Who has access: Anyone → Deploy**. URL deployment رو copy کنید + ID بخشش رو بردارید.

**۷. mhrv-rs config:**

```toml
[relay]
mode = "full"
auth_key = "your-mhrv-auth-key"
script_ids = ["YOUR_DEPLOYMENT_ID"]
```

**`script_ids` plural با s** — این یک typo رایجه که config رو 0-deployment می‌کنه.

**۸. Connect + verify:**

mhrv-rs رو start کنید + log باید نشون بده:

```
INFO batch: 1 ops → AKfyc..., rtt=Xs    ← good
INFO tunnel session abc1234... opened for ...:443    ← good
```

اگر `ERROR batch failed: got the v1.8.0 bad-auth decoy` می‌گیرید، AUTH_KEY mismatch است (gam ۶ check کنید).

اگر `Connection refused` به VPS، firewall بسته است (gam ۴ بررسی کنید).

برای فارسی-language راهنما با تصاویر [tunnel-node README فارسی](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/blob/main/tunnel-node/README.fa.md) رو ببینید.

اگر در گامی fail کرد، error log + خروجی command رو share کنید + می‌تونیم narrow کنیم.

---
<sub>[reply via Anthropic Claude | reviewed by @therealaleph]</sub>
```

## Template 5: Account suspension / phone-required (for "action required" reports)

For users reporting Google account flag or "action required" notifications:

```markdown
این الگو شناخته‌شده‌ست + در اساس Google's anti-abuse system فلاگ می‌کنه new accounts که immediately Apps Script deployment می‌سازن (مخصوصاً بدون phone verification).

**Stage تشخیص account flag:**

```
Stage 1: "Action required - add phone number"
   ↓ (phone اضافه می‌شه) → account stable
   ↓ (phone اضافه نمی‌شه + automation activity ادامه می‌ده)
   ↓
Stage 2: "Account temporarily restricted"
   ↓ (Apps Script deployments شروع می‌کنن Workspace landing HTML برگردونن
   ↓  به‌جای execute کردن — see #421 + cause #6 در v1.8.3 detection)
   ↓
Stage 3: "Account suspended" — full lockout، deployments fail
```

شما الان در Stage 1. اگر زود phone verify کنید، account stable می‌مونه + deployments بدون مشکل ادامه می‌دن.

**برای فکر شما درباره ban Google account کلی:**

در history reports این پروژه (~۵۰+ کاربر در طول سال گذشته)، **هیچ confirmed case full account ban** ندیدم. consequences scope-شده به Apps Script + UrlFetchApp quota — نه Gmail یا Drive یا سایر Google services. accounts با history regular usage (Gmail, Drive files، etc.) و age چند سال + در low-risk قرار دارند برای personal CodeFull.gs deployment.

**workarounds:**

**۱. بهترین: phone اضافه کنید.**

Iranian phone گاهی filter می‌شه، ولی می‌توانید:

- phone یک friend/family member outside Iran استفاده کنید (SMS code رو forward کنند)
- TextNow / Google Voice (US) / paid SMS-receive services
- بعضی موارد Google یک phone رو روی چند account قبول می‌کنه (~۵ account per phone limit)

**۲. اگر phone نمی‌توانید:**

accounts احتمالاً به Stage 2-3 progress می‌کنن طی روزها-تا-هفته. برای حفظ service:

- deployments جدید زیر accounts متفاوت بسازید قبل از اینکه old fail کنه
- از **community shared deployment** workflow ([#325](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/325)) استفاده کنید — friend با account stable deployment می‌سازه + ID share می‌کنه + AUTH_KEY مشترک

**۳. برای access به script.google.com وقتی شبکه slow:**

می‌توانید از **mhrv-rs خود** برای access به script.google.com استفاده کنید. mhrv-rs's HTTP proxy به browser → CONNECT tunneling به Google عمل می‌کنه (نه UrlFetchApp.fetch — که Google block می‌کنه). browser رو با proxy `127.0.0.1:8086` تنظیم کنید + بروید script.google.com.

**Action item:**

اگر Stage 1a هستید (notification ولی deployments هنوز کار می‌کنن): فوراً phone verify کنید.

اگر Stage 1b هستید (deployments شروع به Workspace HTML برمی‌گردونن): همان، plus rotation deployment‌ها به accounts سالم.

---
<sub>[reply via Anthropic Claude | reviewed by @therealaleph]</sub>
```

## Template 6: Architectural limit (Google services + UrlFetchApp self-loop)

For users asking why `cloud.google.com` / `colab` / `gmail` / `meet` / `gemini` doesn't work:

```markdown
این محدودیت **architectural** است + ربطی به config یا setup شما نداره.

**Apps Script's UrlFetchApp self-loop restriction:**

`UrlFetchApp.fetch()` Google در API hardcoded ساخته که نمی‌تونه به دامنه‌های `*.google.com` / `*.googleapis.com` / `*.gstatic.com` request بفرسته. Apps Script یا empty response می‌ده یا 4xx/5xx error.

این محدودیت **Google ست** (نه implementation ما) + در Apps Script API documentation هم ذکر شده. هیچ HTTP-relay مبتنی بر Apps Script نمی‌تونه به Google services از Apps Script→Google path برسه.

**سایت‌های متأثر:**

- `cloud.google.com` — Console
- `colab.research.google.com` — Colab
- `gemini.google.com` — Gemini chat
- `drive.google.com` — Drive
- `docs.google.com` / `sheets.google.com` / `slides.google.com` — Workspace
- `meet.google.com` — Meet (Web)
- `mail.google.com` — Gmail
- `script.google.com/home/usage` — Apps Script dashboard
- `*.google.com` به‌طور کلی

**راه‌حل‌ها:**

**۱. سایت‌های alternative:**

- به‌جای Drive: WebDAV / Mega / Cloudflare R2
- به‌جای Colab: Kaggle Notebooks / Jupyter Lab روی VPS
- به‌جای Gemini: ChatGPT (openai.com) / Claude (claude.ai) — اگر CF block نشدن، کار می‌کنن
- به‌جای Cloud Console: SSH مستقیم یا cloud provider's CLI

**۲. Full mode + VPS:**

VPS از طرف خود به Google direct وصل می‌شه. در Full mode، traffic Google رو می‌توانید با xray dual-routing از mhrv-rs bypass کنید. detail در [#420](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/420). با این setup همه‌ی Google services از طریق VPS direct کار می‌کنن.

**۳. temp VPN موقت:**

برای access گاه‌گاهی به Google services (مثلاً برای download فایل از Drive یا setup OAuth)، یک VPN موقت ۱۰ دقیقه‌ای استفاده کنید + سپس به mhrv-rs برمی‌گردید.

**نتیجه:**

اگر می‌خواهید سایت‌های Google کار کنن با همان setup mhrv-rs که الان دارید، نیاز به Full mode + VPS + xray routing است. تا وقتی فقط apps_script mode دارید، Google services unreachable می‌مونن.

---
<sub>[reply via Anthropic Claude | reviewed by @therealaleph]</sub>
```

## Common Persian phrases for inline use

When writing custom replies, these phrases come up frequently and should be standardized:

| Concept | Persian phrasing |
|---------|------------------|
| "redeploy as new version" | `redeploy as new version کنید (نه head)` |
| "exact match" | `دقیقاً match کنه` / `exact match` |
| "case-sensitive" | `case-sensitive است` |
| "ISP throttle" | `ISP throttle` (English term, transliterate not used) |
| "narrow down" | `narrow کنیم` |
| "share the log" | `log رو share کنید` |
| "thanks for the report" | `ممنون از گزارش` / `تشکر از گزارش` |
| "I owe you" / "apologies" | `معذرت می‌خوام بابت` |
| "for your specific case" | `برای case خاص شما` |
| "unfortunately" | `متأسفانه` |
| "the workaround is" | `workaround این هست که...` |
| "this is a known issue" | `این مشکل شناخته شده است` |
| "feature is queued" | `feature در roadmap است` |
| "we'll ship in v1.x.y" | `در v1.x.y ship می‌شه` |
| "configuration file" | `فایل config` |
| "command line" | `command line` / `terminal` / `ترمینال` |
| "deployment" (Apps Script) | `deployment` (transliterated `دپلوی` is not used in this project) |
| "tunnel" (Full mode) | `tunnel` |
| "browser" | `browser` / `مرورگر` |
| "system proxy" | `system proxy` |
| "page loads but X doesn't work" | `page بالا میاد ولی X کار نمی‌کنه` |
| "I tested with curl" | `با curl تست کردم` |
| "the bug is fixed in vX.Y.Z" | `bug در vX.Y.Z حل شده` |
| "thanks for catching this" | `ممنون از catch کردن این` |
| "let me know if it works" | `اگر کار کرد گزارش بدید` |
| "if it fails again, share the log" | `اگر دوباره fail کرد، log رو share کنید` |

These let Persian replies use English technical terms naturally without forced transliteration, which matches how Iranian developers actually talk.
