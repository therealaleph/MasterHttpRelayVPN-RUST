# Tunnel Node — راهنمای فارسی

> *English: [README.md](./README.md)*

سرور پل HTTP-tunnel برای حالت `full` در MasterHttpRelayVPN. درخواست‌های HTTP-tunnel رو که از Apps Script می‌رسن، به اتصال‌های واقعی TCP/UDP تبدیل می‌کنه.

این `tunnel-node` همون قطعه‌ای از مسیر Full mode هست که روی **VPS شما** اجرا می‌شه. جواب کوتاه به سؤال «آیا VPS لازمه؟» = **بله، برای حالت Full بدون VPS کار نمی‌کنه**.

## معماری

```
موبایل/PC → mhrv-rs → [TLS با domain-fronting روی Google] → Apps Script → [HTTP] → Tunnel Node (روی VPS شما) → [TCP/UDP واقعی] → اینترنت
```

Tunnel-node session‌های پایدار TCP و UDP رو نگه می‌داره. session‌های TCP اتصال‌های واقعی به سرور مقصد هستن؛ session‌های UDP، socketهای connected-UDP به یک `host:port` مقصد هستن. data از طریق پروتکل JSON جریان داره:

- **connect** — باز کردن TCP به `host:port` + برگرداندن session ID
- **data** — نوشتن data کلاینت + خوندن جواب سرور
- **udp_open** — باز کردن UDP به `host:port`، اختیاری اولین datagram رو همزمان می‌فرسته
- **udp_data** — یک datagram UDP می‌فرسته، یا اگه `d` ست نشه برای datagram‌های برگشتی poll می‌کنه
- **close** — تخریب session
- **batch** — پردازش چند op در یک request HTTP (تعداد روند-تریپ کمتر)

## استقرار

### Cloud Run (پیشنهاد برای کاربران ایرانی متأثر از فیلتر #313)

اجرای tunnel-node روی **Google Cloud Run** یعنی destination IP خود Google هست — احتمال filter شدن مسیر Apps Script → tunnel-node توسط ISP ایران بسیار پایین‌تر از Hetzner/DigitalOcean. ([کانتکست در #313](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/313))

```bash
cd tunnel-node
gcloud run deploy tunnel-node \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars TUNNEL_AUTH_KEY=$(openssl rand -hex 24) \
  --memory 256Mi \
  --cpu 1 \
  --max-instances 1
```

### Docker — image آماده (هر VPS)

سریع‌ترین مسیر. image آماده pull کن و اجرا کن؛ نیاز به Rust toolchain روی VPS نیست.

```bash
# secret قوی بساز. ذخیره‌اش کن — همین مقدار رو بعداً تو CodeFull.gs paste می‌کنی.
SECRET=$(openssl rand -hex 24)
echo "TUNNEL_AUTH_KEY شما: $SECRET"

# Pull + run.
docker run -d \
  --name mhrv-tunnel \
  --restart unless-stopped \
  -p 8080:8080 \
  -e TUNNEL_AUTH_KEY="$SECRET" \
  ghcr.io/therealaleph/mhrv-tunnel-node:latest
```

تگ `:latest` آخرین release رو دنبال می‌کنه. برای production توصیه می‌شه روی version مشخص pin بزنی: `ghcr.io/therealaleph/mhrv-tunnel-node:v1.8.0` (یا هر نسخه‌ای که داری). image روی `linux/amd64` و `linux/arm64` موجوده.

**docker-compose.yml** اگه این رو ترجیح می‌دی:

```yaml
services:
  tunnel:
    image: ghcr.io/therealaleph/mhrv-tunnel-node:latest
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      TUNNEL_AUTH_KEY: ${TUNNEL_AUTH_KEY}
```

سپس `TUNNEL_AUTH_KEY=your-secret docker compose up -d`.

### Docker — build از source

اگه می‌خوای خودت image رو build کنی (یا custom تغییر بدی):

```bash
cd tunnel-node
docker build -t tunnel-node .
docker run -p 8080:8080 -e TUNNEL_AUTH_KEY=your-secret tunnel-node
```

### Binary مستقیم

```bash
cd tunnel-node
cargo build --release
TUNNEL_AUTH_KEY=your-secret PORT=8080 ./target/release/tunnel-node
```

## متغیرهای محیطی

| متغیر | الزامی | پیش‌فرض | توضیح |
|-------|--------|---------|-------|
| `TUNNEL_AUTH_KEY` | بله | `changeme` | secret مشترک — باید با `TUNNEL_AUTH_KEY` در CodeFull.gs match کنه |
| `PORT` | خیر | `8080` | پورت listen (Cloud Run خودش این رو ست می‌کنه) |
| `MHRV_DIAGNOSTIC` | خیر | (off) | اگه `1` باشه، روی auth بد به‌جای decoy 404 nginx، JSON `{"e":"unauthorized"}` صریح برمی‌گردونه. **فقط برای setup/debug** — قبل از public کردن tunnel-node خاموشش کن. (v1.8.0+) |

## پروتکل

### تک op: `POST /tunnel`

```json
{"k":"auth","op":"connect","host":"example.com","port":443}
{"k":"auth","op":"data","sid":"uuid","data":"base64"}
{"k":"auth","op":"close","sid":"uuid"}
```

### Batch: `POST /tunnel/batch`

```json
{
  "k": "auth",
  "ops": [
    {"op":"data","sid":"uuid1","d":"base64"},
    {"op":"udp_data","sid":"uuid2","d":"base64"},
    {"op":"close","sid":"uuid3"}
  ]
}
→ {"r": [{...}, {...}, {...}]}
```

### Health check: `GET /health` → `ok`

## Performance: تعداد deployment و عمق pipeline

کلاینت mhrv-rs در حالت Full یک batch-multiplexer pipelined اجرا می‌کنه. هر روند-تریپ Apps Script حدود ۲ ثانیه طول می‌کشه، پس کلاینت چندین request batch همزمان شلیک می‌کنه — عمق pipeline برابر تعداد deployment ID‌های Apps Script هست (حداقل ۲، بدون سقف بالا).

تعداد deployment بیشتر = batchهای همزمان بیشتر روی tunnel-node = latency پایین‌تر برای session. با ۶ deployment، هر ۰.۳ ثانیه یه batch جدید می‌رسه (به‌جای هر ۲ ثانیه).

خود tunnel-node per-request stateless هست (session‌ها بر اساس UUID key می‌شن)، پس batchهای همزمان رو طبیعی handle می‌کنه. برای بهترین نتیجه، ۳–۱۲ Apps Script روی account‌های Google جداگانه deploy کن و همهٔ deployment ID‌ها رو در config کلاینت لیست کن.

---

## سؤالات رایج

### حجم مصرف چقدره؟

سه لایه overhead هست در حالت Full:

1. **Base64 encoding** برای data ها در JSON envelope = ~۳۳٪ overhead روی payload (4 byte per 3 byte raw)
2. **JSON envelope + headers** = ~۵-۱۵٪ overhead بسته به اندازه payload
3. **Random padding (v1.8.0+)** برای DPI defense = متوسط ۵۱۲ بایت اضافه به هر batch

تخمین کلی: اگه ۱ GB دانلود می‌کنی، ~۱.۲۵-۱.۳ GB روی پهنای باند VPS مصرف می‌کنه.

برای ۲۰ GB ماهانه استفاده روزمره (browsing + Telegram + ویدیو متوسط)، ~۲۵-۲۷ GB پهنای باند VPS لازم داری. Hetzner CX11 (€۴/ماه) ۲۰ TB ماهانه می‌ده — یعنی به سقف نمی‌رسی مگه streaming سنگین.

### روی موبایل کل برنامه‌ها رو بالا میاره؟

**بستگی به Mode داره:**

- **mhrv-rs Android در Tunnel mode (Operating Mode → Tunnel)** + Full + tunnel-node = ✅ کل ترافیک Android (شامل YouTube، Telegram MTProto، Instagram، Snapchat، هر چیزی) capture می‌شه. این از VpnService استفاده می‌کنه.
- **mhrv-rs Android در Proxy mode** + Full + tunnel-node = فقط app‌هایی که proxy رو صریحاً respect می‌کنن (Chrome، Firefox، برخی app‌های Telegram-فارسی). YouTube/Insta/Telegram اصلی proxy رو نادیده می‌گیرن + از mhrv-rs رد نمی‌شن.

برای اینکه «همهٔ app‌ها بیان» = حتماً **Tunnel mode** فعال کن.

### سرعت چقدر خوبه؟

برای یک flow (یک download، یک ویدیو، یک TCP connection) معمولاً **۵۰–۲۰۰ KB/s** هست. علت:

- Apps Script روند-تریپ floor ~۲۰۰-۵۰۰ ms داره (غیر قابل پایین آوردن، Google-side limit)
- هر batch به یک deployment باند می‌شه + هر flow به یک batch
- در نتیجه per-flow throughput = batch_size / batch_round_trip = (~۶۴-۲۵۶ KB) / (~۲۵۰-۵۰۰ ms) ≈ ۱۲۸-۵۰۰ KB/s ceiling

برای **چند flow همزمان** (browsing با چند تب، Telegram + YouTube همزمان)، throughput جمعی به sum از همه flow‌ها مقیاس می‌خوره — با ۶ deployment روی ۶ Google account می‌تونی ۶ flow همزمان داشته باشی.

**توصیه واقع‌بینانه:** برای browsing عادی + chat + ویدیو متوسط = کافیه. برای دانلود فایل‌های بزرگ سریع، **Wireguard مستقیم روی همان VPS** ابزار درست‌تره (۵-۱۰x سریع‌تر، چون Apps Script رو دور می‌زنه). mhrv-rs ارزش اصلیش لایه «دور زدن censorship با domain-fronting» هست، نه سرعت raw — وقتی به اون لایه نیاز نداری (مسیر مستقیم به VPS باز هست)، ابزار ساده‌تر بهتره.

### آیا VPS لازمه؟

برای **حالت Full** (شامل Telegram، YouTube بدون 60s SABR cliff، WebSockets، MTProto و هر چیزی غیر-HTTPS-ساده): **بله، VPS الزامی هست**.

برای **حالت `apps_script`** (browsing فقط HTTPS): **خیر، نیاز به VPS نیست** — فقط نیاز به Apps Script setup روی Google account داری.

برای **حالت `direct`** (Google services مثل Search/Gmail/YouTube، به علاوهٔ هر `fronting_groups` که تنظیم کرده باشید): **نه VPS لازمه نه Apps Script** — فقط تونل بازنویسی `SNI`. (نام قبلی این حالت `google_only` بود.)

### چه VPS‌ای پیشنهاد می‌شه؟

- **Hetzner CX11** (Falkenstein/Helsinki، €۴/ماه) — best value، ۲۰ TB ماهانه، خوب برای کاربران اروپا/خاورمیانه
- **DigitalOcean basic droplet** ($۶/ماه، NYC/SFO) — برای کاربران آمریکا
- **Google Cloud Run** (free tier تا ۲ میلیون request/ماه + ۵ GB egress) — تنها provider که destination IP اصلاً Google هست، پس مسیر Iran→Apps Script→Cloud-Run-tunnel-node کاملاً درون شبکه Google می‌مونه و ISP filter نمی‌بینه. **بهترین گزینه برای کاربران ایرانی متأثر از [#313](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/313)**.

برای راهنمای قدم‌به‌قدم setup: [#310 reply (راهنمای فارسی)](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/310#issuecomment-4326086988).
