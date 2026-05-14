<div dir="rtl">

# استفاده از mhrv-rs به‌عنوان پروکسی upstream (سایفون، xray، مرورگرها)

نسخهٔ انگلیسی: [docs/use-as-upstream.md](use-as-upstream.md).

به‌طور پیش‌فرض، mhrv-rs یک پروکسی HTTP محلی روی `127.0.0.1:8085` و یک پروکسی SOCKS5 روی `127.0.0.1:8086` در دسترس قرار می‌دهد (پیش‌فرض اندروید: HTTP `8080` و SOCKS5 `1081`). هر ابزاری که تنظیم upstream proxy داشته باشد می‌تواند از این پروکسی عبور کند.

حالت رایج: سرورهای bootstrap سایفون مسدودند، پس upstream proxy سایفون را روی mhrv-rs می‌گذاری تا اولین hop سایفون از طریق تونل SNI-fronting ما به شبکه‌اش برسد.

## از حالت `direct` استفاده کن

حالت‌های `apps_script` و `full` تلاش می‌کنند هر هاست را از رلهٔ Apps Script عبور دهند، که با پروتکل باینری سایفون سازگار نیست. حالت `direct` رله را کنار می‌گذارد: SNI-rewrite برای هاست‌هایی که mhrv-rs می‌شناسد، TCP خام برای بقیه. این دقیقاً همان چیزی است که سایفون نیاز دارد — رمزنگاری end-to-end خودش دست‌نخورده می‌ماند و cert pinning نمی‌شکند.

در رابط دسکتاپ / برنامهٔ اندروید گزینهٔ **Direct (no relay)** را انتخاب کن، یا در کانفیگ بگذار:

<div dir="ltr">

```jsonc
{
  "mode": "direct",
  "listen_host": "127.0.0.1",
  "listen_port": 8085,
  "socks5_port": 8086
}
```

</div>

## سایفون — ویندوز / مک / لینوکس

۱. برنامهٔ mhrv-rs را در حالت `direct` اجرا کن. host:port زیر دکمهٔ Start نمایش داده می‌شود — روی **copy** بزن.

۲. در سایفون این مسیر را باز کن: **Options** → **Proxy settings** → **Upstream proxy**.

۳. تیک **Connect through an upstream proxy** را بزن.

۴. در فیلد **Hostname** مقدار `127.0.0.1`، در **Port** مقدار `8085` و در **Type** گزینهٔ `HTTP` را انتخاب کن. (یا SOCKS5 روی پورت `8086`.)

۵. روی **Save** بزن، بعد در سایفون **Connect** را بزن.

## سایفون — اندروید

اندروید همزمان فقط یک VPN فعال اجازه می‌دهد و سایفون به این اسلات نیاز دارد. قبل از شروع: برنامهٔ mhrv-rs را باز کن و در بخش Network مقدار **Connection mode** را روی **PROXY_ONLY** بگذار. در این حالت mhrv-rs فقط پروکسی محلی را اجرا می‌کند و اسلات VPN را برای سایفون آزاد می‌گذارد.

۱. در mhrv-rs ابتدا Connection mode را روی `PROXY_ONLY` بگذار، سپس حالت `Direct` را انتخاب کن و **Connect** را بزن. host:port زیر دکمهٔ Connect نمایش داده می‌شود — روی **copy** بزن.

۲. در برنامهٔ سایفون این مسیر را باز کن: **Options** → **Proxy** → **Upstream proxy**.

۳. در فیلد **Host** مقدار `127.0.0.1` و در **Port** مقدار `8080` (برای HTTP) یا `1081` (برای SOCKS5) را وارد کن.

۴. در سایفون **Connect** را بزن.

## تنظیم xray / v2ray

یک outbound از نوع `http` (یا `socks`) اضافه کن که به mhrv-rs اشاره کند:

<div dir="ltr">

```jsonc
{
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "http",
      "settings": {
        "servers": [
          { "address": "127.0.0.1", "port": 8085 }
        ]
      }
    }
  ]
}
```

</div>

## مرورگرها / SwitchyOmega

پروکسی را روی `127.0.0.1:8085` تنظیم کن. چیز دیگری لازم نیست.

## رفع اشکال

- **سایفون روی «در حال اتصال…» می‌ماند** — مطمئن شو mhrv-rs در حالت `direct` است و پورت با چیزی که در سایفون وارد کردی یکی است. در پنل log اخیر رابط mhrv-rs هر CONNECT را که می‌بیند نمایش می‌دهد؛ باید هاست‌های سایفون را آنجا با برچسب `raw-tcp (direct mode: no relay)` ببینی.

- **یک هاست خاص MITM می‌شود در حالی که نمی‌خواهی** — آن را به `passthrough_hosts` در `config.json` اضافه کن. این لیست بر همهٔ تصمیم‌های دیگر dispatch اولویت دارد.

- **برعکس زنجیر کن (outbound از mhrv-rs از طریق سایفون یا xray)** — در `config.json` فیلد `upstream_socks5` را روی پورت SOCKS5 محلی آن ابزار تنظیم کن. flowهای raw-TCP / passthrough از آنجا خارج می‌شوند. ترافیک رلهٔ Apps Script طبق طراحی همچنان از edge گوگل می‌گذرد.

## همچنین ببین

- راهنمای [fronting-groups.md](fronting-groups.md) — افزودن CDNهای غیرگوگلی (Vercel، Fastly، Netlify) به مسیر SNI-rewrite.
- مرجع کامل [حالت direct در راهنمای کامل](guide.fa.md#حالت-direct).

</div>
