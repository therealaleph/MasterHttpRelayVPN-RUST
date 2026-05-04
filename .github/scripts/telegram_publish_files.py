#!/usr/bin/env python3
"""Post each release artifact individually to a Telegram channel.

Used by .github/workflows/telegram-publish-files.yml. Reads files from
--assets-dir, picks a Persian caption per filename, posts via the
Telegram Bot API `sendDocument` endpoint with --hashtag appended.

Files larger than the Telegram Bot API's 50 MB ceiling are split into
~45 MB byte chunks via Python (no `split` shell dep) and posted as
`<name>.part_aa`, `.part_ab`, ... — recipients reassemble with
`cat <name>.part_* > <name>`.

Re-runnable: posts every file every time. Use carefully when re-running
for the same version (the channel will get duplicate posts).
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import json
from pathlib import Path

# Telegram sendMessage caps at 4096 chars total. Leave headroom for
# the announcement header / cross-link footer / hashtag — anything
# above this gets truncated with a "see full notes on GitHub" tail.
TG_CHANGELOG_BUDGET = 3500

# Telegram Bot API uploads cap at 50 MB. Pick 45 MB for chunks so the
# multipart envelope + caption + Telegram's own overhead don't push us
# over. Bigger chunks (e.g. 49 MB) sometimes hit "Request Entity Too
# Large" depending on caption length.
CHUNK_LIMIT_BYTES = 45 * 1024 * 1024

# Sleep between uploads. Telegram's documented rate limit is 1 msg/sec
# to the same chat, plus a soft "burst" allowance. 1.5s is conservative
# and means a 20-file release publishes in ~30 s.
INTER_UPLOAD_SLEEP_SECS = 1.5

# Filename-substring → Persian caption. Order matters: longest /
# most-specific patterns first, since a shorter pattern (e.g.
# "android-x86") can match a more-specific filename ("android-x86_64").
# Match is `pattern in filename`.
CAPTIONS: list[tuple[str, str]] = [
    # Android — universal first (the recommended default for non-technical users).
    ("android-universal", "نسخه اندروید (universal) — برای همه دستگاه‌ها"),
    ("android-arm64-v8a", "نسخه اندروید (arm64-v8a) — گوشی‌های مدرن ۶۴ بیتی"),
    ("android-armeabi-v7a", "نسخه اندروید (armv7) — گوشی‌های قدیمی‌تر ۳۲ بیتی"),
    ("android-x86_64", "نسخه اندروید (x86_64) — شبیه‌ساز ۶۴ بیتی"),
    ("android-x86", "نسخه اندروید (x86) — شبیه‌ساز"),
    # Windows.
    ("windows-amd64", "نسخه ویندوز x64 (۶۴ بیتی)"),
    ("windows-i686", "نسخه ویندوز x86 (۳۲ بیتی، Win7+)"),
    # macOS — .app bundles before plain CLI tarballs.
    ("macos-arm64-app", "نسخه macOS (Apple Silicon) — برنامه گرافیکی .app"),
    ("macos-amd64-app", "نسخه macOS (Intel) — برنامه گرافیکی .app"),
    ("macos-arm64", "نسخه macOS (Apple Silicon) — CLI"),
    ("macos-amd64", "نسخه macOS (Intel) — CLI"),
    # Linux — musl static first, glibc second.
    ("linux-musl-amd64", "نسخه لینوکس amd64 (musl static) — Alpine / OpenWRT-x86"),
    ("linux-musl-arm64", "نسخه لینوکس arm64 (musl static)"),
    ("linux-amd64", "نسخه لینوکس amd64 (glibc)"),
    ("linux-arm64", "نسخه لینوکس arm64 (glibc)"),
    # Embedded targets.
    ("openwrt-mipsel-softfloat", "نسخه OpenWRT (mipsel softfloat) — روتر MT7621"),
    ("raspbian-armhf", "نسخه Raspbian (armhf) — رزبری پای ۳۲ بیتی"),
]


def caption_for(filename: str) -> str:
    """Return the Persian caption for a filename, falling back to the
    bare filename if nothing matches."""
    for pattern, persian in CAPTIONS:
        if pattern in filename:
            return persian
    return f"نسخه `{filename}`"


def order_files(files: list[Path]) -> list[Path]:
    """Sort release files in CAPTIONS order (Android first, then
    Windows, macOS, Linux, embedded). Files not matching any pattern
    fall to the end in alphabetical order."""
    order_map: dict[str, int] = {pattern: idx for idx, (pattern, _) in enumerate(CAPTIONS)}

    def key(p: Path) -> tuple[int, str]:
        for pattern, idx in order_map.items():
            if pattern in p.name:
                return (idx, p.name)
        # Unknown patterns: push to end, alphabetize among themselves.
        return (len(CAPTIONS), p.name)

    return sorted(files, key=key)


def split_file(path: Path, chunk_bytes: int) -> list[Path]:
    """Split `path` into chunks of at most `chunk_bytes` bytes. Returns
    the list of chunk paths, named `<orig>.part_aa`, `.part_ab`, ...
    Mimics `split -b <chunk_bytes>`. Reassembled via
    `cat <name>.part_* > <name>`.

    Skips work if existing parts are already present (idempotent re-run)."""
    parts: list[Path] = []

    def part_name(idx: int) -> str:
        # 26-letter base: aa..az, ba..bz, ... mirroring split's default.
        first = chr(ord("a") + idx // 26)
        second = chr(ord("a") + idx % 26)
        return f"{path.name}.part_{first}{second}"

    idx = 0
    with path.open("rb") as src:
        while True:
            buf = src.read(chunk_bytes)
            if not buf:
                break
            part_path = path.parent / part_name(idx)
            with part_path.open("wb") as dst:
                dst.write(buf)
            parts.append(part_path)
            idx += 1
    return parts


def send_document(
    bot_token: str,
    chat_id: str,
    file_path: Path,
    caption: str,
) -> dict:
    """POST a single file via the Telegram Bot API sendDocument endpoint.
    Returns the parsed JSON response. Raises on HTTP error.

    Uses urllib + a hand-rolled multipart/form-data encoder so we don't
    pull `requests` (the workflow runs on stock GitHub-hosted runners
    where stdlib-only is preferable for cold-start speed)."""
    url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
    boundary = "----mhrvUploadBoundary" + str(int(time.time() * 1000))
    body = build_multipart(
        boundary,
        fields={
            "chat_id": chat_id,
            "caption": caption,
            "parse_mode": "HTML",
            # Disable preview to keep the channel tidy.
            "disable_notification": "false",
        },
        files={"document": (file_path.name, file_path.read_bytes(), "application/octet-stream")},
    )
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    # 5 minute timeout for the actual upload — Telegram occasionally
    # takes a while to process 40+ MB documents.
    with urllib.request.urlopen(req, timeout=300) as resp:
        return json.loads(resp.read().decode("utf-8"))


def build_multipart(
    boundary: str,
    fields: dict[str, str],
    files: dict[str, tuple[str, bytes, str]],
) -> bytes:
    """Build a multipart/form-data body. `files` is name → (filename,
    bytes, mime). Plain stdlib so we don't need `requests`."""
    parts: list[bytes] = []
    crlf = b"\r\n"
    bnd = f"--{boundary}".encode()

    for name, value in fields.items():
        parts.append(bnd)
        parts.append(f'Content-Disposition: form-data; name="{name}"'.encode())
        parts.append(b"")
        parts.append(value.encode("utf-8"))

    for name, (filename, data, mime) in files.items():
        parts.append(bnd)
        parts.append(
            f'Content-Disposition: form-data; name="{name}"; filename="{filename}"'.encode()
        )
        parts.append(f"Content-Type: {mime}".encode())
        parts.append(b"")
        parts.append(data)

    parts.append(f"--{boundary}--".encode())
    parts.append(b"")
    return crlf.join(parts)


def html_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def load_changelog(repo_root: Path, version: str) -> tuple[str | None, str | None]:
    """Read `docs/changelog/v{version}.md` and split into (Persian, English).

    The repo convention (see `docs/changelog/v1.1.0.md`) is:
        <!-- comment line -->
        Persian content...
        ---
        English content...

    Returns (None, None) if the file doesn't exist (lets callers fall back
    to the bare "release dropped" announcement gracefully). Returns
    (persian, None) if there's no `---` separator (single-language file).
    """
    path = repo_root / "docs" / "changelog" / f"v{version}.md"
    if not path.is_file():
        return None, None
    text = path.read_text(encoding="utf-8")
    # Strip leading HTML comments (the standard `<!-- see docs/... -->`
    # header). Their content is for editors, not readers.
    text = re.sub(r"^\s*<!--.*?-->\s*", "", text, count=1, flags=re.DOTALL)
    # Split on the literal `---` line that separates Persian from English.
    # We require it to be on its own line so an inline `---` inside a code
    # block doesn't accidentally split the body.
    parts = re.split(r"\n\s*---\s*\n", text, maxsplit=1)
    persian = parts[0].strip() or None
    english = parts[1].strip() if len(parts) > 1 else None
    if english:
        english = english.strip() or None
    return persian, english


def brief_changelog(text: str, max_total: int = 1500) -> str:
    """Compress a changelog body to top-level bullets only, with each bullet
    trimmed to a short readable headline.

    Sub-bullets, prose explanations, contributor @-mentions, and embedded
    "by @user with full root cause + fix" prefatory phrases are stripped.
    Markdown link `[text](url)` becomes plain `text`, with the special case
    of `[#nnn](url)` → `#nnn` (issue/PR number stays readable without the
    visual clutter of the URL). The result still goes through
    `md_to_tg_html` for backtick → <code> conversion.

    Why bullets-only: Telegram channel readers want "what shipped" in a
    glance, not the architectural detail that lives in the git log + the
    full `docs/changelog/v*.md` file. The full English text is still in
    the repo for archival.

    `max_total` caps the assembled brief so the announcement stays well
    under Telegram's 4096-char sendMessage budget after header / footer
    chrome is added.
    """
    out: list[str] = []
    total_len = 0

    for raw in text.splitlines():
        if not raw.startswith("• "):
            continue
        body = raw[2:].strip()

        # Strip "by @user with full root cause + fix" / "from @user" /
        # "by @user". The "with ..." clause after "by @user" runs to the
        # next closing paren — greedy `[^)]*` is what consumes it
        # cleanly. Without the greedy form, the trailing "with full
        # root cause + fix" remained in the headline.
        body = re.sub(r" by @[\w-]+(?: with [^)]*)?", "", body)
        body = re.sub(r" from @[\w-]+", "", body)

        # `(PR [#nnn](url))` → `(#nnn)` and bare `[#nnn](url)` → `#nnn`.
        # Done before generic `[text](url)` so the issue-number form
        # wins over the catch-all (which would expand the link text).
        body = re.sub(r"PR \[#(\d+)\]\([^)]+\)", r"#\1", body)
        body = re.sub(r"\[#(\d+)\]\([^)]+\)", r"#\1", body)
        body = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", body)

        # Cut at the first natural sentence boundary that isn't too
        # early. ":" anchored to position ≥ 30 catches "Title: details"
        # without truncating short headers like "Tests:" / "API:" /
        # "Build:" that are themselves the headline. ". " catches the
        # rest. " — " (em-dash with spaces) is our explicit "headline
        # — body" form in the changelogs.
        candidates = []
        for sep, min_pos in ((":", 30), (". ", 5), (" — ", 5)):
            idx = body.find(sep)
            if idx >= min_pos and idx < 200:
                candidates.append(idx)
        if candidates:
            body = body[: min(candidates)].rstrip()

        # Hard cap at 200 chars so a single sentence-less bullet
        # (e.g. comma-separated list) can't dominate the brief.
        if len(body) > 200:
            body = body[:197].rstrip() + "…"

        # If our truncation left an unclosed `(`, strip from there. A
        # dangling `(` reads as a typo in the channel post; better to
        # drop the parenthesised aside than to show a half-open one.
        # Same for `[`. Counts compare: if open > close, find the last
        # offending char and trim back to the previous space.
        for open_ch, close_ch in (("(", ")"), ("[", "]")):
            if body.count(open_ch) > body.count(close_ch):
                last = body.rfind(open_ch)
                if last > 0:
                    body = body[:last].rstrip()

        line = f"• {body}"
        # +1 for the line separator we'll insert when joining.
        if total_len + len(line) + 1 > max_total:
            break
        out.append(line)
        total_len += len(line) + 1

    return "\n".join(out)


def md_to_tg_html(md: str, max_len: int = TG_CHANGELOG_BUDGET) -> str:
    """Convert a subset of Markdown to Telegram-flavoured HTML.

    Handles only the patterns that show up in our changelog files:
      - `**bold**`            → `<b>bold</b>`
      - `[text](url)`         → `<a href="url">text</a>`
      - `` `code` ``          → `<code>code</code>`
      - `<!-- comment -->`    → stripped
      - everything else       → HTML-escaped, line breaks preserved

    The order of operations matters because the input is going through
    HTML escape: we first carve out the markdown spans into placeholders
    that escape() can't touch, then escape the rest, then put the spans
    back as Telegram HTML. This is the same trick the Python `markdown`
    package uses for inline tokens — much simpler than a real parser
    when the input grammar is tiny.

    The result is also truncated at `max_len` chars (Telegram's 4096-char
    sendMessage limit minus header/footer headroom). Truncation snaps to
    the previous newline so we never cut a markdown span in half.
    """
    # 1. Strip HTML comments, including multi-line.
    md = re.sub(r"<!--.*?-->", "", md, flags=re.DOTALL).strip()

    # 2. Carve out the markdown spans into placeholder tokens. We pick a
    #    NUL-delimited form because NUL is illegal in markdown source and
    #    in Telegram messages — safe placeholder.
    spans: list[str] = []

    def stash(html: str) -> str:
        spans.append(html)
        return f"\x00{len(spans) - 1}\x00"

    # Inline code first — backticks are exclusive of the other patterns.
    md = re.sub(
        r"`([^`\n]+)`",
        lambda m: stash(f"<code>{html_escape(m.group(1))}</code>"),
        md,
    )
    # Markdown links `[text](url)` — link text gets HTML-escaped, URL is
    # passed through but quotes inside it would break the attribute, so
    # we escape `"` only there.
    md = re.sub(
        r"\[([^\]]+)\]\(([^)]+)\)",
        lambda m: stash(
            f'<a href="{m.group(2).replace(chr(34), "&quot;")}">'
            f"{html_escape(m.group(1))}</a>"
        ),
        md,
    )
    # Bold `**text**`. Done after links so a `**[text](url)**` pattern
    # still works (the link is already a placeholder by now).
    md = re.sub(
        r"\*\*([^*\n]+)\*\*",
        lambda m: stash(f"<b>{html_escape(m.group(1))}</b>"),
        md,
    )

    # 3. HTML-escape everything that wasn't a span. Placeholders survive
    #    because they contain only NUL and digits, which the escape pass
    #    leaves alone.
    md = html_escape(md)

    # 4. Restore the placeholders. We loop because a placeholder's
    #    expansion can itself contain placeholders — e.g. a markdown
    #    link `[`code`](url)` stashes the inline code first, then the
    #    link captures the code's `\x00N\x00` token as its link text.
    #    A single pass would leave that inner token un-restored. Bound
    #    the loop to len(spans)+1 so a malformed input can't run away.
    for _ in range(len(spans) + 1):
        new = re.sub(
            r"\x00(\d+)\x00",
            lambda m: spans[int(m.group(1))],
            md,
        )
        if new == md:
            break
        md = new

    # 5. Truncate to fit Telegram's sendMessage cap. Snap to a newline
    #    boundary so a code/link span isn't cut in half. The trailing
    #    "..." line tells the reader to go to GitHub for the full notes.
    if len(md) > max_len:
        cut = md.rfind("\n", 0, max_len)
        if cut < max_len // 2:
            cut = max_len  # very long single line — chop hard
        md = md[:cut].rstrip() + "\n…\n<i>(see full notes on GitHub)</i>"
    return md


def repo_root_from_script() -> Path:
    """Find the repo root from this script's location: `<root>/.github/
    scripts/telegram_publish_files.py` → `<root>`. Used by `load_changelog`
    so callers don't have to pass it in (and so the script Just Works
    when run from `cwd != repo root`)."""
    return Path(__file__).resolve().parent.parent.parent


def sha256_hex(path: Path) -> str:
    """Stream-hash the file in 1 MiB chunks. Avoids loading 40+ MB APKs
    into RAM twice (once for hashing, once for upload)."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def post_file(
    bot_token: str,
    chat_id: str,
    file_path: Path,
    base_caption: str,
    hashtag: str,
) -> bool:
    """Post one file. If too big, split + post each part. Returns True
    on success of all parts, False on any failure.

    Each caption ends with the file's SHA-256 in hex under a Persian
    "تایید اصالت" (authenticity verification) label, so recipients can
    `sha256sum <file>` after download and confirm it matches what the
    channel posted — defends against modified copies if the channel is
    ever compromised or relayed through a third party."""
    size = file_path.stat().st_size

    # Compute the original-file hash regardless of whether we'll chunk
    # it. For chunked uploads, every part's caption shows this hash so
    # the user can verify the full file once reassembled with `cat`.
    print(f"  hashing {file_path.name}...", flush=True)
    full_sha = sha256_hex(file_path)

    if size <= CHUNK_LIMIT_BYTES:
        caption = (
            f"<b>{html_escape(base_caption)}</b>\n"
            f"<code>{html_escape(file_path.name)}</code>\n"
            f"\nتایید اصالت (SHA-256):\n"
            f"<code>{full_sha}</code>\n"
            f"\n{hashtag}"
        )
        print(f"  uploading {file_path.name} ({size / 1_048_576:.1f} MB)...", flush=True)
        try:
            resp = send_document(bot_token, chat_id, file_path, caption)
            if not resp.get("ok"):
                print(f"    !! Telegram returned not-ok: {resp}", flush=True)
                return False
            print(f"    ok (message_id={resp['result']['message_id']})", flush=True)
            return True
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")[:500]
            print(f"    !! HTTP {e.code}: {err_body}", flush=True)
            return False
        except Exception as e:
            print(f"    !! exception: {e}", flush=True)
            return False
        finally:
            time.sleep(INTER_UPLOAD_SLEEP_SECS)

    # Too big — split and post each part.
    print(
        f"  splitting {file_path.name} ({size / 1_048_576:.1f} MB > "
        f"{CHUNK_LIMIT_BYTES / 1_048_576:.0f} MB ceiling)...",
        flush=True,
    )
    parts = split_file(file_path, CHUNK_LIMIT_BYTES)
    if not parts:
        print(f"    !! split produced 0 parts (empty file?)", flush=True)
        return False

    n = len(parts)
    all_ok = True
    for idx, part_path in enumerate(parts, start=1):
        # Hash the individual part too — lets the user verify each
        # downloaded chunk before bothering to reassemble.
        part_sha = sha256_hex(part_path)
        part_caption = (
            f"<b>{html_escape(base_caption)} — قسمت {idx}/{n}</b>\n"
            f"<code>{html_escape(part_path.name)}</code>\n"
            f"\nبرای بازسازی فایل اصلی:\n"
            f"<code>cat {html_escape(file_path.name)}.part_* &gt; "
            f"{html_escape(file_path.name)}</code>\n"
            f"\nتایید اصالت این قسمت (SHA-256):\n"
            f"<code>{part_sha}</code>\n"
            f"\nتایید اصالت فایل کامل پس از بازسازی (SHA-256):\n"
            f"<code>{full_sha}</code>\n"
            f"\n{hashtag}"
        )
        psize = part_path.stat().st_size
        print(
            f"    uploading part {idx}/{n}: {part_path.name} ({psize / 1_048_576:.1f} MB)...",
            flush=True,
        )
        try:
            resp = send_document(bot_token, chat_id, part_path, part_caption)
            if not resp.get("ok"):
                print(f"      !! Telegram returned not-ok: {resp}", flush=True)
                all_ok = False
            else:
                print(
                    f"      ok (message_id={resp['result']['message_id']})", flush=True
                )
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")[:500]
            print(f"      !! HTTP {e.code}: {err_body}", flush=True)
            all_ok = False
        except Exception as e:
            print(f"      !! exception: {e}", flush=True)
            all_ok = False
        finally:
            time.sleep(INTER_UPLOAD_SLEEP_SECS)
            # Tidy up the part file once posted.
            try:
                part_path.unlink()
            except OSError:
                pass

    return all_ok


def files_channel_post_link(chat_id: str, message_id: int) -> str:
    """Build a `t.me` link to a specific message in the files channel.

    For private supergroups/channels (negative ID with `-100` prefix),
    Telegram exposes posts at `https://t.me/c/<id>/<msg>` where `<id>`
    is the chat ID with the `-100` stripped. This link works for users
    who are members of the channel.

    If `FILES_CHANNEL_USERNAME` is set in env (e.g. `mhrv_files`), uses
    the public-channel form `https://t.me/<username>/<msg>` instead,
    which is clickable for everyone."""
    username = os.environ.get("FILES_CHANNEL_USERNAME", "").strip().lstrip("@")
    if username:
        return f"https://t.me/{username}/{message_id}"
    cid = chat_id
    if cid.startswith("-100"):
        cid = cid[4:]
    elif cid.startswith("-"):
        cid = cid[1:]
    return f"https://t.me/c/{cid}/{message_id}"


def post_main_channel_pointer(
    bot_token: str,
    main_chat_id: str,
    files_channel_post_link: str,
    version: str,
    hashtag: str,
    channel_username_link: str = "",
    channel_invite_link: str = "",
    english_notes_brief: str | None = None,
) -> bool:
    """Post a short cross-link to the main announcement channel pointing
    at the anchor post in the files channel. Replaces the previous
    behaviour of posting the universal APK + full changelog directly
    to the main channel — the main channel becomes a discovery surface
    while the files channel hosts the actual artifacts.

    When `english_notes_brief` is supplied (the brief-extracted English
    half of `docs/changelog/v{version}.md` via `brief_changelog`), it's
    rendered between the title and the files-channel link so subscribers
    see what's new without clicking through. Falls back to the bare
    pointer if notes aren't available.

    English brief (not Persian full) is what we ship to TG: the audience
    is the worldwide channel, and short brief-tone bullets read cleanly
    in a chat client where Persian RTL prose mixed with `<code>` /
    `<b>` spans rendered awkwardly. The full Persian + full English
    changelog stays in `docs/changelog/v*.md` for archival.

    Includes channel-join links (public username + invite hash) at the
    bottom so recipients who aren't yet members can subscribe before
    clicking through to the specific release post.
    """
    parts = [
        f"<b>📦 mhrv-rs v{html_escape(version)} released</b>",
        "",
    ]
    if english_notes_brief:
        # Tighter budget than the files-channel announcement since the
        # cross-link has extra footer chrome (channel-join links).
        parts.append(md_to_tg_html(english_notes_brief, max_len=TG_CHANGELOG_BUDGET - 400))
        parts.append("")
    parts.extend([
        f"Files (Android APKs, Windows, macOS, Linux, OpenWRT) on the files channel:",
        "",
        f"👉 <a href=\"{html_escape(files_channel_post_link)}\">"
        f"v{html_escape(version)} — all files with SHA-256</a>",
    ])
    # Channel-join links. Two forms handle different states of the
    # files channel: the `t.me/<username>` form works for public
    # channels and is the prettier link; the `t.me/+<hash>` invite
    # link works regardless of whether the channel is public, and is
    # the only path in for private/restricted channels. Showing both
    # is forgiving — recipients click whichever works for them.
    if channel_username_link or channel_invite_link:
        parts.append("")
        parts.append("Channel:")
        if channel_username_link:
            # Render as plain URL (not HTML <a>) so the text shows the
            # link itself — useful when users share the message via
            # screenshot or copy-paste outside Telegram, which would
            # strip the <a href> wrapper.
            parts.append(html_escape(channel_username_link))
        if channel_invite_link:
            parts.append(f"or: {html_escape(channel_invite_link)}")
    parts.append("")
    parts.append(hashtag)
    text = "\n".join(parts)
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    data = urllib.parse.urlencode({
        "chat_id": main_chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": "false",
    }).encode()
    print(f"  posting cross-link to main channel {main_chat_id}...", flush=True)
    try:
        with urllib.request.urlopen(
            urllib.request.Request(url, data=data, method="POST"), timeout=30
        ) as resp:
            r = json.loads(resp.read().decode("utf-8"))
            if not r.get("ok"):
                print(f"    !! main-channel post failed: {r}", flush=True)
                return False
            print(
                f"    ok (message_id={r['result']['message_id']})", flush=True
            )
            return True
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")[:500]
        print(f"    !! HTTP {e.code}: {err_body}", flush=True)
        return False
    except Exception as e:
        print(f"    !! exception: {e}", flush=True)
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets-dir", required=True, type=Path)
    parser.add_argument("--version", required=True, help="e.g. 1.8.0")
    parser.add_argument("--hashtag", required=True, help="e.g. #v180")
    args = parser.parse_args()

    bot_token = os.environ.get("BOT_TOKEN")
    chat_id = os.environ.get("CHAT_ID")
    if not bot_token or not chat_id:
        print("BOT_TOKEN and CHAT_ID env vars required", file=sys.stderr)
        return 2

    if not args.assets_dir.is_dir():
        print(f"--assets-dir {args.assets_dir} not a directory", file=sys.stderr)
        return 2

    # Collect all regular files in the directory (no recursion). Skip
    # split-part leftovers from a previous run of this script if any
    # exist — we'll regenerate cleanly.
    raw_files = [
        p for p in args.assets_dir.iterdir()
        if p.is_file() and ".part_" not in p.name
    ]
    if not raw_files:
        print(f"no files found in {args.assets_dir}", file=sys.stderr)
        return 2

    files = order_files(raw_files)
    print(f"publishing {len(files)} file(s) to Telegram chat {chat_id} for v{args.version}:")
    for f in files:
        print(f"  - {f.name}")
    print()

    # Leading announcement in the files channel. Captured `message_id`
    # is the anchor that the main-channel cross-link points at — the
    # main channel doesn't carry files anymore, just a single message
    # saying "new release, click here." Recipients land on this anchor
    # and scroll down to see all the platform-specific files.
    #
    # We pull the English half of `docs/changelog/v{version}.md`, run it
    # through `brief_changelog` to keep just the top-level bullets (no
    # sub-bullets, no contributor mentions, no embedded prose), and
    # inject that into the announcement. Brief English (not full Persian)
    # is the right tone for a Telegram channel post: subscribers want
    # "what shipped" in one glance; the full archival changelog stays in
    # the repo. Falls back to the bare skeleton if the changelog file
    # doesn't exist (e.g. an out-of-band re-publish for an old tag).
    _persian_notes, english_notes = load_changelog(repo_root_from_script(), args.version)
    english_brief = brief_changelog(english_notes) if english_notes else None
    announce_lines = [
        f"<b>📦 mhrv-rs {html_escape('v' + args.version)} released</b>",
        "",
    ]
    if english_brief:
        announce_lines.append(md_to_tg_html(english_brief))
        announce_lines.append("")
    announce_lines.extend([
        "Per-platform files follow with SHA-256 captions for verification.",
        "",
        args.hashtag,
    ])
    announce = "\n".join(announce_lines)
    announce_msg_id: int | None = None
    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = urllib.parse.urlencode({
            "chat_id": chat_id,
            "text": announce,
            "parse_mode": "HTML",
            "disable_web_page_preview": "true",
        }).encode()
        with urllib.request.urlopen(
            urllib.request.Request(url, data=data, method="POST"), timeout=30
        ) as resp:
            r = json.loads(resp.read().decode("utf-8"))
            if not r.get("ok"):
                print(f"  !! announcement failed: {r}", flush=True)
            else:
                announce_msg_id = r["result"]["message_id"]
                print(
                    f"  announcement posted (message_id={announce_msg_id})",
                    flush=True,
                )
    except Exception as e:
        # Non-fatal for the file uploads, but cross-link to the main
        # channel below will be skipped — without the anchor message_id
        # there's nothing to point at.
        print(f"  !! announcement exception: {e}", flush=True)
    time.sleep(INTER_UPLOAD_SLEEP_SECS)

    failures = 0
    for f in files:
        base = caption_for(f.name)
        ok = post_file(bot_token, chat_id, f, base, args.hashtag)
        if not ok:
            failures += 1

    # Cross-link to the main announcement channel. Skipped if MAIN_CHAT_ID
    # is unset (development / private testing) or if the files-channel
    # announcement didn't post (no anchor to link to).
    main_chat_id = os.environ.get("MAIN_CHAT_ID", "").strip()
    if main_chat_id and announce_msg_id is not None:
        link = files_channel_post_link(chat_id, announce_msg_id)
        # Optional channel-join links rendered alongside the cross-link.
        # `FILES_CHANNEL_USERNAME` is the public-username form (clean
        # `t.me/<name>` URL — clickable for everyone). `FILES_CHANNEL_INVITE`
        # is the `t.me/+<hash>` invite link, the only join path for
        # private channels. Either or both can be set; both render in
        # the body as separate lines.
        username = os.environ.get("FILES_CHANNEL_USERNAME", "").strip().lstrip("@")
        username_link = f"https://t.me/{username}" if username else ""
        invite_link = os.environ.get("FILES_CHANNEL_INVITE", "").strip()
        print()
        print(f"posting cross-link to main channel:")
        print(f"  post link: {link}")
        if username_link:
            print(f"  channel username link: {username_link}")
        if invite_link:
            print(f"  channel invite link:   {invite_link}")
        ok = post_main_channel_pointer(
            bot_token,
            main_chat_id,
            link,
            args.version,
            args.hashtag,
            channel_username_link=username_link,
            channel_invite_link=invite_link,
            english_notes_brief=english_brief,
        )
        if not ok:
            failures += 1
    elif main_chat_id and announce_msg_id is None:
        print()
        print(
            "  !! MAIN_CHAT_ID is set but announcement message_id is None — "
            "skipping cross-link (no anchor to point at).",
            flush=True,
        )
        failures += 1
    else:
        print()
        print("  MAIN_CHAT_ID not set, skipping cross-link", flush=True)

    print()
    if failures:
        print(f"DONE with {failures} failure(s) out of {len(files)}", flush=True)
        return 1
    print(f"DONE — {len(files)} files posted successfully", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
