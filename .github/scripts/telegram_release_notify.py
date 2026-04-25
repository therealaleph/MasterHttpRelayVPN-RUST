#!/usr/bin/env python3
"""
Post a CI-built Android APK to the project Telegram channel on each
release tag, followed by a reply-threaded changelog message with
Persian + English bullets in <blockquote> blocks.

Called from the `telegram:` job in `.github/workflows/release.yml`.
Environment:
    BOT_TOKEN   Telegram bot token (repo secret TELEGRAM_BOT_TOKEN)
    CHAT_ID     Numeric chat id, e.g. -1002282061190 (repo secret
                TELEGRAM_CHAT_ID)
Arguments:
    --apk        path to the APK file to upload
    --version    bare version string, e.g. "1.1.0"
    --repo       "owner/repo"
    --changelog  path to docs/changelog/vX.Y.Z.md; split on a line
                 that is exactly "---" — anything before is Persian,
                 anything after is English. Missing file = only the
                 APK is posted (no reply).

Why Python over curl: curl's `-F name=value` multipart spec treats
`<file` as "read from file" and `@file` as "upload file". Our HTML
captions contain literal `<b>` tags, which triggers the file-read
path and exits 26 "Failed to open/read local data". urllib has no
such behavior.

Telegram quirks we deliberately handle:
  - Captions max out at 1024 chars, so the APK caption is short
    (title + sha256 + repo + release URL) and the real changelog
    goes in a reply-threaded message (sendMessage has no practical
    length limit).
  - sendDocument content-type defaults to application/octet-stream
    for unknown extensions — we pass .apk with
    application/vnd.android.package-archive so channel previews
    label it as an Android package, not a generic file.
"""
import argparse
import hashlib
import http.client
import json
import os
import re
import ssl
import sys
import uuid
from pathlib import Path


def parse_changelog(path: str) -> tuple[str, str]:
    """Return (persian_body, english_body). Blank strings if file missing."""
    p = Path(path)
    if not p.is_file():
        return "", ""
    body = p.read_text(encoding="utf-8")
    # Strip a leading HTML comment block if present — the changelog
    # template uses <!-- ... --> to document the format for editors;
    # we don't want that echoed to Telegram.
    body = re.sub(r"^\s*<!--.*?-->\s*", "", body, count=1, flags=re.S)
    fa, sep, en = body.partition("\n---\n")
    if not sep:
        # No separator — treat everything as Persian (content-language
        # is a project preference rather than a hard rule).
        return body.strip(), ""
    return fa.strip(), en.strip()


# Telegram caption hard-cap is 1024 chars. The fixed parts of our caption
# (title + SHA hash + two-link footer with their preambles) sum to roughly
# 470 chars on a typical version string. That leaves ~550 chars for the
# release-note section before we'd start losing the trailing release URL.
# Keep the budget conservative so a long version string or a slightly
# longer hash representation doesn't push us over.
CAPTION_FA_NOTE_BUDGET = 500


def _md_links_to_html(text: str) -> str:
    """Convert `[label](url)` markdown links to `<a href="url">label</a>`.

    Telegram's HTML parse mode renders `<a>` as clickable but treats
    markdown verbatim, so an unconverted `[#160](https://…)` appears as
    that literal string in the channel post — both ugly and wasteful of
    caption budget. The HTML form is shorter visually (`#160` vs the
    full URL), still clickable, and counts the same toward Telegram's
    1024-char limit. Inline `code` (`backtick-quoted`) is also
    translated to `<code>…</code>` since markdown backticks render
    literally too.
    """
    text = re.sub(
        r"\[([^\]]+)\]\(([^)]+)\)",
        lambda m: f'<a href="{m.group(2)}">{m.group(1)}</a>',
        text,
    )
    text = re.sub(r"`([^`\n]+)`", r"<code>\1</code>", text)
    # Bold (**…**) is rare in our changelog but happens — convert to <b>.
    text = re.sub(r"\*\*([^*\n]+)\*\*", r"<b>\1</b>", text)
    return text


def _extract_headlines(fa_section: str) -> str:
    """For each `• …: …` bullet, keep the headline part and drop the
    elaboration.

    Our changelog convention writes each bullet as one of:
      • headline: full explanation
      • headline ([#NN](url)): full explanation
      • headline (issue ref): full explanation

    The headline is everything up to the `: ` (colon + space) that ends
    the leading clause. Naively searching for the first `:` lands inside
    `https:` URLs of the markdown link form — instead we search from the
    end of the parenthesized-issue-ref (if any) for the first `: `, or
    fall back to the first `: ` in the line.

    Headlines stay on the FA caption; the explanation is preserved in
    the docs/changelog/ file and (optionally) the reply-threaded message
    posted via --with-changelog.

    Returns a newline-joined string of `• <headline>` lines.
    """
    headlines: list[str] = []
    for line in fa_section.splitlines():
        if not line.startswith("• "):
            continue
        body = line[2:]  # drop "• "
        # Prefer cutting at "): " — the close of the parenthesized ref
        # followed by the convention colon + space. That's our actual
        # bullet structure and avoids the false-positive `https:` cut.
        cut_idx = body.find("): ")
        if cut_idx > 0:
            headline = body[: cut_idx + 1]  # keep the close paren
        else:
            # Fall back to ": " (colon + space) anywhere in the body.
            # Adding the space requirement skips `https:` which is
            # always followed by `/`.
            cut_idx = body.find(": ")
            headline = body[:cut_idx] if cut_idx > 0 else body
        headlines.append(f"• {headline.rstrip()}")
    return "\n".join(headlines)


def build_caption_release_note(changelog_path: str) -> str:
    """Build the Persian "what's new" block for the Telegram caption.

    Pulls the FA section of `docs/changelog/v<ver>.md`, extracts just
    the bullet headlines (before the first `:` of each bullet) so the
    note is compact, converts markdown links/code to Telegram HTML for
    clickability, and wraps in a `<blockquote>`. Falls back to the full
    FA section if the headlines extraction yields nothing (e.g. a
    changelog that doesn't follow our `• headline: details` convention).

    If the result still exceeds CAPTION_FA_NOTE_BUDGET, truncate at a
    bullet boundary with a trailing `…`. In practice the headlines-only
    form fits comfortably for any reasonable release note.
    """
    fa, _en = parse_changelog(changelog_path)
    if not fa:
        return ""
    headlines = _extract_headlines(fa)
    note = headlines if headlines else fa.strip()
    note = _md_links_to_html(note)
    if len(note) > CAPTION_FA_NOTE_BUDGET:
        truncated = note[:CAPTION_FA_NOTE_BUDGET]
        last_bullet = truncated.rfind("\n•")
        if last_bullet > 0:
            note = truncated[:last_bullet].rstrip() + "\n…"
        else:
            note = truncated.rstrip() + "…"
    return f"<blockquote>{note}</blockquote>"


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def tg_request(method: str, token: str, *, body: bytes, content_type: str) -> dict:
    """POST `body` to https://api.telegram.org/bot<token>/<method>."""
    conn = http.client.HTTPSConnection(
        "api.telegram.org", context=ssl.create_default_context()
    )
    conn.request(
        "POST",
        f"/bot{token}/{method}",
        body=body,
        headers={"Content-Type": content_type, "Content-Length": str(len(body))},
    )
    resp = conn.getresponse()
    raw = resp.read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        raise SystemExit(f"Telegram {method}: non-JSON response ({resp.status}): {raw!r}")
    if not data.get("ok"):
        raise SystemExit(f"Telegram {method} failed: {data}")
    return data["result"]


def send_document(token: str, chat_id: str, apk_path: str, caption: str) -> int:
    """Upload the APK file with a short HTML caption. Returns message_id."""
    boundary = "----" + uuid.uuid4().hex
    with open(apk_path, "rb") as f:
        file_bytes = f.read()

    def text_field(name: str, value: str) -> bytes:
        return (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
            f"{value}\r\n"
        ).encode("utf-8")

    def file_field(name: str, filename: str, content: bytes) -> bytes:
        head = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
            # Proper MIME type — makes the Telegram client show the APK
            # with the Android package icon and honour its size/name.
            f"Content-Type: application/vnd.android.package-archive\r\n\r\n"
        ).encode("utf-8")
        return head + content + b"\r\n"

    body = (
        text_field("chat_id", chat_id)
        + text_field("caption", caption)
        + text_field("parse_mode", "HTML")
        + file_field("document", os.path.basename(apk_path), file_bytes)
        + f"--{boundary}--\r\n".encode("utf-8")
    )

    result = tg_request(
        "sendDocument",
        token,
        body=body,
        content_type=f"multipart/form-data; boundary={boundary}",
    )
    return int(result["message_id"])


def send_reply(token: str, chat_id: str, text: str, reply_to: int) -> None:
    """Post a text message as a reply to the APK message."""
    from urllib.parse import urlencode

    body = urlencode(
        {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "reply_to_message_id": str(reply_to),
        }
    ).encode()
    tg_request(
        "sendMessage",
        token,
        body=body,
        content_type="application/x-www-form-urlencoded",
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--changelog", required=True,
                    help="Path to docs/changelog/vX.Y.Z.md; only read when --with-changelog is passed.")
    # Default: just the APK + short caption (title + SHA-256 + repo URL +
    # release URL). The per-release Persian/English blockquote reply is
    # opt-in via `--with-changelog` so routine releases don't flood the
    # channel with bullet-point bodies. To re-enable for a specific tag:
    # set the repo variable TELEGRAM_INCLUDE_CHANGELOG=true before pushing
    # the tag (the workflow converts that into --with-changelog).
    ap.add_argument("--with-changelog", action="store_true",
                    help="Include the Persian+English changelog as a reply-threaded message.")
    # Dry-run lets you verify the rendered caption locally without hitting
    # Telegram. Useful when changing the brief-release-note budget /
    # truncation logic — print, eyeball, push.
    ap.add_argument("--dry-run", action="store_true",
                    help="Render the caption and print it instead of posting. "
                         "Skips token/chat_id checks.")
    args = ap.parse_args()

    if not args.dry_run:
        token = os.environ.get("BOT_TOKEN", "")
        chat_id = os.environ.get("CHAT_ID", "")
        if not token or not chat_id:
            print("TELEGRAM secrets not present, skipping post.")
            return 0
    else:
        token = ""
        chat_id = ""

    ver = args.version
    sha = sha256_of(args.apk)
    # Brief Persian release-note above the links. Pulled from the FA
    # half of `docs/changelog/v<ver>.md` so each release auto-includes
    # what's new without manual edits to this script. Truncated to fit
    # Telegram's 1024-char caption budget alongside title + SHA + the
    # two-link footer.
    fa_note = build_caption_release_note(args.changelog)

    # Caption structure requested by the repo owner:
    #   1. Title + SHA-256 (as before)
    #   2. Brief Persian "what's new" note (extracted from changelog)
    #   3. Persian preamble labelling the repo link as
    #      "GitHub repo + full Persian guide"
    #   4. Repo URL
    #   5. Persian preamble labelling the release link as
    #      "this version's release — desktop/router builds live here"
    #   6. Release URL
    # Keeps total well under Telegram's 1024-char caption limit.
    caption_parts = [
        f"<b>mhrv-rs Android v{ver}</b>",
        "",
        f"SHA-256: <code>{sha}</code>",
    ]
    if fa_note:
        caption_parts.extend(["", fa_note])
    caption_parts.extend([
        "",
        "مخزن گیتهاب  + مطالعه راهنمای کامل فارسی:",
        f"https://github.com/{args.repo}",
        "",
        "لینک به این نسخه جهت دریافت نسخه های مربوط به مودم و کامپیوتر:",
        f"https://github.com/{args.repo}/releases/tag/v{ver}",
    ])
    caption = "\n".join(caption_parts)

    if args.dry_run:
        print(f"--- DRY RUN: caption ({len(caption)} chars) ---")
        print(caption)
        print(f"--- END DRY RUN ---")
        if args.with_changelog:
            fa, en = parse_changelog(args.changelog)
            print(f"\nWould reply with changelog "
                  f"(fa: {len(fa) if fa else 0} chars, "
                  f"en: {len(en) if en else 0} chars)")
        return 0

    doc_mid = send_document(token, chat_id, args.apk, caption)
    print(f"sendDocument OK, message_id={doc_mid}")

    if not args.with_changelog:
        print("Changelog reply disabled (default). Pass --with-changelog to include.")
        return 0

    fa, en = parse_changelog(args.changelog)
    if not fa and not en:
        print(f"No changelog at {args.changelog}, skipping reply.")
        return 0

    parts = []
    if fa:
        parts.append(f"<blockquote>{fa}</blockquote>")
    if en:
        parts.append(f"<blockquote>{en}</blockquote>")
    reply = "\n\n".join(parts)

    send_reply(token, chat_id, reply, doc_mid)
    print("Reply OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
