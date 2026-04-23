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
    args = ap.parse_args()

    token = os.environ.get("BOT_TOKEN", "")
    chat_id = os.environ.get("CHAT_ID", "")
    if not token or not chat_id:
        print("TELEGRAM secrets not present, skipping post.")
        return 0

    ver = args.version
    sha = sha256_of(args.apk)
    caption = (
        f"<b>mhrv-rs Android v{ver}</b>\n\n"
        f"SHA-256: <code>{sha}</code>\n"
        f"https://github.com/{args.repo}\n"
        f"https://github.com/{args.repo}/releases/tag/v{ver}"
    )

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
