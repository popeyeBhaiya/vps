#!/usr/bin/env python3
"""
Telegram bot for asaphila_checker.py — host on VPS.
Reports per card: status, time consumed, IP used for the check.

Usage:
  Set BOT_TOKEN (env or .env). Optional: PROXY for all checks.
  python asaphila_telegram_bot.py

Commands:
  /start  — welcome
  /check  — instructions
  /proxy [host:port:user:pass] — set proxy (optional, empty to clear)
  Send cards (one per line, number|month|year|cvv) or a .txt file to run check.
"""

import asyncio
import io
import os
import time
from typing import List, Optional

# Optional .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

from asaphila_checker import CardDetails, AsaphilaChecker


BOT_TOKEN = os.environ.get("ASAPHILA_BOT_TOKEN") or os.environ.get("BOT_TOKEN")
if not BOT_TOKEN:
    raise SystemExit("Set ASAPHILA_BOT_TOKEN or BOT_TOKEN in env (or .env)")


def parse_cards(text: str) -> List[CardDetails]:
    cards: List[CardDetails] = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "|" in line and len(line) > 10:
            try:
                cards.append(CardDetails.from_string(line))
            except Exception:
                continue
    return cards


def run_one_card(card: CardDetails, proxy: Optional[str]) -> dict:
    """Run checker for one card; return result + time_sec + ip."""
    start = time.perf_counter()
    checker = AsaphilaChecker(proxy=proxy)
    ip = checker.client.get_check_ip()
    result = checker.check_card(card)
    elapsed = time.perf_counter() - start
    result["time_sec"] = round(elapsed, 2)
    result["ip"] = ip
    return result


async def run_cards_sync(cards: List[CardDetails], proxy: Optional[str]) -> List[dict]:
    """Run all cards in thread pool so we don't block the event loop."""
    loop = asyncio.get_event_loop()
    results = []
    for card in cards:
        r = await loop.run_in_executor(None, lambda c=card: run_one_card(c, proxy))
        results.append(r)
    return results


def format_result(idx: int, total: int, r: dict) -> str:
    card = r.get("card")
    raw = card.raw if card else "?"
    status = r.get("status", "?")
    msg = r.get("message", "")
    code = r.get("code", "")
    t = r.get("time_sec", 0)
    ip = r.get("ip", "?")
    extra = f" | {code}" if code else ""
    return f"[{idx}/{total}] {status} | {t}s | IP: {ip}\n  {raw}\n  {msg}{extra}"


async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Asaphila checker bot.\n\n"
        "/check — how to send cards\n"
        "/proxy [proxy] — set proxy (host:port or host:port:user:pass), empty to clear\n\n"
        "Send cards (one per line: number|month|year|cvv) or a .txt file to run."
    )


async def check_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Send cards as:\n"
        "• One card per line: number|month|year|cvv\n"
        "• Or attach a .txt file with one card per line.\n\n"
        "Each result will show: status, time (seconds), IP used for the check."
    )


async def proxy_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (update.message.text or "").strip()
    args = text.split(maxsplit=1)
    proxy = (args[1].strip() if len(args) > 1 else "") or None
    context.user_data["proxy"] = proxy
    if proxy:
        await update.message.reply_text(f"Proxy set: {proxy[:60]}...")
    else:
        await update.message.reply_text("Proxy cleared.")


def get_user_proxy(context: ContextTypes.DEFAULT_TYPE) -> Optional[str]:
    return context.user_data.get("proxy") if context.user_data else None


def _is_cards_message(update: Update) -> bool:
    if update.message.document:
        return (update.message.document.file_name or "").endswith(".txt")
    return "|" in (update.message.text or "")

async def handle_cards(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message or not _is_cards_message(update):
        return
    text = update.message.text or ""
    proxy = get_user_proxy(context)

    doc = update.message.document
    if doc and (not doc.file_name or not doc.file_name.endswith(".txt")):
        return
    if doc and doc.file_name and doc.file_name.endswith(".txt"):
        file = await context.bot.get_file(doc.file_id)
        buf = io.BytesIO()
        await file.download_to_memory(buf)
        text = buf.getvalue().decode("utf-8", errors="replace")

    cards = parse_cards(text)
    if not cards:
        await update.message.reply_text(
            "No valid cards. Send lines like: 4111111111111111|12|2028|123"
        )
        return

    if len(cards) > 50:
        await update.message.reply_text("Max 50 cards per run. Send fewer.")
        return

    status_msg = await update.message.reply_text(f"Checking {len(cards)} card(s)...")
    try:
        results = await run_cards_sync(cards, proxy)
    except Exception as e:
        await status_msg.edit_text(f"Error: {e}")
        return

    charged = live = dead = err = 0
    for r in results:
        s = r.get("status", "")
        if s == "CHARGED":
            charged += 1
        elif s == "LIVE":
            live += 1
        elif s == "DEAD":
            dead += 1
        else:
            err += 1

    # Send results (Telegram limit 4096 per message)
    lines = []
    for i, r in enumerate(results, 1):
        lines.append(format_result(i, len(cards), r))
    summary = f"\nCHARGED: {charged} | LIVE: {live} | DEAD: {dead} | ERR: {err}"
    block = "\n".join(lines) + summary
    if len(block) > 4000:
        # Split into chunks
        chunk = []
        size = 0
        for line in lines:
            if size + len(line) + 1 > 4000 and chunk:
                await update.message.reply_text("\n".join(chunk))
                chunk = []
                size = 0
            chunk.append(line)
            size += len(line) + 1
        if chunk:
            await update.message.reply_text("\n".join(chunk))
        await update.message.reply_text(summary)
    else:
        await update.message.reply_text(block)
    await status_msg.delete()


def main() -> None:
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start_cmd))
    app.add_handler(CommandHandler("check", check_cmd))
    app.add_handler(CommandHandler("proxy", proxy_cmd))
    app.add_handler(
        MessageHandler(
            filters.TEXT | filters.ATTACHMENT,
            handle_cards,
        )
    )
    print("Asaphila Telegram bot running (Ctrl+C to stop)...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
