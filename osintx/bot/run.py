"""Telegram-бот OsintX (python-telegram-bot v21, асинхронный).

Что умеет бот:
  /search <цель>   — полный поиск (email, логин, @telegram, телефон, домен, IP, ФИО, крипта)
  /deep <цель>     — глубокий поиск
  /id <цель>       — Telegram-разведка: t.me-карточка, подписчики, посты, fragment,
                     а при настроенном MTProto — числовой ID, DC, общие чаты, поиск по сообщениям
  /password <пароль> — проверка пароля по утечкам (k-anonymity)
  /history, /stats, /sources, /dataset-search <значение>, /graph <цель>
  просто текст      — трактуется как цель поиска

Результаты: сводка в чат + файлы отчёта (HTML/JSON/CSV/Markdown) по кнопке.
"""
from __future__ import annotations

import asyncio
import html
import io
import json
import logging
import time
from typing import Any

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import (Application, CallbackQueryHandler, CommandHandler, ContextTypes,
                          MessageHandler, filters)

from .. import __version__
from ..config import get_settings
from ..core.store import get_store
from ..core.utils import detect_target_type, human_ms
from ..engine import Engine
from ..report import FORMATS, to_text

logging.basicConfig(format="%(asctime)s %(levelname)s %(name)s: %(message)s", level=logging.INFO)
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger("osintx.bot")

HELP = f"""<b>OsintX {__version__}</b> — OSINT-поиск по открытым источникам.

<b>Что можно отправить</b>
• email — <code>ivan.petrov@example.com</code>
• логин — <code>torvalds</code>
• Telegram — <code>@durov</code> или <code>t.me/durov</code>
• телефон — <code>+79991234567</code>
• домен — <code>example.com</code>
• IP — <code>8.8.8.8</code>
• ФИО — <code>Иван Петров</code>
• криптоадрес — BTC/ETH

<b>Команды</b>
/search &lt;цель&gt; — обычный поиск
/deep &lt;цель&gt; — глубокий поиск (больше источников, дольше)
/id &lt;@username | телефон&gt; — Telegram-разведка
/password &lt;пароль&gt; — проверка пароля по утечкам (пароль не передаётся наружу)
/history — последние поиски, /stats — статистика базы
/sources — сколько источников подключено
/dataset-search &lt;значение&gt; — поиск по загруженным внешним базам
/graph &lt;цель&gt; — схема связей (mermaid)

Просто отправьте цель сообщением — начну поиск."""


def _allowed(update: Update) -> bool:
    allowed = get_settings().allowed_ids
    if not allowed:
        return True
    user = update.effective_user
    return bool(user and user.id in allowed)


async def _guard(update: Update) -> bool:
    if _allowed(update):
        return True
    await update.effective_message.reply_text(
        f"Доступ ограничен. Ваш Telegram ID: {update.effective_user.id}\n"
        "Добавьте его в TELEGRAM_ALLOWED_IDS в .env, чтобы разрешить доступ.")
    return False


def _report_keyboard(search_id: str, target: str, deep: bool) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📄 HTML", callback_data=f"dl:html:{search_id}"),
         InlineKeyboardButton("🧾 JSON", callback_data=f"dl:json:{search_id}"),
         InlineKeyboardButton("📊 CSV", callback_data=f"dl:csv:{search_id}")],
        [InlineKeyboardButton("🧠 Глубже", callback_data=f"deep:{target[:40]}" if len(target) <= 40
                              else f"deep:{search_id}"),
         InlineKeyboardButton("📈 Граф", callback_data=f"graph:{target[:40]}")],
    ])


class Progress:
    """Сообщение-прогресс, которое редактируется по мере поступления событий."""

    def __init__(self, message, target: str):
        self.message = message
        self.target = target
        self.hits: list[str] = []
        self.stage = "запуск"
        self.last_edit = 0.0
        self.lock = asyncio.Lock()

    def _text(self) -> str:
        lines = [f"🔎 <b>Поиск:</b> <code>{html.escape(self.target)}</code>",
                 f"Этап: {html.escape(self.stage)}",
                 f"Найдено: <b>{len(self.hits)}</b>", ""]
        lines += [f"✅ {html.escape(h)}" for h in self.hits[-12:]]
        return "\n".join(lines)

    async def on_event(self, ev: dict[str, Any]) -> None:
        kind = ev.get("kind")
        if kind == "stage":
            self.stage = str(ev.get("message", ""))[:60]
        elif kind == "module_start":
            self.stage = str(ev.get("title", ev.get("module", "")))[:60]
        elif kind == "hit":
            self.hits.append(f"{ev.get('source')}: {str(ev.get('url') or ev.get('detail') or '')[:70]}")
        else:
            return
        now = time.time()
        if now - self.last_edit < 1.6:
            return
        async with self.lock:
            self.last_edit = now
            try:
                await self.message.edit_text(self._text(), parse_mode=ParseMode.HTML,
                                             disable_web_page_preview=True)
            except Exception:
                pass


def _summary_text(report) -> str:
    s = report.summary
    lines = [f"<b>Готово:</b> <code>{html.escape(report.target)}</code> "
             f"({report.target_type}) за {human_ms(report.duration_ms)}",
             f"Находок: <b>{s['findings']}</b> | проверено источников: {s['sources_checked']} "
             f"(недоступно {s['sources_failed']}, покрытие {s['coverage']}%)",
             f"Оценка экспозиции: {s['risk_score']}/100", ""]
    by_conf = s.get("by_confidence") or {}
    if by_conf:
        lines.append("Достоверность: " + ", ".join(f"{k}: {v}" for k, v in by_conf.items()))
    for f in report.findings[:14]:
        icon = {"high": "🟢", "medium": "🟡", "low": "⚪"}.get(f.confidence, "•")
        lines.append(f"{icon} <b>{html.escape(f.source)}</b>: {html.escape(f.title[:180])}")
        if f.url:
            lines.append(f'   <a href="{html.escape(f.url)}">ссылка</a>')
    if len(report.findings) > 14:
        lines.append(f"… ещё {len(report.findings) - 14} находок в файлах отчёта")
    if not report.findings:
        lines.append("Находок нет. Проверьте недоступные источники в отчёте — "
                     "их отказ не означает «не найдено».")
    return "\n".join(lines)


async def run_search(update: Update, target: str, *, deep: bool = False) -> None:
    if not await _guard(update):
        return
    message = await update.effective_message.reply_text(
        f"🔎 Ищу <code>{html.escape(target)}</code> …", parse_mode=ParseMode.HTML,
        disable_web_page_preview=True)
    # ограничиваем длину текста Telegram (4096)
    progress = Progress(message, target)
    engine = Engine()
    try:
        report = await engine.search(
            target, deep=deep, variant_probe=deep or None, on_event=progress.on_event,
            timeout=25 if deep else 15)
    except Exception as exc:
        await message.edit_text(f"⚠️ Ошибка поиска: {html.escape(str(exc))[:300]}")
        return
    text = _summary_text(report)[:4000]
    keyboard = _report_keyboard(report.search_id, report.target, deep)
    try:
        await message.edit_text(text, parse_mode=ParseMode.HTML, reply_markup=keyboard,
                                disable_web_page_preview=True)
    except Exception:
        await message.edit_text(text[:4000], reply_markup=keyboard)


async def cmd_start(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _guard(update):
        return
    await update.message.reply_text(HELP, parse_mode=ParseMode.HTML, disable_web_page_preview=True)


async def cmd_search(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    target = " ".join(context.args).strip()
    if not target:
        await update.message.reply_text("Укажите цель: /search ivan.petrov@example.com")
        return
    await run_search(update, target, deep=False)


async def cmd_deep(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    target = " ".join(context.args).strip()
    if not target:
        await update.message.reply_text("Укажите цель: /deep @durov")
        return
    await run_search(update, target, deep=True)


async def cmd_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (update.message.text or "").strip()
    if not text or text.startswith("/"):
        return
    if update.message.chat.type != "private" and "@" + (context.bot.username or "") not in text:
        return  # в группах реагируем только на упоминание
    text = text.replace("@" + (context.bot.username or ""), "").strip()
    await run_search(update, text)


async def cmd_id(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Telegram-разведка (t.me + MTProto при наличии ключей)."""
    target = " ".join(context.args).strip()
    if not target:
        await update.message.reply_text("Укажите @username, ссылку t.me/... или номер телефона.")
        return
    if not await _guard(update):
        return
    message = await update.message.reply_text(
        f"📡 Telegram-разведка: <code>{html.escape(target)}</code>", parse_mode=ParseMode.HTML)
    progress = Progress(message, target)
    from ..modules.base import Context as ModContext
    from ..core.http import HttpClient
    from ..modules.telegram import TelegramModule
    from ..core.models import ModuleResult

    settings = get_settings()
    async with HttpClient(settings) as http:
        ctx = ModContext(settings=settings, http=http, store=get_store(),
                         options={"deep": True, "use_keys": True, "smtp": False}, emit=progress.on_event)
        result = ModuleResult(module="telegram", target=target)
        await TelegramModule().run(ctx, target, result)
    lines = [f"📡 <b>Telegram:</b> <code>{html.escape(target)}</code>", ""]
    for f in result.findings[:16]:
        lines.append(f"• <b>{html.escape(f.source)}</b>: {html.escape(f.title[:200])}")
        if f.url:
            lines.append(f'   <a href="{html.escape(f.url)}">открыть</a>')
    for st in result.statuses:
        if st.status in ("unsupported", "blocked", "error"):
            lines.append(f"⛔ {html.escape(st.source)}: {html.escape((st.detail or st.error)[:180])}")
    if not result.findings:
        lines.append("Публичных данных не найдено.")
    await message.edit_text("\n".join(lines)[:4000], parse_mode=ParseMode.HTML,
                            disable_web_page_preview=True)


async def cmd_password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _guard(update):
        return
    password = context.args[0] if context.args else ""
    if not password:
        await update.message.reply_text("Использование: /password мойпароль\n"
                                        "Пароль уходит только в виде первых 5 символов SHA-1 (k-anonymity).")
        return
    from ..core.http import HttpClient
    from ..modules.base import Context as ModContext
    from ..modules.breach import check_password_pwned

    settings = get_settings()
    async with HttpClient(settings) as http:
        ctx = ModContext(settings=settings, http=http, store=get_store())
        result = await check_password_pwned(password, ctx)
    try:
        await update.message.delete()
    except Exception:
        pass
    if not result.get("checked"):
        await update.message.reply_text(f"⚠️ Не удалось проверить: {result.get('error')}")
        return
    if result["pwned"]:
        await update.message.reply_text(
            f"🔴 Пароль найден в утечках: {result['count']:,} совпадений в базе HIBP.\n"
            "Смените его везде, где использовали, и включите двухфакторную аутентификацию.")
    else:
        await update.message.reply_text("🟢 В базе HIBP (800+ млн утёкших паролей) пароль не найден.\n"
                                        "Это не гарантия стойкости — используйте менеджер паролей.")


async def cmd_history(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _guard(update):
        return
    rows = get_store().history(limit=15)
    if not rows:
        await update.message.reply_text("История пуста.")
        return
    lines = ["<b>Последние поиски</b>"]
    for r in rows:
        lines.append(f"• <code>{html.escape(r['target'][:40])}</code> ({r['target_type']}) — "
                     f"находок {r['findings']}, покрытие {r['coverage']}%, {r['started_at'][:16]}")
    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.HTML)


async def cmd_stats(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _guard(update):
        return
    stats = get_store().stats()
    from ..core.registry import count_sources
    counts = count_sources()
    text = (f"<b>База OsintX</b>\n"
            f"Поисков: {stats['searches']}\nНаходок: {stats['findings']}\n"
            f"Сущностей: {stats['entities']}\nСвязей: {stats['edges']}\n"
            f"Внешних баз загружено: {len(stats['datasets'])}\n\n"
            f"<b>Источники:</b> логины {counts['username']}, email {counts['email']}, "
            f"телефоны {counts['phone']}\nБД: <code>{html.escape(stats['db_path'])}</code>")
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


async def cmd_sources(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _guard(update):
        return
    from ..core.registry import count_sources
    counts = count_sources()
    await update.message.reply_text(
        f"Источников в реестре:\n• логины: {counts['username']}\n• email: {counts['email']}\n"
        f"• телефоны: {counts['phone']}\n\nПлюс API-проверки в коде: GitHub, GitLab, Keybase, Reddit, "
        f"Hacker News, StackOverflow, DNS/RDAP/crt.sh, Shodan InternetDB, Tor Onionoo, XposedOrNot, "
        f"Wikidata, OpenSanctions, Blockstream, Blockchair и другие.")


async def cmd_dataset_search(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _guard(update):
        return
    value = " ".join(context.args).strip()
    if not value:
        await update.message.reply_text("Использование: /dataset-search user@example.com")
        return
    hits = get_store().search_local(value, limit=25)
    if not hits:
        await update.message.reply_text("Совпадений в загруженных базах нет.")
        return
    lines = [f"<b>Найдено {len(hits)} совпадений в локальных базах:</b>"]
    for h in hits[:20]:
        lines.append(f"• [{html.escape(str(h.get('dataset')))}] <code>{html.escape(str(h.get('value')))}</code> "
                     f"{html.escape(str(h.get('extra') or '')[:80])}")
    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.HTML)


async def cmd_graph(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _guard(update):
        return
    target = " ".join(context.args).strip()
    if not target:
        await update.message.reply_text("Использование: /graph ivan.petrov@example.com")
        return
    store = get_store()
    data = store.entity_neighbours(detect_target_type(target), target, depth=2)
    if not data["edges"]:
        await update.message.reply_text("Связей нет — сначала выполните /search по этой цели.")
        return
    lines = ["graph LR"]
    for e in data["edges"][:60]:
        lines.append(f'    "{e["src"]}" -->|{e["relation"]}| "{e["dst"]}"')
    await update.message.reply_text("```\n" + "\n".join(lines)[:3500] + "\n```",
                                    parse_mode=ParseMode.MARKDOWN_V2)


async def cmd_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    data = query.data or ""
    if data.startswith("dl:"):
        _, fmt, search_id = data.split(":", 2)

        class _Tmp:  # минимальная обёртка, чтобы переиспользовать _summary_text-подобную логику
            pass

        from ..web.app import _load_report  # переиспользуем загрузку отчёта из БД/памяти
        report = _load_report(search_id)
        if report is None:
            await query.message.reply_text("Отчёт не найден (истёк). Запустите поиск заново.")
            return
        func, ext = FORMATS[fmt]
        content = func(report)
        buf = io.BytesIO(content.encode("utf-8"))
        buf.name = f"osintx_{report.target_type}_{report.search_id}.{ext}"
        await query.message.reply_document(buf, filename=buf.name,
                                          caption=f"Отчёт по {report.target} ({fmt})")
    elif data.startswith("deep:"):
        target = data.split(":", 1)[1]
        await query.message.reply_text(f"Запускаю глубокий поиск по {target} …")
        await run_search(update, target, deep=True)
    elif data.startswith("graph:"):
        target = data.split(":", 1)[1]
        store = get_store()
        payload = store.entity_neighbours(detect_target_type(target), target, depth=2)
        if not payload["edges"]:
            await query.message.reply_text("Связей не найдено.")
            return
        lines = ["graph LR"]
        for e in payload["edges"][:60]:
            lines.append(f'    "{e["src"]}" -->|{e["relation"]}| "{e["dst"]}"')
        await query.message.reply_text("```\n" + "\n".join(lines)[:3500] + "\n```",
                                       parse_mode=ParseMode.MARKDOWN_V2)


async def cmd_error(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    log.error("Ошибка обработки: %s", context.error)


def main() -> int:
    settings = get_settings()
    if not settings.bot_token:
        print("Не задан TELEGRAM_BOT_TOKEN. Добавьте токен от @BotFather в .env")
        return 1
    app = Application.builder().token(settings.bot_token).concurrent_updates(True).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_start))
    app.add_handler(CommandHandler("search", cmd_search))
    app.add_handler(CommandHandler("deep", cmd_deep))
    app.add_handler(CommandHandler("id", cmd_id))
    app.add_handler(CommandHandler("password", cmd_password))
    app.add_handler(CommandHandler("history", cmd_history))
    app.add_handler(CommandHandler("stats", cmd_stats))
    app.add_handler(CommandHandler("sources", cmd_sources))
    app.add_handler(CommandHandler("dataset_search", cmd_dataset_search))
    app.add_handler(CommandHandler("graph", cmd_graph))
    app.add_handler(CallbackQueryHandler(cmd_callback))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, cmd_text))
    app.add_error_handler(cmd_error)
    print("OsintX-бот запущен. Нажмите Ctrl+C для остановки.")
    app.run_polling(allowed_updates=["message", "callback_query"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
