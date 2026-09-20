"""Telegram-бот OsintX (python-telegram-bot v21+, асинхронный).

Что умеет бот:

  Поиск
    /search <цель>        — полный поиск (email, логин, @telegram, телефон, домен, IP, ФИО, крипта)
    /deep <цель>          — глубокий поиск
    /email /user /phone /tg /domain /ip /name <значение> — быстрый поиск нужного типа
    текст сообщением      — то же, что /search (в группах — по упоминанию бота)

  Работа с результатом
    🔗 кнопки-пивоты       — раскрутить найденное: нажать на email/логин/домен/IP и искать дальше
    ◀ ▶ пагинация          — находок может быть много
    📄 HTML / 🧾 JSON / 📊 CSV — файлы отчёта
    🧠 Глубже / 📈 Граф    — повторный глубокий поиск и схема связей
    🌍 Веб-отчёт           — если задан WEB_PUBLIC_URL

  Telegram-разведка
    /id <@user|телефон>    — t.me-карточка, подписчики, посты, fragment; с MTProto — ID, DC, поиск по сообщениям

  Наблюдение
    /watch add|list|rm|check  — слежение за целями; фоновая проверка раз в N часов (TELEGRAM_WATCH_INTERVAL)

  Прочее
    /settings              — настройки поиска (глубина, варианты, ключи, сохранение в историю)
    /modules               — выбрать модули кнопками
    /password <пароль>     — проверка пароля по утечкам (k-anonymity)
    /report <id>           — заново получить отчёт из истории
    /history /stats /sources /graph /dataset-search /cancel

Запуск: `python bot.py` (корневой файл) или `osintx bot`.
"""
from __future__ import annotations

import asyncio
import warnings
import html
import io
import logging
import time
from datetime import timedelta
from typing import Any

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ChatAction, ParseMode
from telegram.error import NetworkError
from telegram.ext import (Application, CallbackQueryHandler, CommandHandler, ContextTypes,
                          MessageHandler, filters)

from .. import __version__
from ..config import get_settings
from ..core.history import load_report
from ..core.http import HttpClient
from ..core.models import ModuleResult
from ..core.store import get_store
from ..core.utils import detect_target_type
from ..engine import Engine
from ..netcheck import diagnose, explain_network_error
from ..report import FORMATS
from . import ui
from .limits import RateLimiter
from .watch import check_all as watch_check_all

logging.basicConfig(format="%(asctime)s %(levelname)s %(name)s: %(message)s", level=logging.INFO)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("telegram.ext.Application").setLevel(logging.WARNING)
log = logging.getLogger("osintx.bot")

limiter = RateLimiter()
RUNNING: dict[int, asyncio.Event] = {}       # chat_id → событие отмены текущего поиска

FORCED_TYPE = {
    "email": "email", "user": "username", "phone": "phone", "tg": "telegram",
    "domain": "domain", "ip": "ip", "name": "person", "crypto": "crypto",
}

HELP = f"""<b>OsintX {__version__}</b> — OSINT-поиск по открытым источникам.

<b>Просто отправьте цель сообщением</b> — начну поиск:
• email — <code>ivan.petrov@example.com</code>
• логин — <code>torvalds</code>
• Telegram — <code>@durov</code> или <code>t.me/durov</code>
• телефон — <code>+79991234567</code>
• домен — <code>example.com</code>  • IP — <code>8.8.8.8</code>
• ФИО — <code>Иван Петров</code>  • крипта — BTC/ETH адрес

<b>Поиск</b>
/search &lt;цель&gt; · /deep &lt;цель&gt;
/email · /user · /phone · /tg · /domain · /ip · /name — быстрый поиск нужного типа
/geo &lt;цель&gt; — где живёт: страна и город по публичным профилям
/changes &lt;цель&gt; — что менялось: ник, имя, био, город (по прошлым проверкам)
/vk &lt;ник&gt; — ВКонтакте: профиль, город, посты, сообщества (+ VK_TOKEN для полного доступа)
/max &lt;ник&gt; — мессенджер MAX: канал/бот по @нику, ссылки max.ru/u/…

<b>Результат</b>
Кнопки под сводкой: раскрутить найденное дальше (пивот), листать находки (◀ ▶),
скачать HTML/JSON/CSV, повторить глубоко, посмотреть граф связей.

<b>Telegram</b>
/id &lt;@user|телефон&gt; — профиль, подписчики, посты, fragment; с MTProto — ID, DC, поиск по сообщениям
«Где писал»: в поиске по @каналу/логину Telegram бот разбирает посты, считает активность
и ищет упоминания через t.me/s/&lt;канал&gt;?q=… — конкретные посты со ссылками

<b>Наблюдение</b>
/watch add &lt;цель&gt; · /watch list · /watch check · /watch rm &lt;цель&gt;
Бот сам перепроверяет цели (интервал: TELEGRAM_WATCH_INTERVAL часов) и сообщает только о новых данных.

<b>Прочее</b>
/settings — настройки поиска · /modules — выбрать модули
/password &lt;пароль&gt; — проверка пароля по утечкам
/report &lt;id&gt; · /history · /stats · /sources · /dataset-search &lt;значение&gt; · /cancel"""


async def cmd_start(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    """Приветствие + ваш Telegram ID (нужен для TELEGRAM_ALLOWED_IDS)."""
    if not await _guard(update):
        return
    user_id = update.effective_user.id
    extra = ("" if get_settings().allowed_ids else
             "\n<i>Доступ открыт всем, кто знает @username бота. Впишите этот ID в "
             "TELEGRAM_ALLOWED_IDS, чтобы ограничить круг.</i>")
    await update.message.reply_text(
        HELP + f"\n\n<b>Ваш Telegram ID:</b> <code>{user_id}</code>" + extra,
        parse_mode=ParseMode.HTML, disable_web_page_preview=True)


# ───────────────────────────── доступ и утилиты ─────────────────────────────
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


def _user_id(update: Update) -> int:
    return update.effective_user.id if update.effective_user else 0


class Progress:
    """Редактируемое сообщение-прогресс (с троттлингом под лимиты Telegram)."""

    def __init__(self, message, target: str, page_limit: float = 1.6):
        self.message = message
        self.target = target
        self.hits: list[str] = []
        self.stage = "запуск"
        self.last_edit = 0.0
        self.page_limit = page_limit
        self.lock = asyncio.Lock()

    def _text(self) -> str:
        lines = [f"🔎 <b>Поиск:</b> <code>{html.escape(self.target)}</code>",
                 f"Этап: {html.escape(self.stage)}",
                 f"Найдено: <b>{len(self.hits)}</b>", ""]
        lines += [f"✅ {html.escape(hit)}" for hit in self.hits[-12:]]
        lines.append("")
        lines.append("<i>Отменить: /cancel</i>")
        return "\n".join(lines)

    async def on_event(self, event: dict[str, Any]) -> None:
        kind = event.get("kind")
        if kind == "stage":
            self.stage = str(event.get("message", ""))[:60]
        elif kind == "module_start":
            self.stage = str(event.get("message") or event.get("title") or "")[:60]
        elif kind == "hit":
            self.hits.append(f"{event.get('source')}: {str(event.get('url') or event.get('detail') or '')[:70]}")
        else:
            return
        now = time.time()
        if now - self.last_edit < self.page_limit:
            return
        async with self.lock:
            self.last_edit = now
            try:
                await self.message.edit_text(self._text(), parse_mode=ParseMode.HTML,
                                             disable_web_page_preview=True)
            except Exception:
                pass


async def _typing(update: Update) -> None:
    try:
        await update.effective_chat.send_action(ChatAction.TYPING)
    except Exception:
        pass


# ───────────────────────────── основной поиск ─────────────────────────────
async def run_search(update: Update, target: str, *, deep: bool | None = None,
                     target_type: str | None = None, modules: list[str] | None = None,
                     use_prefs: bool = True) -> None:
    if not await _guard(update):
        return
    target = (target or "").strip()
    if not target:
        return
    store = get_store()
    user_id = _user_id(update)
    chat_id = update.effective_chat.id

    prefs = store.get_prefs(user_id) if use_prefs else {}
    deep = prefs.get("deep", False) if deep is None else deep
    variants = prefs.get("variants", False)
    save = prefs.get("save", True)
    use_keys = prefs.get("use_keys", True)
    modules = modules or prefs.get("modules")

    ok, message = limiter.check(user_id, target=target)
    if not ok:
        await update.effective_message.reply_text(message)
        return
    if chat_id in RUNNING:
        await update.effective_message.reply_text(
            "⚠️ В этом чате уже идёт поиск. Дождитесь его окончания или отправьте /cancel.")
        return

    limiter.register(user_id)
    store.log_search(user_id, target)
    cancel_event = asyncio.Event()
    RUNNING[chat_id] = cancel_event

    progress_message = await update.effective_message.reply_text(
        f"🔎 Ищу <code>{html.escape(target)}</code> …" + ("\nГлубокий режим." if deep else ""),
        parse_mode=ParseMode.HTML, disable_web_page_preview=True)
    progress = Progress(progress_message, target)
    engine = Engine()
    started = time.time()
    try:
        report = await engine.search(
            target, deep=deep, variant_probe=variants or deep, use_keys=use_keys,
            on_event=progress.on_event, timeout=25 if deep else 15,
            target_type=target_type, modules=modules, no_save=not save,
            cancel_event=cancel_event)
    except Exception as exc:
        RUNNING.pop(chat_id, None)
        await progress_message.edit_text(f"⚠️ Ошибка поиска: {html.escape(str(exc))[:300]}")
        return
    finally:
        RUNNING.pop(chat_id, None)

    ui.remember(report)

    text, page, pages = ui.summary_text(report)
    keyboard = ui.report_keyboard(report, page, pages, deep=deep,
                                  web_url=get_settings().public_url)
    try:
        await progress_message.edit_text(text[:4000], parse_mode=ParseMode.HTML,
                                         reply_markup=keyboard, disable_web_page_preview=True)
    except Exception:
        await progress_message.edit_text(text[:4000], reply_markup=keyboard)
    log.info("поиск %s (user=%s): находок %s за %.1fс",
             target, user_id, len(report.findings), time.time() - started)


async def cmd_search(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    target = " ".join(context.args).strip()
    if not target:
        await update.message.reply_text("Укажите цель: /search ivan.petrov@example.com")
        return
    await run_search(update, target)


async def cmd_deep(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    target = " ".join(context.args).strip()
    if not target:
        await update.message.reply_text("Укажите цель: /deep @durov")
        return
    await run_search(update, target, deep=True)


async def cmd_typed(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Быстрые команды /email /user /phone /tg /domain /ip /name."""
    command = (update.message.text or "").split()[0].lstrip("/").split("@")[0]
    target_type = FORCED_TYPE.get(command)
    target = " ".join(context.args).strip()
    if not target:
        await update.message.reply_text(f"Использование: /{command} <значение>")
        return
    await run_search(update, target, target_type=target_type)


async def cmd_geo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """«Где живёт?» — страна/город по публичным профилям (GitHub, Gravatar, Keybase, Steam, телефон)."""
    if not await _guard(update):
        return
    target = " ".join(context.args).strip()
    if not target:
        await update.message.reply_text(
            "Использование: /geo <цель>\n"
            "Смотрю страну и город по публичным данным: локации в профилях GitHub/GitLab, "
            "Gravatar, Keybase, Steam, bio в Telegram, страна номера телефона.\n"
            "Пример: /geo torvalds")
        return
    await run_search(update, target, modules=["geo", "telegram", "username", "wayback"],
                     deep=False, use_keys=False)


async def cmd_vk(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """ВКонтакте: профиль/сообщество, город, посты. Без VK_TOKEN — публичная мобильная версия."""
    if not await _guard(update):
        return
    target = " ".join(context.args).strip().lstrip("@")
    if not target:
        await update.message.reply_text(
            "Использование: /vk <ник или id>\n"
            "Смотрю профиль ВКонтакте: имя, город/страна, подписчики, публичные записи и связи.\n"
            "Без VK_TOKEN доступна только мобильная публичная страница (имя и записи); "
            "сервисный ключ VK_TOKEN даёт город, подписчиков и точные даты.\n"
            "Пример: /vk durov")
        return
    await run_search(update, target, modules=["vk", "geo", "telegram"], deep=False)


async def cmd_max(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Мессенджер MAX: канал/бот по @нику и ссылки на профиль max.ru/u/…"""
    if not await _guard(update):
        return
    target = " ".join(context.args).strip().lstrip("@")
    if not target:
        await update.message.reply_text(
            "Использование: /max <ник|ссылка>\n"
            "Проверяю в мессенджере MAX: канал/бот по @нику, персональную ссылку max.ru/u/<hash>.\n"
            "Важно: у личных профилей MAX нет публичных @username — человека можно найти "
            "только по персональной ссылке или по номеру из контактов (честно помечаю это в отчёте).\n"
            "Пример: /max news")
        return
    await run_search(update, target, modules=["max", "telegram"], deep=False)


async def cmd_changes(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Что менялось у цели: ник, имя, био, город — по прошлым проверкам."""
    if not await _guard(update):
        return
    target = " ".join(context.args).strip()
    if not target:
        await update.message.reply_text("Использование: /changes <цель>\n"
                                        "Покажу, что изменилось с прошлых проверок (ник, имя, био, город, "
                                        "подписчики). Первое наблюдение добавляется каждым поиском.")
        return
    from ..insights import format_changes

    store = get_store()
    changes = store.profile_changes(target, limit=20)
    stats = store.snapshot_stats(target)
    latest = store.latest_snapshots(target)
    text = format_changes(changes, target)
    if stats["total"]:
        text += f"\n\nНаблюдений: {stats['total']}"
        if latest:
            text += "\nПоследние значения:\n" + "\n".join(
                f"• <code>{html.escape(k)}</code> = {html.escape(v[:80])}" for k, v in sorted(latest.items())[:8])
    await update.message.reply_text(text[:4000], parse_mode=ParseMode.HTML)


async def cmd_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (update.message.text or "").strip()
    if not text or text.startswith("/"):
        return
    in_group = update.message.chat.type != "private"
    if in_group and f"@{context.bot.username}" not in text:
        return
    text = text.replace(f"@{context.bot.username}", "").strip()
    if text:
        await run_search(update, text)


async def cmd_cancel(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _guard(update):
        return
    event = RUNNING.get(update.effective_chat.id)
    if not event:
        await update.message.reply_text("Нет активного поиска.")
        return
    event.set()
    await update.message.reply_text("⏹ Останавливаю поиск — уже проверенные источники останутся в отчёте.")


# ───────────────────────────── Telegram-разведка ─────────────────────────────
async def cmd_id(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Telegram-разведка: t.me-карточка + (при MTProto) ID, DC и поиск по сообщениям.

    Флаг ``--deep`` в аргументах оставлен для совместимости: модуль и так проверяет
    всё, что доступно с текущими настройками.
    """
    args = context.args or []
    target = " ".join(item for item in args if item not in ("--deep", "-d")).strip()
    if not target:
        await update.message.reply_text(
            "Укажите @username, ссылку t.me/... или номер телефона.\n"
            "Флаг --deep включает поиск по двум разделам (текст/сообщения, если настроен MTProto).")
        return
    if not await _guard(update):
        return
    settings = get_settings()
    message = await update.message.reply_text(
        f"📡 Telegram-разведка: <code>{html.escape(target)}</code>", parse_mode=ParseMode.HTML,
        disable_web_page_preview=True)
    await _typing(update)
    progress = Progress(message, target)
    from ..modules.base import Context as ModuleContext
    from ..modules.telegram import TelegramModule

    async with HttpClient(settings) as http:
        module_ctx = ModuleContext(settings=settings, http=http, store=get_store(),
                                   options={"deep": True, "use_keys": True, "smtp": False},
                                   emit=progress.on_event)
        result = ModuleResult(module="telegram", target=target)
        try:
            await TelegramModule().run(module_ctx, target, result)
        except Exception as exc:
            await message.edit_text(f"⚠️ Ошибка Telegram-модуля: {html.escape(str(exc))[:300]}")
            return

    # ── собираем карточку ──
    lines = [f"📡 <b>Telegram:</b> <code>{html.escape(target)}</code>", ""]
    profile = next((f for f in result.findings if f.kind == "profile"), None)
    if profile:
        lines.append(f"<b>{html.escape(profile.title)}</b>")
        data = profile.data or {}
        for key, label in (("name", "Имя"), ("kind", "Тип"), ("bio", "Описание"),
                           ("subscribers", "Подписчиков"), ("id", "ID"), ("phone", "Телефон"),
                           ("dc_id", "DC"), ("status", "Статус"), ("premium", "Premium"),
                           ("common_chats_count", "Общих чатов")):
            value = data.get(key)
            if value not in (None, "", False, 0, []):
                lines.append(f"• {label}: {html.escape(str(value)[:180])}")
        if data.get("scam") or data.get("fake"):
            lines.append("⚠️ Аккаунт помечен Telegram как скам/фейк")
    for finding in result.findings:
        if finding is profile or finding.kind == "link":
            continue
        lines.append(f"\n<b>{html.escape(finding.source)}</b>: {html.escape(finding.title[:200])}")
        if finding.url:
            lines.append(f'   <a href="{html.escape(finding.url)}">открыть</a>')
        posts = (finding.data or {}).get("posts")
        if posts:
            for post in posts[:3]:
                lines.append(f"   • {html.escape(post[:160])}")
        messages = (finding.data or {}).get("messages")
        if messages:
            for item in messages[:5]:
                lines.append(f"   • [{html.escape(str(item.get('date', ''))[:10])}] "
                             f"{html.escape(str(item.get('text', ''))[:160])}")
    unavailable = [s for s in result.statuses if s.status in ("unsupported", "blocked", "error")]
    if unavailable:
        lines.append("\n— недоступно —")
        for status in unavailable[:5]:
            lines.append(f"⛔ {html.escape(status.source)}: {html.escape((status.detail or status.error)[:160])}")
    if not result.findings:
        lines.append("Публичных данных не найдено.")

    keyboard = None
    if profile:
        username = (profile.data or {}).get("username") or (
            target.lstrip("@") if not target.startswith("+") else "")
        if username:
            keyboard = InlineKeyboardMarkup([[
                InlineKeyboardButton("🔎 Полный поиск по логину", callback_data=f"pivot:telegram:{username[:44]}"),
                InlineKeyboardButton("📈 Граф", callback_data="graph:last"),
            ]])
    await message.edit_text("\n".join(lines)[:4000], parse_mode=ParseMode.HTML,
                            disable_web_page_preview=True, reply_markup=keyboard)


# ───────────────────────────── пароли ─────────────────────────────
async def cmd_password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _guard(update):
        return
    password = context.args[0] if context.args else ""
    if not password:
        await update.message.reply_text("Использование: /password мойпароль\n"
                                        "Наружу уходят только первые 5 символов SHA-1 (k-anonymity).")
        return
    from ..modules.base import Context as ModuleContext
    from ..modules.breach import check_password_pwned

    settings = get_settings()
    async with HttpClient(settings) as http:
        module_ctx = ModuleContext(settings=settings, http=http, store=get_store())
        result = await check_password_pwned(password, module_ctx)
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


# ───────────────────────────── наблюдение ─────────────────────────────
async def cmd_watch(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _guard(update):
        return
    store = get_store()
    chat_id = update.effective_chat.id
    args = context.args or []
    action = (args[0].lower() if args else "list")
    rest = " ".join(args[1:]).strip()

    if action == "add":
        if not rest:
            await update.message.reply_text("Использование: /watch add ivan.petrov@example.com")
            return
        store.watch_add(rest, detect_target_type(rest), note=f"tg:{_user_id(update)}",
                        chat_id=chat_id, interval_hours=float(get_settings().watch_interval))
        await update.message.reply_text(
            f"👁 В наблюдении: <code>{html.escape(rest)}</code>\n"
            f"Проверка: /watch check вручную"
            + (f" или автоматически каждые {get_settings().watch_interval:g} ч"
               if get_settings().watch_interval else "")
            + ".\nСообщаю только о НОВЫХ находках.", parse_mode=ParseMode.HTML)

    elif action in ("list", "ls"):
        rows = store.watch_list(chat_id=chat_id)
        if not rows:
            await update.message.reply_text("Список наблюдения пуст: /watch add <цель>")
            return
        lines = ["<b>Наблюдение:</b>"]
        for row in rows:
            lines.append(f"• <code>{html.escape(row['target'])}</code> ({row['target_type']}) — "
                         f"проверка: {(row['last_check'] or 'ещё не было')[:16]}")
        await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.HTML)

    elif action in ("rm", "del", "remove"):
        if not rest:
            await update.message.reply_text("Использование: /watch rm <цель>")
            return
        store.watch_remove_target(rest)
        await update.message.reply_text(f"Удалено из наблюдения: {html.escape(rest)}")

    elif action == "check":
        rows = store.watch_list(chat_id=chat_id)
        if not rows:
            await update.message.reply_text("Список наблюдения пуст.")
            return
        message = await update.message.reply_text(f"👁 Проверяю {len(rows)} цел(ей) …")
        results = await watch_check_all(store=store, engine=Engine(), chat_id=chat_id, limit=10)
        await message.edit_text(_format_watch_results(results)[:4000], parse_mode=ParseMode.HTML)
    else:
        await update.message.reply_text(
            "Команды: /watch add <цель> | /watch list | /watch check | /watch rm <цель>")


def _format_watch_results(results: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for item in results:
        target = html.escape(str(item.get("target"))[:60])
        if item.get("error"):
            lines.append(f"⚠️ <code>{target}</code> — ошибка: {html.escape(str(item['error'])[:120])}")
            continue
        if item.get("first_time"):
            lines.append(f"🆕 <code>{target}</code> — первая проверка, находок {item.get('findings', 0)} "
                         f"(покрытие {item.get('coverage', 0)}%)")
        elif item.get("new"):
            lines.append(f"🔔 <code>{target}</code> — новых данных: {len(item['new'])}")
            lines.extend(f"   • {html.escape(str(entry)[:120])}" for entry in item["new"][:6])
        else:
            lines.append(f"✅ <code>{target}</code> — без изменений (находок {item.get('findings', 0)})")
    return "\n".join(lines) or "Нечего проверять."


# ───────────────────────────── настройки/модули ─────────────────────────────
async def cmd_settings(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _guard(update):
        return
    prefs = get_store().get_prefs(_user_id(update))
    await update.message.reply_text(ui.prefs_text(prefs), parse_mode=ParseMode.HTML,
                                    reply_markup=ui.settings_keyboard(prefs))


async def cmd_modules(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _guard(update):
        return
    store = get_store()
    prefs = store.get_prefs(_user_id(update))
    if context.args:
        selected = [name.strip() for name in " ".join(context.args).replace(",", " ").split() if name.strip()]
        unknown = [name for name in selected if name not in dict(ui.MODULES)]
        if unknown:
            await update.message.reply_text(
                "Неизвестные модули: " + ", ".join(unknown) + "\nДоступны: "
                + ", ".join(name for name, _ in ui.MODULES))
            return
        store.set_prefs(_user_id(update), modules=selected or None)
        await update.message.reply_text(
            "Модули сохранены: " + (", ".join(selected) if selected else "авто (по типу цели)"))
        return
    await update.message.reply_text(
        "Выберите модули кнопками — набор сохранится для ваших поисков "
        "(«Сбросить» вернёт автоопределение по типу цели).",
        reply_markup=ui.modules_keyboard(prefs.get("modules")))


async def cmd_report(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _guard(update):
        return
    search_id = (context.args[0] if context.args else "").strip()
    if not search_id:
        await update.message.reply_text("Использование: /report <id поиска>\n"
                                        "ID виден в сводке и в /history (можно указывать начало).")
        return
    store = get_store()
    report = ui.recall(search_id) or load_report(search_id, store)
    if report is None and len(search_id) >= 6:
        for row in store.history(limit=50):
            if row["id"].startswith(search_id):
                report = load_report(row["id"], store)
                break
    if report is None:
        await update.message.reply_text("Отчёт не найден. Посмотрите /history.")
        return
    text, page, pages = ui.summary_text(report)
    await update.message.reply_text(text[:4000], parse_mode=ParseMode.HTML,
                                    reply_markup=ui.report_keyboard(report, page, pages,
                                                                    web_url=get_settings().public_url),
                                    disable_web_page_preview=True)


# ───────────────────────────── история/статистика ─────────────────────────────
async def cmd_history(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _guard(update):
        return
    rows = get_store().history(limit=15)
    if not rows:
        await update.message.reply_text("История пуста.")
        return
    lines = ["<b>Последние поиски</b> (нажмите /report &lt;id&gt; чтобы открыть заново)"]
    for row in rows:
        lines.append(f"• <code>{row['id'][:8]}</code> <code>{html.escape(row['target'][:38])}</code> "
                     f"({row['target_type']}) — находок {row['findings']}, покрытие {row['coverage']}%, "
                     f"{row['started_at'][:16]}")
    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.HTML)


async def cmd_stats(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _guard(update):
        return
    from ..core.registry import count_sources

    stats = get_store().stats()
    counts = count_sources()
    await update.message.reply_text(
        f"<b>База OsintX</b>\nПоисков: {stats['searches']}\nНаходок: {stats['findings']}\n"
        f"Сущностей: {stats['entities']}\nСвязей: {stats['edges']}\n"
        f"Внешних баз: {len(stats['datasets'])}\n\n"
        f"<b>Источники:</b> логины {counts['username']}, email {counts['email']}, телефоны {counts['phone']}\n"
        f"БД: <code>{html.escape(stats['db_path'])}</code>",
        parse_mode=ParseMode.HTML)


async def cmd_sources(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _guard(update):
        return
    from ..core.registry import count_sources

    counts = count_sources()
    await update.message.reply_text(
        f"Источников в реестре:\n• логины: {counts['username']}\n• email: {counts['email']}\n"
        f"• телефоны: {counts['phone']}\n\nБольше площадок — импортом публичных датасетов с ПК: "
        f"osintx sources --import-wmn (≈700 сайтов WhatsMyName) и --import-sherlock (≈400).\n"
        f"Плюс API-проверки в коде: GitHub, GitLab, Keybase, "
        f"Reddit, Hacker News, StackOverflow, DNS/RDAP/crt.sh, Shodan InternetDB, Tor Onionoo, "
        f"XposedOrNot, Wikidata, OpenSanctions, Blockstream, Blockchair и другие.")


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
    for hit in hits[:20]:
        lines.append(f"• [{html.escape(str(hit.get('dataset')))}] "
                     f"<code>{html.escape(str(hit.get('value')))}</code> "
                     f"{html.escape(str(hit.get('extra') or '')[:80])}")
    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.HTML)


async def cmd_graph(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _guard(update):
        return
    target = " ".join(context.args).strip()
    if not target:
        await update.message.reply_text("Использование: /graph ivan.petrov@example.com")
        return
    await _send_graph(update.effective_chat.id, context, target)


async def _send_graph(chat_id: int, context: ContextTypes.DEFAULT_TYPE, target: str) -> None:
    store = get_store()
    payload = store.entity_neighbours(detect_target_type(target), target, depth=2)
    if not payload["edges"]:
        await context.bot.send_message(chat_id, "Связей нет — сначала выполните поиск по этой цели.")
        return
    lines = [f"🔗 <b>Связи для</b> <code>{html.escape(target)}</code> ({len(payload['edges'])}):"]
    for edge in payload["edges"][:25]:
        lines.append(f"• <code>{html.escape(edge['src'])}</code> —{html.escape(str(edge['relation']))}→ "
                     f"<code>{html.escape(edge['dst'])}</code>")
    mermaid = ["graph LR"] + [f'    "{edge["src"]}" -->|{edge["relation"]}| "{edge["dst"]}"'
                              for edge in payload["edges"][:40]]
    await context.bot.send_message(chat_id, "\n".join(lines)[:3500], parse_mode=ParseMode.HTML)
    await context.bot.send_message(chat_id, "```\n" + "\n".join(mermaid)[:3300] + "\n```",
                                   parse_mode=ParseMode.MARKDOWN_V2)


# ───────────────────────────── кнопки ─────────────────────────────
def _send_report_file(chat_id: int, context: ContextTypes.DEFAULT_TYPE, report, fmt: str):
    func, ext = FORMATS[fmt]
    content = func(report)
    buf = io.BytesIO(content.encode("utf-8"))
    buf.name = f"osintx_{report.target_type}_{report.search_id}.{ext}"
    return buf


async def cmd_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    data = query.data or ""
    if data == "noop":
        await query.answer()
        return

    # ── скачивание файлов отчёта ──
    if data.startswith("dl:"):
        await query.answer("Готовлю файл…")
        _, fmt, search_id = data.split(":", 2)
        report = ui.recall(search_id) or load_report(search_id, get_store())
        if report is None:
            await query.message.reply_text("Отчёт не найден (истёк). Запустите поиск заново.")
            return
        buf = _send_report_file(query.message.chat_id, context, report, fmt)
        await query.message.reply_document(buf, filename=buf.name,
                                          caption=f"Отчёт по {report.target} ({fmt.upper()})")
        return

    # ── пагинация сводки ──
    if data.startswith("page:"):
        _, search_id, page_raw = data.split(":", 2)
        report = ui.recall(search_id) or load_report(search_id, get_store())
        if report is None:
            await query.answer("Отчёт больше недоступен", show_alert=True)
            return
        await query.answer()
        text, page, pages = ui.summary_text(report, page=int(page_raw))
        try:
            await query.message.edit_text(text[:4000], parse_mode=ParseMode.HTML,
                                          reply_markup=ui.report_keyboard(report, page, pages,
                                                                          web_url=get_settings().public_url),
                                          disable_web_page_preview=True)
        except Exception:
            pass
        return

    # ── пивот: искать найденную сущность дальше ──
    if data.startswith("pivot:"):
        _, category, value = data.split(":", 2)
        await query.answer(f"Ищу {value} …")
        fake_update = _QueryAsUpdate(query)
        await run_search(fake_update, value, target_type=category, use_prefs=True)  # type: ignore[arg-type]
        return

    # ── глубже / граф ──
    if data.startswith("deep:"):
        search_id = data.split(":", 1)[1]
        report = ui.recall(search_id) or load_report(search_id, get_store())
        await query.answer("Запускаю глубокий поиск…")
        await run_search(_QueryAsUpdate(query), report.target if report else "", deep=True)  # type: ignore[arg-type]
        return
    if data.startswith("graph:"):
        search_id = data.split(":", 1)[1]
        await query.answer()
        if search_id == "last":
            await query.message.reply_text("Сначала выполните поиск, затем нажмите «Граф».")
            return
        report = ui.recall(search_id) or load_report(search_id, get_store())
        if report is None:
            await query.message.reply_text("Отчёт не найден.")
            return
        await _send_graph(query.message.chat_id, context, report.target)
        return

    # ── выбор модулей ──
    if data.startswith("mod:"):
        user_id = query.from_user.id
        store = get_store()
        prefs = store.get_prefs(user_id)
        selected = list(prefs.get("modules") or [])
        name = data.split(":", 1)[1]
        if name in selected:
            selected.remove(name)
        else:
            selected.append(name)
        store.set_prefs(user_id, modules=selected or None)
        await query.answer(f"Модули: {', '.join(selected) if selected else 'авто'}")
        try:
            await query.message.edit_reply_markup(ui.modules_keyboard(selected))
        except Exception:
            pass
        return
    if data == "mod_reset":
        get_store().set_prefs(query.from_user.id, modules=None)
        await query.answer("Модули: авто по типу цели")
        try:
            await query.message.edit_reply_markup(ui.modules_keyboard(None))
        except Exception:
            pass
        return
    if data == "run_modules":
        prefs = get_store().get_prefs(query.from_user.id)
        chosen = ", ".join(prefs.get("modules") or []) or "авто (по типу цели)"
        await query.answer("Отправьте цель сообщением", show_alert=True)
        await query.message.reply_text(
            f"Модули для поиска: <b>{html.escape(chosen)}</b>\n"
            "Отправьте цель обычным сообщением (или /search <цель>) — поиск пойдёт с этим набором.",
            parse_mode=ParseMode.HTML)
        return

    # ── настройки ──
    if data.startswith("set:"):
        key = data.split(":", 1)[1]
        user_id = query.from_user.id
        store = get_store()
        if key == "reset":
            store.set_prefs(user_id, deep=False, variants=False, save=True, use_keys=True, modules=None)
            await query.answer("Настройки сброшены")
        else:
            prefs = store.get_prefs(user_id)
            store.set_prefs(user_id, **{key: not prefs.get(key, False)})
            await query.answer("Обновлено")
        prefs = store.get_prefs(user_id)
        try:
            await query.message.edit_text(ui.prefs_text(prefs), parse_mode=ParseMode.HTML,
                                          reply_markup=ui.settings_keyboard(prefs))
        except Exception:
            pass
        return

    await query.answer()


class _QueryAsUpdate:
    """Позволяет запустить поиск из нажатия кнопки, как если бы пришло сообщение."""

    def __init__(self, query):
        self.callback_query = query
        self.effective_user = query.from_user
        self.effective_chat = query.message.chat
        self.effective_message = query.message
        self.message = query.message


async def cmd_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Ошибки не должны молча killить бота и не должны пугать трейсбеком."""
    error = context.error
    text = str(error)
    if isinstance(error, NetworkError) or "getaddrinfo" in text or "ConnectError" in text:
        log.error("сетевая ошибка при обращении к Telegram: %s", text)
        if not getattr(cmd_error, "_hint_shown", False):
            cmd_error._hint_shown = True       # подсказку печатаем один раз за запуск
            print(explain_network_error(error))
        return
    log.error("Ошибка обработки: %s", error, exc_info=error)


# ───────────────────────────── фоновые задачи ─────────────────────────────
async def run_watch_cycle(bot) -> list[dict[str, Any]]:
    """Один цикл наблюдения: проверить «просроченные» цели и уведомить владельцев.

    Возвращает результаты проверки (для тестов и логов).
    """
    store = get_store()
    due = store.watch_due()
    if not due:
        return []
    log.info("проверка наблюдения: %s цел(ей)", len(due))
    results = await watch_check_all(store=store, engine=Engine(), only_due=True, limit=5)
    await notify_watch_results(bot, results)
    return results


async def notify_watch_results(bot, results: list[dict[str, Any]]) -> None:
    """Отправляет уведомление только если по цели появились новые данные."""
    for item in results:
        chat_id = item.get("chat_id")
        if not chat_id or item.get("error") or item.get("first_time") or not item.get("new"):
            continue
        text = (f"🔔 <b>Новые данные по цели наблюдения</b>\n"
                f"<code>{html.escape(str(item['target']))}</code> — новых находок: {len(item['new'])}\n"
                + "\n".join(f"• {html.escape(str(entry)[:120])}" for entry in item["new"][:8]))
        try:
            await bot.send_message(chat_id, text[:4000], parse_mode=ParseMode.HTML)
        except Exception as exc:
            log.warning("не удалось отправить уведомление в %s: %s", chat_id, exc)


async def watch_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Задача для JobQueue (если установлен apscheduler)."""
    await run_watch_cycle(context.bot)


async def _watch_loop(app: Application, interval_hours: float) -> None:
    """Запасной планировщик без apscheduler: обычная asyncio-задача."""
    await asyncio.sleep(120)  # даём боту стартовать
    while True:
        try:
            await run_watch_cycle(app.bot)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # цикл не должен умирать из-за одной ошибки
            log.warning("ошибка в цикле наблюдения: %s", exc)
        await asyncio.sleep(max(900.0, float(interval_hours) * 3600))


def _job_queue(app: Application):
    """Возвращает JobQueue, если apscheduler установлен (иначе None, без предупреждений)."""
    try:
        import apscheduler  # noqa: F401
    except ImportError:
        return None
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")   # PTB ругается, если JobQueue не настроен
        try:
            return app.job_queue
        except (RuntimeError, AttributeError):
            return None


def setup_watch_scheduler(app: Application, interval_hours: float) -> str:
    """Ставит фоновую проверку наблюдений.

    Возвращает режим: ``job_queue`` (apscheduler), ``task`` (встроенный цикл) или ``off``.
    apscheduler — необязательная зависимость: без него всё работает через asyncio-задачу.
    """
    if not interval_hours:
        return "off"
    job_queue = _job_queue(app)
    if job_queue is not None:
        job_queue.run_repeating(watch_job, interval=timedelta(hours=interval_hours),
                                first=timedelta(minutes=2), name="osintx-watch")
        return "job_queue"
    try:
        app.create_task(_watch_loop(app, interval_hours), name="osintx-watch")
        return "task"
    except Exception as exc:  # pragma: no cover - экзотические сборки PTB
        log.warning("не удалось включить фоновое наблюдение: %s", exc)
        return "off"


async def post_init(application: Application) -> None:
    """После старта: включаем фоновое наблюдение и логируем, кто мы."""
    settings = get_settings()
    mode = setup_watch_scheduler(application, settings.watch_interval)
    log.info("наблюдение: режим %s, интервал %s ч", mode, settings.watch_interval)
    try:
        me = await application.bot.get_me()
        log.info("бот запущен: @%s", me.username)
    except Exception as exc:
        log.warning("не удалось получить данные бота: %s", exc)


# ───────────────────────────── сборка и запуск ─────────────────────────────
def _socks_support() -> bool:
    """Установлен ли socksio (нужен httpx для socks4/socks5-прокси)."""
    try:
        import socksio  # noqa: F401
        return True
    except ImportError:
        return False


def proxy_hint(proxy: str) -> str:
    """Разбирает настройку прокси: (можно_использовать, предупреждение)."""
    proxy = (proxy or "").strip()
    if not proxy:
        return True, ""
    if proxy.startswith(("socks4", "socks5")) and not _socks_support():
        return False, ("Для SOCKS-прокси нужен пакет socksio:  pip install socksio\n"
                       "   Либо укажите HTTP-прокси:  TELEGRAM_PROXY=http://host:port")
    if not proxy.startswith(("http://", "https://", "socks4://", "socks5://")):
        return False, ("Адрес прокси должен начинаться с http://, https://, socks4:// или socks5://\n"
                       f"   сейчас: {proxy!r}")
    return True, ""


def build_application(token: str, *, proxy: str | None = None) -> Application:
    """Собирает приложение со всеми командами (без обращения к сети).

    ``proxy`` (или TELEGRAM_PROXY/OSINTX_PROXY из окружения) направляет запросы к
    Telegram через http/socks5-прокси — нужно там, где Telegram блокируется.
    """
    settings = get_settings()
    proxy = proxy if proxy is not None else settings.telegram_proxy
    builder = Application.builder().token(token).concurrent_updates(True).post_init(post_init)
    if proxy:
        usable, hint = proxy_hint(proxy)
        if not usable:
            raise RuntimeError(f"Прокси настроен неверно: {hint}")
        builder = builder.proxy(proxy).get_updates_proxy(proxy)
    app = builder.build()
    commands = [
        CommandHandler("start", cmd_start), CommandHandler("help", cmd_start),
        CommandHandler("search", cmd_search), CommandHandler("deep", cmd_deep),
        CommandHandler("id", cmd_id), CommandHandler("password", cmd_password),
        CommandHandler("history", cmd_history), CommandHandler("stats", cmd_stats),
        CommandHandler("sources", cmd_sources), CommandHandler("dataset_search", cmd_dataset_search),
        CommandHandler("graph", cmd_graph), CommandHandler("watch", cmd_watch),
        CommandHandler("settings", cmd_settings), CommandHandler("modules", cmd_modules),
        CommandHandler("report", cmd_report), CommandHandler("cancel", cmd_cancel),
        CommandHandler("geo", cmd_geo), CommandHandler("changes", cmd_changes),
        CommandHandler("vk", cmd_vk), CommandHandler("max", cmd_max),
    ]
    for name in FORCED_TYPE:
        commands.append(CommandHandler(name, cmd_typed))
    for handler in commands:
        app.add_handler(handler)
    app.add_handler(CallbackQueryHandler(cmd_callback))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, cmd_text))
    app.add_error_handler(cmd_error)
    return app


async def _probe_token(token: str) -> tuple[bool, str]:
    """Реальная проверка токена: getMe + доступность api.telegram.org."""
    try:
        from telegram import Bot
        bot = Bot(token)
        me = await bot.get_me()
        return True, (f"✅ Токен рабочий. Бот: @{me.username} "
                      f"({me.first_name or 'без имени'}, id={me.id})")
    except Exception as exc:
        name = type(exc).__name__
        text = str(exc)[:200]
        if "Unauthorized" in text or "401" in text:
            return False, f"❌ Токен неверный или отозван: {text}"
        if "ConnectError" in name or "Timeout" in name or "NetworkError" in name:
            return False, (f"❌ Не удалось связаться с api.telegram.org ({name}: {text}).\n"
                           "   Проверьте интернет/прокси. Из ограниченных сетей (например, песочниц "
                           "с whitelist-прокси) Telegram API недоступен — запускайте бота на своей "
                           "машине или VPS, либо укажите прокси в OSINTX_PROXY.")
        return False, f"❌ Ошибка проверки токена: {name}: {text}"


def check_bot(args) -> int:
    """osintx bot --check — проверить токен и настройки, ничего не запуская."""
    settings = get_settings()
    token = args.token or settings.bot_token
    with_net = getattr(args, "net", False)
    print("Проверка настроек Telegram-бота\n" + "-" * 40)
    print(f"токен: {'задан' if token else 'НЕ ЗАДАН (получить у @BotFather)'}"
          + (f" ({token[:10]}…)" if token else ""))
    print(f"ограничение доступа: {settings.allowed_ids or 'нет (бот открыт для всех)'}")
    print(f"MTProto: {'настроен' if settings.tg_api_id and settings.tg_api_hash else 'не настроен'}")
    print(f"фоновая проверка наблюдения: "
          f"{'каждые %g ч' % settings.watch_interval if settings.watch_interval else 'выключена'}")
    print(f"прокси для Telegram: {settings.telegram_proxy or 'не используется'}")
    if settings.telegram_proxy:
        usable, hint = proxy_hint(settings.telegram_proxy)
        print(f"   проверка прокси: {'✅ можно использовать' if usable else '❌ ' + hint}")
    print(f"каталог данных: {settings.data_dir}")
    if with_net:
        report, _ok = diagnose()
        print("\n" + report)
    if not token:
        print("\nДобавьте в .env:  TELEGRAM_BOT_TOKEN=123456:AA...\n"
              "Или запустите мастер: osintx init")
        return 1
    ok, message = asyncio.run(_probe_token(token))
    print("\n" + message)
    if ok:
        print("\nЗапуск:  python bot.py   (или osintx bot)")
    else:
        print(explain_network_error(message))
        if not with_net:
            print("\nПодробная диагностика сети:  python bot.py --net")
    return 0 if ok else 1


def _cli_token(argv: list[str]) -> str:
    for index, item in enumerate(argv):
        if item == "--token" and index + 1 < len(argv):
            return argv[index + 1].strip()
    return ""


def main() -> int:
    settings = get_settings()
    import sys
    if "--net" in sys.argv:
        report, ok = diagnose()
        print(report)
        return 0 if ok else 1
    if "--check" in sys.argv:
        from argparse import Namespace
        return check_bot(Namespace(token=_cli_token(sys.argv), net="--net" in sys.argv))
    if not settings.bot_token:
        print("Не задан TELEGRAM_BOT_TOKEN. Добавьте токен от @BotFather в .env")
        print("Проверить настройки и токен без запуска:  osintx bot --check")
        return 1
    try:
        app = build_application(settings.bot_token)
    except RuntimeError as exc:
        print(f"❌ {exc}")
        return 1
    if settings.telegram_proxy:
        print(f"Прокси для Telegram: {settings.telegram_proxy}")
    print("OsintX-бот запущен. Команды: /help | Ctrl+C — остановить.")
    try:
        app.run_polling(allowed_updates=["message", "callback_query"], drop_pending_updates=True)
    except KeyboardInterrupt:
        print("\nОстановлено.")
        return 130
    except (NetworkError, ConnectionError, OSError) as exc:
        print(explain_network_error(exc))
        return 2
    except Exception as exc:
        text = str(exc)
        if "getaddrinfo" in text or "ConnectError" in text or "NetworkError" in text:
            print(explain_network_error(exc))
            return 2
        raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
