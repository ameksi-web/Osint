"""Telegram-модуль: реальные проверки по t.me, Fragment и (опционально) MTProto.

Что делается БЕЗ входа в аккаунт (публичные данные):
  * существование юзернейма/канала/бота: разбор t.me/<name> и t.me/s/<name>;
  * тип аккаунта (канал / группа / бот / пользователь), название, bio, число подписчиков,
    дата создания, аватар, признак верификации и скам-пометки;
  * проверка занятости/аукциона юзернейма через fragment.com (реальная площадка Telegram);
  * публичный веб-превью канала t.me/s/<name>: последние посты (автор сам их опубликовал).

С входом в аккаунт (MTProto, Telethon — нужны TG_API_ID/TG_API_HASH):
  * числовой ID и access_hash аккаунта, DC (дата-центр), флаги (premium, verified, scam);
  * количество общих чатов, статус (онлайн/недавно), bio целиком;
  * ГЛОБАЛЬНЫЙ ПОИСК сообщений по слову/номеру/email (то, что умеет Void OSINT);
  * разрешение числового ID → username и наоборот;
  * поиск по номеру телефона (если номер в контактах) — через ImportContacts.

Важно: без MTProto числовой ID «не вычисляется» — его невозможно получить из t.me.
Мы честно сообщаем об этом, а не выдумываем ID.
"""
from __future__ import annotations

import asyncio
import html
import re
from typing import Any

from ..core.models import Finding, ModuleResult, SourceStatus
from .base import Context, Module, add_edge, add_entity, entity_id

TG_META = re.compile(r'<meta property="(og:title|og:description|og:image|og:url)" content="([^"]*)"')
TG_TITLE = re.compile(r'<meta property="og:title" content="([^"]*)"')
TG_DESC = re.compile(r'<meta property="og:description" content="([^"]*)"')
TG_EXTRA = re.compile(r'class="tgme_page_extra">([^<]*)<')
TG_ACTION = re.compile(r'class="tgme_page_action">.*?<a[^>]*href="([^"]*)"', re.DOTALL)
TG_COUNTER = re.compile(r'<span class="counter_value">([^<]*)</span>\s*<span class="counter_type">([^<]*)</span>')
TG_POST = re.compile(r'<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>', re.DOTALL)
TG_POST_DATE = re.compile(r'<time datetime="([^"]+)"')
TG_SUBSCRIBERS = re.compile(r'([\d\s.,KkMmкК]+)\s*(subscribers|подписчик|участник|members)', re.IGNORECASE)


class TelegramModule(Module):
    name = "telegram"
    title = "Telegram: профиль, канал/бот, подписчики, fragment, MTProto-поиск"
    categories = ("telegram",)
    target_types = ("telegram", "phone", "username")

    async def run(self, ctx: Context, target: str, result: ModuleResult) -> None:
        username = _username_from_target(target)
        deep_enabled = ctx.settings.tg_api_id and ctx.settings.tg_api_hash

        if username:
            await self._public_page(ctx, username, result)
            await self._preview(ctx, username, result)
            await self._fragment(ctx, username, result)
        if ctx.settings.tg_api_id and ctx.settings.tg_api_hash:
            await self._mtproto(ctx, target, username, result)
        else:
            self.add_status(result, SourceStatus(
                source="mtproto", category="telegram", status="unsupported",
                detail="MTProto не настроен: нет TG_API_ID/TG_API_HASH. Без него недоступны числовой ID, DC, "
                       "глобальный поиск по сообщениям и разрешение номера в аккаунт. "
                       "Заполни TG_API_ID/TG_API_HASH в .env (my.telegram.org) — модуль включится автоматически."))
        if _looks_like_phone(target):
            self.add_status(result, SourceStatus(
                source="mtproto:phone-lookup", category="telegram",
                status="unsupported" if not deep_enabled else "skipped",
                detail="Поиск Telegram-аккаунта по номеру требует авторизованной сессии MTProto "
                       "(метод contacts.importContacts). Публичных способов нет — сторонние «боты-пробивы» "
                       "используют чужие сессии и нарушают ToS."))
        await self._dorks(ctx, target, username, result)

    # ───────────────────────── публичная страница t.me ─────────────────────────
    async def _public_page(self, ctx: Context, username: str, result: ModuleResult) -> None:
        url = f"https://t.me/{username}"
        resp = await ctx.http.get(url, retries=1)
        if resp.status_code == 404:
            self.add_finding(result, source="t.me", category="telegram", kind="meta", confidence="high",
                             title=f"Юзернейм @{username} свободен или не существует (t.me отдал 404)",
                             value=username, url=url, data={"exists": False},
                             evidence="HTTP 404 от t.me — страница профиля отсутствует", http_code=404)
            self.add_status(result, SourceStatus(source="t.me", category="telegram", status="not_found",
                                                 url=url, http_code=404))
            return
        if resp.error or resp.looks_blocked():
            self.add_status(result, SourceStatus(source="t.me", category="telegram",
                                                 status="blocked" if resp.looks_blocked() else "error",
                                                 url=url, http_code=resp.status_code or None,
                                                 error=resp.error or "страница-заглушка/капча"))
            return
        if resp.status_code != 200:
            self.add_status(result, SourceStatus(source="t.me", category="telegram", status="error", url=url,
                                                 http_code=resp.status_code))
            return

        body = resp.text
        meta = {k: html.unescape(v) for k, v in TG_META.findall(body)}
        title = html.unescape(TG_TITLE.search(body).group(1)) if TG_TITLE.search(body) else ""
        desc = html.unescape(TG_DESC.search(body).group(1)) if TG_DESC.search(body) else ""
        extra = html.unescape(TG_EXTRA.search(body).group(1)).strip() if TG_EXTRA.search(body) else ""
        counters = {html.unescape(t).strip(): html.unescape(v).strip() for v, t in TG_COUNTER.findall(body)}
        avatars = re.findall(r'background-image:url\(\'([^\']+)\'\)', body)
        kind = ("канал" if "subscribers" in extra.lower() or "подписчик" in extra.lower()
                else "группа/чат" if "members" in extra.lower() or "участник" in extra.lower()
                else "бот" if "bot" in title.lower() or username.lower().endswith("bot")
                else "пользователь")
        display_name = title.replace("Telegram: Contact @", "").replace(f"@{username}", "").strip(" :·-") or username
        subscriber_number = _parse_count(extra)

        self.add_finding(result, source="t.me", category="telegram", kind="profile", confidence="high",
                         title=f"Telegram {kind}: {display_name}" + (f" — {extra}" if extra else ""),
                         url=url, value=username,
                         data={"exists": True, "kind": kind, "name": display_name, "bio": desc,
                               "extra": extra, "subscribers": subscriber_number,
                               "counters": counters, "avatars": avatars[:3],
                               "verified": "verified" in body.lower() or "Verified" in body,
                               "scam_warning": bool(re.search(r"scam|fake|мошенн", body, re.IGNORECASE)),
                               "og": meta},
                         evidence=f"HTTP 200 t.me/{username}: og:title={title!r}, extra={extra!r}",
                         http_code=200)
        add_entity(result, "telegram", username, kind=kind, name=display_name,
                   subscribers=subscriber_number, bio=desc[:300])
        if desc:
            for email in re.findall(r"[\w.+-]+@[\w-]+\.[\w.]{2,}", desc):
                add_edge(result, entity_id("telegram", username), entity_id("email", email.lower()),
                         "email_in_telegram_bio", 0.7, "указан в описании Telegram-профиля")
            for site in re.findall(r"https?://([\w.-]+\.[a-z]{2,})", desc, re.IGNORECASE):
                add_edge(result, entity_id("telegram", username), entity_id("domain", site.lower()),
                         "link_in_telegram_bio", 0.6, "ссылка в описании профиля")
        self.add_status(result, SourceStatus(source="t.me", category="telegram", status="found", url=url,
                                             http_code=200, latency_ms=resp.latency_ms))

    # ───────────────────────── публичный превью (t.me/s) ─────────────────────────
    async def _preview(self, ctx: Context, username: str, result: ModuleResult) -> None:
        url = f"https://t.me/s/{username}"
        resp = await ctx.http.get(url, retries=1)
        if not resp.ok or resp.looks_blocked():
            self.add_status(result, SourceStatus(source="t.me/s", category="telegram",
                                                 status="blocked" if resp.looks_blocked() else "not_found",
                                                 url=url, http_code=resp.status_code or None,
                                                 error=resp.error))
            return
        body = resp.text
        posts_raw = TG_POST.findall(body)
        dates = TG_POST_DATE.findall(body)
        texts = []
        for raw in posts_raw[:12]:
            text = re.sub(r"<br\s*/?>", "\n", raw)
            text = re.sub(r"<[^>]+>", "", text)
            texts.append(html.unescape(text).strip()[:400])
        if not texts:
            self.add_status(result, SourceStatus(source="t.me/s", category="telegram", status="not_found",
                                                 url=url, http_code=resp.status_code,
                                                 detail="публичного превью нет (приватный профиль или пустой канал)"))
            return
        subscriber_guess = None
        m = re.search(r'<div class="tgme_channel_info_counter">\s*<span class="counter_value">([^<]*)</span>\s*'
                      r'<span class="counter_type">([^<]*)</span>', body)
        if m:
            subscriber_guess = _parse_count(f"{m.group(1)} {m.group(2)}")
        self.add_finding(result, source="t.me/s", category="telegram", kind="posts", confidence="high",
                         title=f"Публичные посты канала @{username}: получено {len(texts)} (последние: "
                               f"{dates[0][:10] if dates else '—'})",
                         url=url, value=username,
                         data={"posts": texts, "dates": dates[:12], "count": len(texts),
                               "subscribers": subscriber_guess,
                               "first_post_date": dates[-1][:10] if dates else None,
                               "last_post_date": dates[0][:10] if dates else None},
                         evidence=f"HTTP 200 t.me/s/{username}, найдено {len(texts)} блоков "
                                  f"tgme_widget_message_text", http_code=resp.status_code)
        add_entity(result, "telegram", username, posts_public=len(texts),
                   subscribers=subscriber_guess)
        self.add_status(result, SourceStatus(source="t.me/s", category="telegram", status="found", url=url,
                                             http_code=resp.status_code))
        joined = " ".join(texts)
        for email in set(re.findall(r"[\w.+-]+@[\w-]+\.[\w.]{2,}", joined)):
            add_edge(result, entity_id("telegram", username), entity_id("email", email.lower()),
                     "email_in_posts", 0.5, "адрес встречается в публичных постах канала")
        for phone in set(re.findall(r"\+?\d[\d\s().-]{8,}\d", joined)):
            digits = re.sub(r"\D", "", phone)
            if 9 <= len(digits) <= 15:
                add_edge(result, entity_id("telegram", username), entity_id("phone", "+" + digits),
                         "phone_in_posts", 0.5, "номер встречается в публичных постах канала")

    # ───────────────────────── fragment.com ─────────────────────────
    async def _fragment(self, ctx: Context, username: str, result: ModuleResult) -> None:
        url = f"https://fragment.com/username/{username}"
        resp = await ctx.http.get(url, retries=1)
        if resp.error or resp.looks_blocked():
            self.add_status(result, SourceStatus(source="fragment.com", category="telegram",
                                                 status="blocked" if resp.looks_blocked() else "error",
                                                 url=url, http_code=resp.status_code or None, error=resp.error))
            return
        body = resp.text
        low = body.lower()
        taken = "unavailable" in low or "sold" in low or "taken" in low or "on auction" in low or "for sale" in low
        price = re.search(r"([\d\s,.]+)\s*(TON|ton)", body)
        self.add_finding(result, source="fragment.com", category="telegram", kind="meta", confidence="medium",
                         title=(f"Fragment (аукцион Telegram-юзернеймов): статус — "
                                f"{'занят/на аукционе' if taken else 'доступен для покупки'}"
                                + (f", цена {price.group(0).strip()}" if price else "")),
                         url=url, value=username,
                         data={"taken": taken, "price": price.group(0).strip() if price else None,
                               "http_code": resp.status_code},
                         evidence=f"HTTP {resp.status_code} fragment.com/username/{username}; "
                                  f"маркеры занятости: taken={taken}",
                         http_code=resp.status_code)
        self.add_status(result, SourceStatus(source="fragment.com", category="telegram",
                                             status="found" if resp.ok else "error", url=url,
                                             http_code=resp.status_code or None))

    # ───────────────────────── MTProto (Telethon) ─────────────────────────
    async def _mtproto(self, ctx: Context, target: str, username: str | None, result: ModuleResult) -> None:
        try:
            from telethon import TelegramClient, functions, types  # noqa: F401
        except ImportError:
            self.add_status(result, SourceStatus(source="mtproto", category="telegram", status="unsupported",
                                                 detail="Telethon не установлен (pip install telethon)"))
            return
        session_path = str(ctx.settings.data_dir / ctx.settings.tg_session)
        client = TelegramClient(session_path, ctx.settings.tg_api_id, ctx.settings.tg_api_hash,
                                device_model="OsintX", system_version="1.0", app_version="1.0")
        try:
            await client.connect()
            if not await client.is_user_authorized():
                self.add_status(result, SourceStatus(
                    source="mtproto", category="telegram", status="unsupported",
                    detail=f"Сессия {session_path}.session не авторизована. Запусти один раз "
                           "`python -m osintx.tg_auth` (или `osintx tgauth`) и введи номер+код — "
                           "после этого MTProto-поиск заработает."))
                return
            await self._mtproto_entity(ctx, client, target, username, result)
            await self._mtproto_search(ctx, client, target, result)
            self.add_status(result, SourceStatus(source="mtproto", category="telegram", status="found",
                                                 detail="сессия активна, данные получены"))
        except Exception as exc:
            self.add_status(result, SourceStatus(source="mtproto", category="telegram", status="error",
                                                 error=f"{type(exc).__name__}: {exc}"[:250]))
        finally:
            try:
                await client.disconnect()
            except Exception:
                pass

    async def _mtproto_entity(self, ctx: Context, client, target: str, username: str | None,
                              result: ModuleResult) -> None:
        from telethon.tl.functions.users import GetFullUserRequest
        try:
            entity = await client.get_entity(username or target)
        except Exception as exc:
            self.add_status(result, SourceStatus(source="mtproto:entity", category="telegram", status="not_found",
                                                 error=f"get_entity: {type(exc).__name__}: {exc}"[:200]))
            return
        full = None
        try:
            full = await client(GetFullUserRequest(entity))
        except Exception:
            pass
        about = getattr(full, "full_user", None) and getattr(full.full_user, "about", None)
        common_chats = getattr(full.full_user, "common_chats_count", None) if getattr(full, "full_user", None) else None
        data = {
            "id": entity.id,
            "access_hash": getattr(entity, "access_hash", None),
            "username": getattr(entity, "username", None),
            "usernames": [getattr(u, "username", None) for u in (getattr(entity, "usernames", None) or [])],
            "first_name": getattr(entity, "first_name", None),
            "last_name": getattr(entity, "last_name", None),
            "title": getattr(entity, "title", None),
            "phone": getattr(entity, "phone", None),
            "bot": getattr(entity, "bot", None),
            "verified": getattr(entity, "verified", None),
            "scam": getattr(entity, "scam", None),
            "fake": getattr(entity, "fake", None),
            "premium": getattr(entity, "premium", None),
            "restricted": getattr(entity, "restricted", None),
            "lang_code": getattr(entity, "lang_code", None),
            "status": type(getattr(entity, "status", None)).__name__,
            "participants_count": getattr(entity, "participants_count", None),
            "dc_id": getattr(getattr(entity, "photo", None), "dc_id", None),
            "bio": about,
            "common_chats_count": common_chats,
            "birthday": str(getattr(full.full_user, "birthday", None)) if getattr(full, "full_user", None) else None,
            "personal_channel_id": getattr(getattr(full, "full_user", None), "personal_channel_id", None),
            "peer_type": type(entity).__name__,
        }
        title_bits = [data.get("title") or f"{data.get('first_name') or ''} {data.get('last_name') or ''}".strip(),
                      f"id={data['id']}"]
        if data.get("premium"):
            title_bits.append("premium")
        if data.get("scam") or data.get("fake"):
            title_bits.append("⚠ помечен как скам/фейк")
        self.add_finding(result, source="mtproto:entity", category="telegram", kind="profile", confidence="high",
                         title="Telegram MTProto: " + ", ".join(str(b) for b in title_bits if b),
                         url=f"https://t.me/{data['username']}" if data.get("username") else "",
                         value=str(data.get("id")), data=data,
                         evidence=f"users.GetFullUser → id={data['id']}, access_hash={data.get('access_hash')}, "
                                  f"dc_id={data.get('dc_id')}, common_chats={common_chats}")
        add_entity(result, "telegram_id", str(data["id"]), username=data.get("username"),
                   premium=data.get("premium"), dc=data.get("dc_id"), phone=data.get("phone"))
        if data.get("username"):
            add_edge(result, entity_id("telegram_id", str(data["id"])), entity_id("telegram", data["username"]),
                     "id_username", 1.0, "одна и та же сущность Telegram (MTProto)")
        if data.get("phone"):
            add_edge(result, entity_id("telegram_id", str(data["id"])), entity_id("phone", data["phone"]),
                     "bound_phone", 1.0, "номер привязан к аккаунту (виден через MTProto)")

    async def _mtproto_search(self, ctx: Context, client, query: str, result: ModuleResult) -> None:
        """Глобальный поиск по сообщениям — аналог поиска в Void OSINT."""
        from telethon import functions
        try:
            res = await client(functions.messages.SearchGlobalRequest(
                q=query, filter=None, min_date=None, max_date=None, offset_rate=0, offset_peer=None,
                offset_id=0, limit=30))
        except Exception as exc:
            self.add_status(result, SourceStatus(source="mtproto:search", category="telegram", status="error",
                                                 error=f"{type(exc).__name__}: {exc}"[:200]))
            return
        messages = getattr(res, "messages", []) or []
        chats = {getattr(c, "id", None): getattr(c, "title", None) or getattr(c, "username", None)
                 for c in (getattr(res, "chats", []) or [])}
        hits = []
        for m in messages:
            text = (getattr(m, "message", "") or "").strip()
            if not text:
                continue
            peer = getattr(m, "peer_id", None)
            chat_id = getattr(peer, "channel_id", None) or getattr(peer, "chat_id", None) or getattr(peer, "user_id", None)
            sender = None
            try:
                sender = await client.get_entity(getattr(m, "from_id", None) or peer)
            except Exception:
                pass
            hits.append({
                "text": text[:600],
                "date": str(getattr(m, "date", "")),
                "chat": chats.get(chat_id),
                "chat_id": chat_id,
                "message_id": getattr(m, "id", None),
                "sender_id": getattr(sender, "id", None),
                "sender_username": getattr(sender, "username", None),
                "link": (f"https://t.me/{chats.get(chat_id)}/{getattr(m, 'id', '')}"
                         if chats.get(chat_id) else None),
            })
        if not hits:
            self.add_status(result, SourceStatus(source="mtproto:search", category="telegram", status="not_found",
                                                 detail="messages.SearchGlobal не вернул сообщений"))
            return
        self.add_finding(result, source="mtproto:search", category="telegram", kind="messages", confidence="high",
                         title=f"Глобальный поиск Telegram: найдено {len(hits)} сообщений с упоминанием «{query}»",
                         url=hits[0].get("link") or "", value=query, data={"messages": hits},
                         evidence=f"messages.SearchGlobalRequest(q={query!r}, limit=30) → "
                                  f"{len(messages)} сообщений, {len(hits)} с текстом")
        for h in hits:
            if h.get("sender_username"):
                add_edge(result, entity_id("query", query), entity_id("telegram", h["sender_username"]),
                         "mentioned_in_telegram_message", 0.5, f"сообщение от {h['date']}")
        self.add_status(result, SourceStatus(source="mtproto:search", category="telegram", status="found",
                                             detail=f"{len(hits)} сообщений"))

    # ───────────────────────── dorks ─────────────────────────
    async def _dorks(self, ctx: Context, target: str, username: str | None, result: ModuleResult) -> None:
        q = username or target
        links = [
            f"https://www.google.com/search?q=site%3At.me+%22{q}%22",
            f"https://www.google.com/search?q=%22t.me%2F{q}%22",
            f"https://tgstat.ru/search?q={q}",
            f"https://telemetr.io/search?q={q}",
            f"https://tlgrm.ru/search?q={q}",
            f"https://lyzem.com/search?q={q}",
            f"https://xtea.io/ts_en.html#gsc.tab=0&gsc.q={q}",
        ]
        self.add_finding(result, source="tg-dorks", category="telegram", kind="link", confidence="low",
                         title="Аналитика и поиск по Telegram (tgstat/telemetr/lyzem) — ссылки для проверки",
                         value=q, url=links[0], data={"links": links},
                         evidence="внешние каталоги и поисковики Telegram-контента; автоматических выводов нет")


def _username_from_target(target: str) -> str | None:
    t = target.strip()
    low = t.lower()
    for prefix in ("https://t.me/", "http://t.me/", "https://telegram.me/", "t.me/", "telegram.me/",
                   "https://telegram.dog/", "telegram.dog/"):
        if low.startswith(prefix):
            t = t[len(prefix):]
            break
    t = t.split("?")[0].split("/")[0].strip()
    if t.startswith("@"):
        t = t[1:]
    if t.startswith("+") or t.isdigit() or _looks_like_phone(target):
        return None
    return t if re.fullmatch(r"[A-Za-z0-9_]{4,32}", t or "") else None


def _looks_like_phone(target: str) -> bool:
    digits = re.sub(r"\D", "", target)
    return target.strip().startswith("+") and 9 <= len(digits) <= 15


def _parse_count(value: str) -> int | None:
    if not value:
        return None
    m = re.search(r"([\d\s.,]+)\s*([KkMmкК]?)", value)
    if not m:
        return None
    number = m.group(1).replace(" ", "").replace(",", ".")
    try:
        num = float(number.rstrip("."))
    except ValueError:
        return None
    suffix = m.group(2).lower()
    if suffix in ("k", "к"):
        num *= 1_000
    elif suffix in ("m", "м"):
        num *= 1_000_000
    return int(num)
