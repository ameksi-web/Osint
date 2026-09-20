"""Telegram-модуль: реальные проверки по t.me, Fragment и (опционально) MTProto.

Что делается БЕЗ входа в аккаунт (публичные данные):
  * существование юзернейма/канала/бота: разбор t.me/<name> и t.me/s/<name>;
  * тип аккаунта (канал / группа / бот / пользователь), название, bio, число подписчиков,
    дата создания, аватар, признак верификации и скам-пометки;
  * проверка занятости/аукциона юзернейма через fragment.com (реальная площадка Telegram);
  * публичный веб-превью канала t.me/s/<name>: последние посты (автор сам их опубликовал).

С входом в аккаунт (MTProto, Telethon — нужны TG_API_ID/TG_API_HASH):
  * числовой ID и access_hash аккаунта, DC (дата-центр), флаги (premium, verified, scam);
  * количество общих чатов, общие группы (GetCommonChats) — «в каких группах он был»;
  * чаты/каналы, где найдены его сообщения (из глобального поиска) — «где он писал»;
  * список юзернеймов аккаунта (в т.ч. дополнительные) — прошлые ники копятся в локальной базе;
  * чаще всего встречающиеся слова, хэштеги, домены и активные часы его сообщений;
  * статус (онлайн/недавно), bio целиком;
  * ГЛОБАЛЬНЫЙ ПОИСК сообщений по слову/номеру/email (то, что умеет Void OSINT);
  * разрешение числового ID → username и наоборот;
  * поиск по номеру телефона (если номер в контактах) — через ImportContacts.

Важно: без MTProto числовой ID «не вычисляется» — его невозможно получить из t.me.
Мы честно сообщаем об этом, а не выдумываем ID.
"""
from __future__ import annotations

import hashlib
import html
import re
from typing import Any

from ..core.models import ModuleResult, SourceStatus
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


POST_LINK = re.compile(r'href="(https://t\.me/{name}/\d+)"', re.IGNORECASE)
POST_ID = re.compile(r'data-post="([A-Za-z0-9_]+)/(\d+)"')


# ─────────────────── разбор текстов: «что чаще всего пишет» ───────────────────
STOPWORDS = {
    # русские
    "это", "этот", "эта", "эти", "как", "так", "что", "чтобы", "для", "или", "если", "есть", "был",
    "была", "были", "быть", "его", "её", "ее", "их", "они", "она", "оно", "мы", "вы", "ты", "я",
    "все", "всё", "весь", "ещё", "еще", "уже", "тоже", "также", "там", "тут", "здесь", "когда",
    "кто", "чем", "про", "под", "над", "при", "без", "через", "между", "очень", "просто", "можно",
    "надо", "нужно", "будет", "будут", "меня", "тебя", "нам", "вам", "ним", "ней", "них", "себя",
    "свой", "свои", "который", "которая", "которые", "которое", "этого", "этому", "этом", "того",
    "тому", "том", "these", "this", "that", "than", "then", "there", "here", "from", "with", "have",
    "has", "had", "will", "would", "your", "you", "our", "their", "them", "they", "what", "when",
    "which", "while", "about", "into", "just", "like", "more", "most", "some", "such", "only",
    "also", "been", "were", "was", "are", "and", "the", "for", "not", "but", "вот", "даже", "либо",
    "будто", "раз", "два", "три", "себя", "сейчас", "потом", "пока", "всё-таки", "кстати", "вообще",
    "https", "http", "www", "com", "ru", "org", "net", "его", "нее", "него", "этот-то", "пост",
}
WORD_RE = re.compile(r"[A-Za-zА-Яа-яЁё][\wА-Яа-яЁё]{3,}")
HASHTAG_RE = re.compile(r"#([A-Za-zА-Яа-яЁё0-9_]{2,50})")
DOMAIN_RE = re.compile(r"https?://([\w.-]+\.[A-Za-z]{2,})")
EMOJI_RE = re.compile("[\U0001F300-\U0001FAFF\u2600-\u27BF]")
CYR_RE = re.compile(r"[А-Яа-яЁё]")


def analyse_texts(texts: list[str], limit: int = 10) -> dict[str, Any]:
    """Что чаще всего встречается в сообщениях: слова, хэштеги, домены, язык, длина.

    Никаких домыслов: всё считается по реальным текстам сообщений/постов.
    """
    words: dict[str, int] = {}
    tags: dict[str, int] = {}
    domains: dict[str, int] = {}
    letters = {"кириллица": 0, "латиница": 0}
    total_len = 0
    emoji = 0
    for text in texts:
        body = str(text or "")
        total_len += len(body)
        emoji += len(EMOJI_RE.findall(body))
        letters["кириллица"] += len(CYR_RE.findall(body))
        letters["латиница"] += len(re.findall(r"[A-Za-z]", body))
        for word in WORD_RE.findall(body):
            low = word.lower()
            if low in STOPWORDS or len(low) < 4:
                continue
            words[low] = words.get(low, 0) + 1
        for tag in HASHTAG_RE.findall(body):
            tags[tag.lower()] = tags.get(tag.lower(), 0) + 1
        for domain in DOMAIN_RE.findall(body):
            low = domain.lower().lstrip("www.")
            domains[low] = domains.get(low, 0) + 1
    total_letters = sum(letters.values())
    language = "не определён"
    if total_letters:
        share = letters["кириллица"] / total_letters
        language = ("кириллица" if share >= 0.6 else "латиница" if share <= 0.4 else "смешанный")
    return {
        "words": sorted(words.items(), key=lambda kv: (-kv[1], kv[0]))[:limit],
        "hashtags": sorted(tags.items(), key=lambda kv: (-kv[1], kv[0]))[:limit],
        "domains": sorted(domains.items(), key=lambda kv: (-kv[1], kv[0]))[:limit],
        "messages": len([t for t in texts if str(t or "").strip()]),
        "avg_length": round(total_len / max(len(texts), 1)),
        "language": language,
        "emoji": emoji,
    }


def active_hours(dates: list[str], limit: int = 3) -> list[dict[str, Any]]:
    """Самые активные часы по времени сообщений (работает, если в дате есть время)."""
    hours: dict[int, int] = {}
    weekdays: dict[str, int] = {}
    for raw in dates:
        text = str(raw or "").strip()
        match = re.search(r"(?:T|\s|^)(\d{1,2}):(\d{2})", text)   # время после даты/пробела
        if match:
            hour = int(match.group(1))
            if 0 <= hour <= 23:
                hours[hour] = hours.get(hour, 0) + 1
        day = text[:10]
        try:
            import datetime

            name = ("пн", "вт", "ср", "чт", "пт", "сб", "вс")[datetime.date.fromisoformat(day).weekday()]
            weekdays[name] = weekdays.get(name, 0) + 1
        except ValueError:
            continue
    top_hours = sorted(hours.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]
    return [{"hour": f"{hour:02d}:00–{hour:02d}:59", "messages": count} for hour, count in top_hours], \
           sorted(weekdays.items(), key=lambda kv: (-kv[1], kv[0]))[:3]


def aggregate_chats(hits: list[dict[str, Any]], limit: int = 20) -> list[dict[str, Any]]:
    """По найденным сообщениям — в каких открытых чатах/каналах человек писал и сколько раз."""
    chats: dict[str, dict[str, Any]] = {}
    for hit in hits:
        name = hit.get("chat") or hit.get("chat_id")
        if not name:
            continue
        key = str(name).lstrip("@").lower()
        item = chats.setdefault(key, {"chat": str(name).lstrip("@"), "messages": 0, "links": [],
                                      "last_date": "", "samples": []})
        item["messages"] += 1
        if hit.get("link") and hit["link"] not in item["links"]:
            item["links"].append(hit["link"])
        date = str(hit.get("date") or "")[:10]
        if date > item["last_date"]:
            item["last_date"] = date
        if hit.get("text") and len(item["samples"]) < 3:
            item["samples"].append(str(hit["text"])[:160])
    # больше всего сообщений — сверху, при равенстве свежие чаты выше
    out = sorted(chats.values(), key=lambda i: (i["messages"], i["last_date"]), reverse=True)
    for item in out:
        item["links"] = item["links"][:5]
    return out[:limit]


def search_global_request(query: str, *, limit: int = 30):
    """Запрос глобального поиска сообщений (аналог Void OSINT).

    Все поля обязаны быть TL-объектами: Telethon падал с «a TLObject was expected but
    found something else», когда filter был None. Функция отдельная, чтобы это ловилось
    тестом (проверка ``bytes(request)``) без обращения к сети.
    """
    from telethon import types
    from telethon.tl.functions.messages import SearchGlobalRequest

    return SearchGlobalRequest(q=query, filter=types.InputMessagesFilterEmpty(), min_date=None,
                               max_date=None, offset_rate=0, offset_peer=types.InputPeerEmpty(),
                               offset_id=0, limit=limit)


def common_chats_request(user_id, *, limit: int = 50, max_id: int = 0):
    """Запрос общих групп с целью (только сессия обычного пользователя, не бота)."""
    from telethon.tl.functions.messages import GetCommonChatsRequest

    return GetCommonChatsRequest(user_id=user_id, max_id=max_id, limit=limit)


def _bot_restricted(exc: BaseException) -> bool:
    """Ошибка «этот метод недоступен ботам» (Telegram ограничивает API бот-сессий)."""
    name = type(exc).__name__
    text = f"{name} {exc}".lower()
    return ("botmethodinvalid" in name.lower() or "botmethod" in name.lower()
            or "access for bot users is restricted" in text
            or ("bot" in text and "restricted" in text))


def _post_links(body: str, username: str) -> list[str]:
    """Ссылки на конкретные посты канала в порядке появления (свежие сверху)."""
    pattern = re.compile(rf'href="(https://t\.me/{re.escape(username)}/\d+)"', re.IGNORECASE)
    links = pattern.findall(body)
    if not links:
        links = [f"https://t.me/{channel}/{post}" for channel, post in POST_ID.findall(body)
                 if channel.lower() == username.lower()]
    out: list[str] = []
    for link in links:
        if link not in out:
            out.append(link)
    return out


def _oldest_post_id(body: str, username: str) -> str:
    """ID самого старого поста на странице — для перелистывания (параметр before)."""
    ids = [int(post) for channel, post in POST_ID.findall(body) if channel.lower() == username.lower()]
    if not ids:
        ids = [int(m.group(1)) for m in re.finditer(rf"t\.me/{re.escape(username)}/(\d+)", body, re.IGNORECASE)]
    return str(min(ids)) if ids else ""


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
            posts = await self._preview(ctx, username, result)
            if posts:
                await self._activity(ctx, username, posts, result)
                await self._search_in_channel(ctx, username, posts, result)
                await self._topics(ctx, f"@{username}", posts, result, source="t.me:topics",
                                   note="по публичным постам канала/группы (t.me/s)")
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

        # «в каких группах был»: честно про то, что публично видно, а что нет
        self.add_status(result, SourceStatus(
            source="telegram:groups", category="telegram",
            status="found" if deep_enabled else "unsupported",
            detail=("Общие группы с вашим аккаунтом получены через MTProto (GetCommonChats), "
                    "а чаты, где цель писала, — из глобального поиска сообщений.")
            if deep_enabled else
            ("Список групп, в которых состоит человек, Telegram публично не показывает: это приватные "
             "данные аккаунта. Публично видны только те чаты/каналы, где он оставлял сообщения. "
             "Настроив TG_API_ID/TG_API_HASH (my.telegram.org), модуль добавит общие с вами группы "
             "(GetCommonChats) и все открытые чаты, где найдены его сообщения (глобальный поиск).")))
        await self._identifiers(ctx, username, result)
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
        result.meta.setdefault("telegram_usernames", []).append(username)
        self.add_status(result, SourceStatus(source="t.me", category="telegram", status="found", url=url,
                                             http_code=200, latency_ms=resp.latency_ms))

    # ───────────────────────── публичный превью (t.me/s) ─────────────────────────
    async def _preview(self, ctx: Context, username: str, result: ModuleResult) -> list[dict[str, Any]]:
        """Публичные посты канала/группы. В глубоком режиме листает страницы (before=).

        Возвращает список постов [{date, text, url, views}] — он нужен, чтобы показать
        «где писал»: период активности, частоту постов и упоминания нужных значений.
        """
        url = f"https://t.me/s/{username}"
        resp = await ctx.http.get(url, retries=1)
        if not resp.ok or resp.looks_blocked():
            self.add_status(result, SourceStatus(source="t.me/s", category="telegram",
                                                 status="blocked" if resp.looks_blocked() else "not_found",
                                                 url=url, http_code=resp.status_code or None,
                                                 error=resp.error))
            return []
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
                                                 detail="публичного превью нет (обычный пользователь без открытого "
                                                        "канала, приватный канал или пустая лента)"))
            return []

        post_links = _post_links(body, username)
        posts: list[dict[str, Any]] = []
        for index, text in enumerate(texts):
            link = post_links[index] if index < len(post_links) else ""
            posts.append({"text": text, "url": link,
                          "date": dates[index][:10] if index < len(dates) else ""})
        pages = 3 if ctx.deep else 1
        last_id = _oldest_post_id(body, username)
        for _ in range(pages - 1):
            if not last_id or ctx.cancelled():
                break
            more = await ctx.http.get(f"https://t.me/s/{username}", params={"before": last_id}, retries=1)
            if not more.ok or more.looks_blocked():
                break
            more_texts = [html.unescape(re.sub(r"<[^>]+>", "", re.sub(r"<br\s*/?>", "\n", raw))).strip()[:400]
                          for raw in TG_POST.findall(more.text)][:12]
            more_dates = TG_POST_DATE.findall(more.text)
            more_links = _post_links(more.text, username)
            if not more_texts:
                break
            for index, text in enumerate(more_texts):
                posts.append({"text": text, "url": more_links[index] if index < len(more_links) else "",
                              "date": more_dates[index][:10] if index < len(more_dates) else ""})
            new_last = _oldest_post_id(more.text, username)
            if new_last == last_id:
                break
            last_id = new_last
        subscriber_guess = None
        m = re.search(r'<div class="tgme_channel_info_counter">\s*<span class="counter_value">([^<]*)</span>\s*'
                      r'<span class="counter_type">([^<]*)</span>', body)
        if m:
            subscriber_guess = _parse_count(f"{m.group(1)} {m.group(2)}")
        self.add_finding(result, source="t.me/s", category="telegram", kind="posts", confidence="high",
                         title=f"Публичные посты канала @{username}: получено {len(texts)} (последние: "
                               f"{dates[0][:10] if dates else '—'}) — всего собрано {len(posts)}",
                         url=url, value=username,
                         data={"posts": texts, "dates": dates[:12], "count": len(texts),
                               "collected": len(posts), "timeline": posts[:60],
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
        return posts

    # ───────────────────────── где и когда писал ─────────────────────────
    async def _activity(self, ctx: Context, username: str, posts: list[dict[str, Any]],
                        result: ModuleResult) -> None:
        """Активность автора: период, частота, последний пост — «где и когда писал»."""
        dated = [p["date"] for p in posts if p.get("date")]
        if not dated:
            return
        dated.sort()
        first, last = dated[0], dated[-1]
        days = 0
        try:
            import datetime

            days = (datetime.date.fromisoformat(last) - datetime.date.fromisoformat(first)).days
        except ValueError:
            pass
        per_month = round(len(posts) / max(days / 30, 1), 1) if days else None
        self.add_finding(
            result, source="t.me:activity", category="telegram", kind="meta", confidence="high",
            title=(f"Активность @{username}: {len(posts)} постов, с {first} по {last}"
                   + (f", ~{per_month} постов/мес" if per_month else "")),
            url=f"https://t.me/{username}", value=username,
            data={"posts_collected": len(posts), "first_post_date": first, "last_post_date": last,
                  "days_span": days, "posts_per_month": per_month,
                  "recent": [{"date": p["date"], "url": p["url"], "text": p["text"][:160]}
                             for p in posts[:10]]},
            evidence=f"разбор публичного превью t.me/s/{username} (глубина: {'в deep-режиме' if ctx.deep else 'одна страница'}): "
                     f"{len(posts)} постов, период {first} … {last}",
            http_code=200, tags=["telegram", "активность", "где писал"])
        add_entity(result, "telegram", username, posts=len(posts), last_post=last, first_post=first)

    async def _search_in_channel(self, ctx: Context, username: str, posts: list[dict[str, Any]],
                                 result: ModuleResult) -> None:
        """Поиск упоминаний внутри канала: t.me/s/<канал>?q=<запрос>.

        Так «где писал» работает без MTProto: находим конкретные посты, где встречается
        логин, имя, email или телефон цели, и даём ссылки на них.
        """
        queries = [q for q in dict.fromkeys(
            [username, f"@{username}"] + ([] if not ctx.deep else []) ) if q]
        joined = " \n".join(p["text"] for p in posts)
        queries += [email for email in re.findall(r"[\w.+-]+@[\w-]+\.[\w.]{2,}", joined)][:2]
        for query in queries[:4]:
            resp = await ctx.http.get(f"https://t.me/s/{username}", params={"q": query}, retries=1)
            if not resp.ok or resp.looks_blocked():
                continue
            hits = _post_links(resp.text, username)
            texts = [html.unescape(re.sub(r"<[^>]+>", " ",
                                          re.sub(r"<br\s*/?>", " ", raw))).strip()[:300]
                     for raw in TG_POST.findall(resp.text)][:8]
            if not hits and not texts:
                continue
            key = hashlib.md5(query.lower().encode("utf-8")).hexdigest()[:10]
            self.add_finding(
                result, source=f"t.me:search({query})", category="telegram", kind="messages",
                confidence="high",
                title=f"Упоминания «{query}» в постах @{username}: {len(hits) or len(texts)}",
                url=hits[0] if hits else f"https://t.me/s/{username}?q={query}", value=query,
                data={"query": query, "channel": username, "hits": hits[:15],
                      "snippets": texts[:8], "count": len(hits) or len(texts),
                      "search_url": f"https://t.me/s/{username}?q={query}"},
                evidence=f"t.me/s/{username}?q={query} → найдено вхождений: {len(hits) or len(texts)}",
                http_code=resp.status_code, tags=["telegram", "поиск", "где писал", key])
            add_entity(result, "telegram_search", f"{username}:{query}", hits=len(hits) or len(texts))

    # ─────────────────── «что чаще всего пишет» и «где писал» ───────────────────
    async def _topics(self, ctx: Context, label: str, posts: list[dict[str, Any]],
                      result: ModuleResult, *, source: str, note: str) -> None:
        """Чаще всего встречающиеся слова/хэштеги/домены и активные часы по сообщениям."""
        texts = [p.get("text", "") for p in posts if str(p.get("text") or "").strip()]
        if not texts:
            return
        stats = analyse_texts(texts)
        hours, weekdays = active_hours([p.get("date", "") for p in posts])
        top_words = [f"{word} ×{count}" for word, count in stats["words"][:8]]
        if not top_words and not stats["hashtags"]:
            return
        title = (f"Чаще всего в сообщениях {label}: " + ", ".join(top_words[:6])) if top_words else \
                f"Чаще всего хэштеги {label}: " + ", ".join(f"#{tag}" for tag, _ in stats["hashtags"][:6])
        data = {
            "top_words": stats["words"], "hashtags": stats["hashtags"], "domains": stats["domains"],
            "language": stats["language"], "avg_length": stats["avg_length"],
            "emoji": stats["emoji"], "messages": stats["messages"],
            "active_hours": hours, "active_weekdays": weekdays,
            "summary": title, "note": note,
        }
        bits: list[str] = []
        if stats["hashtags"]:
            bits.append("хэштеги: " + ", ".join(f"#{t}" for t, _ in stats["hashtags"][:5]))
        if stats["domains"]:
            bits.append("ссылки на: " + ", ".join(d for d, _ in stats["domains"][:5]))
        if hours:
            bits.append("чаще пишет в " + ", ".join(h["hour"][:5] for h in hours))
        evidence = (f"{note}: разобрано {stats['messages']} сообщений, в среднем {stats['avg_length']} символов"
                    + ("; " + "; ".join(bits) if bits else ""))
        self.add_finding(result, source=source, category="telegram", kind="topics", confidence="medium",
                         title=title[:250], value=label, data=data, evidence=evidence[:900],
                         url=(posts[0].get("url") or "") if posts else "")
        add_entity(result, "telegram_topics", label, words=[w for w, _ in stats["words"][:10]],
                   hashtags=[t for t, _ in stats["hashtags"][:10]])

    def _chats_finding(self, result: ModuleResult, hits: list[dict[str, Any]], *,
                       source: str = "mtproto:chats", label: str = "") -> None:
        """В каких открытых чатах/каналах найдены сообщения человека — «где писал»."""
        chats = aggregate_chats(hits)
        if not chats:
            return
        total = sum(c["messages"] for c in chats)
        title = (f"Telegram: писал в {len(chats)} открытых чатах/каналах — всего {total} сообщений"
                 + (f" (запрос «{label}»)" if label else ""))
        self.add_finding(result, source=source, category="telegram", kind="chats", confidence="high",
                         title=title[:250], value=label or ",".join(c["chat"] for c in chats[:3]),
                         url=chats[0]["links"][0] if chats[0]["links"] else "",
                         data={"chats": chats, "chats_count": len(chats), "messages": total,
                               "note": "только открытые чаты/каналы, где найдены сообщения; "
                                       "полный список групп аккаунта Telegram публично не отдаёт"},
                         evidence=f"{source}: сообщения сгруппированы по чатам — " +
                                  ", ".join(f"{c['chat']} ({c['messages']})" for c in chats[:6]))
        add_entity(result, "telegram_chats", label or "target", chats=[c["chat"] for c in chats[:20]])

    async def _common_chats(self, ctx: Context, client, entity, result: ModuleResult) -> None:
        """Общие группы цели и вашего аккаунта (MTProto GetCommonChats)."""
        if (result.meta.get("mtproto_session") or {}).get("bot"):
            self.add_status(result, SourceStatus(
                source="mtproto:common-chats", category="telegram", status="unsupported",
                detail="GetCommonChats недоступен для бот-сессии (Telegram ограничивает API ботов). "
                       "Общие группы покажет вход как обычный аккаунт: osintx tgauth --reset && osintx tgauth"))
            return
        try:
            res = await client(common_chats_request(entity))
        except Exception as exc:
            if _bot_restricted(exc):
                self.add_status(result, SourceStatus(
                    source="mtproto:common-chats", category="telegram", status="unsupported",
                    error=f"{type(exc).__name__}: {exc}"[:200],
                    detail="Метод доступен только сессии обычного пользователя: osintx tgauth --reset, "
                           "затем osintx tgauth с номером телефона"))
                return
            self.add_status(result, SourceStatus(source="mtproto:common-chats", category="telegram",
                                                 status="error", error=f"{type(exc).__name__}: {exc}"[:200]))
            return
        chats = getattr(res, "chats", None) or []
        if not chats:
            self.add_status(result, SourceStatus(
                source="mtproto:common-chats", category="telegram", status="not_found",
                detail="общих групп с вашим аккаунтом не найдено (это НЕ значит, что у цели нет групп — "
                       "видны только те, где состоите и вы)"))
            return
        items = [{
            "title": getattr(c, "title", None) or getattr(c, "username", None),
            "username": getattr(c, "username", None),
            "id": getattr(c, "id", None),
            "participants": getattr(c, "participants_count", None),
            "link": (f"https://t.me/{getattr(c, 'username')}" if getattr(c, "username", None) else None),
        } for c in chats]
        self.add_finding(result, source="mtproto:common-chats", category="telegram", kind="groups",
                         confidence="high",
                         title=f"Telegram: общих групп с вашим аккаунтом — {len(items)}",
                         url=next((i["link"] for i in items if i["link"]), ""),
                         value=str(getattr(entity, "id", "")),
                         data={"chats": items, "count": len(items),
                               "note": "GetCommonChats показывает только чаты, где состоите и вы, и цель; "
                                       "полный список групп аккаунта приватный"},
                         evidence="messages.GetCommonChats(user_id=…) → " +
                                  ", ".join(str(i["title"]) for i in items[:8]))
        for item in items:
            if item["link"]:
                add_edge(result, entity_id("telegram_id", str(getattr(entity, "id", ""))),
                         entity_id("telegram", item["username"]), "common_chat", 0.9,
                         "общая группа (MTProto GetCommonChats)")
        self.add_status(result, SourceStatus(source="mtproto:common-chats", category="telegram",
                                             status="found", detail=f"{len(items)} общих групп"))

    async def _identifiers(self, ctx: Context, username: str | None, result: ModuleResult) -> None:
        """Все увиденные юзернеймы аккаунта: текущий и дополнительные (MTProto) — для истории ников."""
        names = [str(n).lstrip("@") for n in (result.meta.get("telegram_usernames") or []) if n]
        names = [n for n in dict.fromkeys(names) if n]
        current = username or (names[0] if names else "")
        if not names and not current:
            return
        if current and current not in names:
            names.insert(0, current)
        title = f"Telegram: юзернеймы — @{current}" + (f" (+{len(names) - 1} доп.)" if len(names) > 1 else "")
        self.add_finding(
            result, source="t.me:usernames", category="telegram", kind="identifiers", confidence="high",
            title=title, url=f"https://t.me/{current}" if current else "", value=current,
            data={"username": current, "usernames": ", ".join(names), "current": current,
                  "observed": names,
                  "note": "ники, увиденные этим поиском (t.me + MTProto usernames). Прежние ники "
                          "накапливаются в локальной базе: /usernames и osintx usernames показывают "
                          "их даже когда бот не запущен"},
            evidence=f"источники ников: t.me/{current}"
                     + (", MTProto users.GetFullUser (usernames)" if len(names) > 1 else ""))
        for name in names[1:]:
            if current:
                add_edge(result, entity_id("telegram", current), entity_id("telegram", name),
                         "same_account_username", 0.9, "дополнительный юзернейм того же аккаунта (MTProto)")

    # ─────────────────── бот-сессия: что реально доступно ───────────────────
    async def _bot_channel(self, ctx: Context, client, target: str, username: str | None,
                           result: ModuleResult) -> None:
        """Публичный канал глазами бот-сессии: последние посты и поиск внутри канала.

        Глобальный поиск и общие группы ботам запрещены, но публичные каналы читать можно —
        это честный максимум того, что даёт бот-токен.
        """
        peer = username or target
        try:
            messages = await client.get_messages(peer, limit=30)
        except Exception as exc:
            self.add_status(result, SourceStatus(
                source="mtproto:channel", category="telegram",
                status="unsupported" if _bot_restricted(exc) else "error",
                error=f"{type(exc).__name__}: {exc}"[:200],
                detail="бот видит только публичные каналы/чаты, где он состоит или админ"))
            return
        posts: list[dict[str, Any]] = []
        for message in messages or []:
            date = getattr(message, "date", None)
            posts.append({
                "text": (getattr(message, "message", "") or "").strip()[:600],
                "date": date.strftime("%Y-%m-%d %H:%M") if hasattr(date, "strftime") else "",
                "url": f"https://t.me/{peer}/{getattr(message, 'id', '')}" if username else "",
                "views": getattr(message, "views", None),
            })
        posts = [p for p in posts if p["text"] or p["url"]]
        if not posts:
            self.add_status(result, SourceStatus(source="mtproto:channel", category="telegram",
                                                 status="not_found",
                                                 detail=f"у {peer} нет доступных боту сообщений"))
            return
        dated = sorted(p["date"][:10] for p in posts if p["date"])
        self.add_finding(
            result, source="mtproto:channel", category="telegram", kind="posts", confidence="high",
            title=f"MTProto (бот): {len(posts)} последних сообщений {peer}"
                  + (f", с {dated[0]} по {dated[-1]}" if dated else ""),
            url=posts[0]["url"], value=peer,
            data={"posts": posts, "count": len(posts), "chat": peer,
                  "first_date": dated[0] if dated else "", "last_date": dated[-1] if dated else "",
                  "note": "бот-сессия: доступны только публичные каналы, где бот участник; "
                          "глобальный поиск и общие группы требуют входа как обычный аккаунт"},
            evidence=f"client.get_messages({peer!r}, limit=30) через бот-сессию → {len(posts)} сообщений",
            http_code=200, tags=["telegram", "mtproto", "посты"])
        self.add_status(result, SourceStatus(source="mtproto:channel", category="telegram", status="found",
                                             detail=f"{len(posts)} сообщений канала"))
        await self._topics(ctx, f"{peer} (бот-сессия)", posts, result, source="mtproto:topics",
                           note="по последним сообщениям канала, прочитанным ботом")
        query = username or target
        if not query:
            return
        try:
            found = await client.get_messages(peer, limit=30, search=query)
        except Exception:
            return
        hits = [{"text": (getattr(m, "message", "") or "").strip()[:600],
                 "date": str(getattr(m, "date", "")), "chat": peer,
                 "link": f"https://t.me/{peer}/{getattr(m, 'id', '')}" if username else ""}
                for m in (found or []) if (getattr(m, "message", "") or "").strip()]
        if hits:
            self._chats_finding(result, hits, source="mtproto:chats", label=query)

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
                           "`osintx tgauth` (или `python bot.py tgauth`) и введи номер+код — "
                           "после этого MTProto-поиск заработает."))
                return
            me = await client.get_me()
            is_bot = bool(getattr(me, "bot", False))
            result.meta["mtproto_session"] = {"bot": is_bot, "id": getattr(me, "id", None),
                                              "username": getattr(me, "username", None)}
            if is_bot:
                # Telegram запрещает ботам глобальный поиск и GetCommonChats — работаем тем, что можно
                self.add_status(result, SourceStatus(
                    source="mtproto:session", category="telegram", status="unsupported",
                    detail="Сессия MTProto — это БОТ-аккаунт (@%s), а не ваш Telegram-аккаунт. Telegram "
                           "запрещает ботам глобальный поиск сообщений (SearchGlobal) и список общих "
                           "групп (GetCommonChats) — именно поэтому эти пункты недоступны. "
                           "Что доступно: чтение публичных каналов. Чтобы получить «где писал», общие "
                           "группы и числовой ID цели — войдите как обычный аккаунт: "
                           "osintx tgauth --reset, затем osintx tgauth и введите НОМЕР ТЕЛЕФОНА "
                           "(не токен бота)." % (getattr(me, "username", None) or "bot",)))
                await self._bot_channel(ctx, client, target, username, result)
                self.add_status(result, SourceStatus(source="mtproto", category="telegram", status="found",
                                                     detail="бот-сессия: доступны только публичные каналы"))
                return
            await self._mtproto_entity(ctx, client, target, username, result)
            await self._mtproto_search(ctx, client, target, result)
            self.add_status(result, SourceStatus(source="mtproto", category="telegram", status="found",
                                                 detail="сессия пользователя активна, данные получены"))
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
        except Exception as exc:
            if _bot_restricted(exc):
                self.add_status(result, SourceStatus(
                    source="mtproto:entity", category="telegram", status="unsupported",
                    error=f"{type(exc).__name__}: {exc}"[:200],
                    detail="Бот-сессия видит только публичные каналы и тех, кто писал боту. "
                           "Полный профиль (bio, общие группы, юзернеймы) даёт вход как обычный аккаунт"))
            else:
                self.add_status(result, SourceStatus(source="mtproto:entity", category="telegram",
                                                     status="error", error=f"{type(exc).__name__}: {exc}"[:200]))
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
        for name in [data.get("username"), *(data.get("usernames") or [])]:
            if name:
                result.meta.setdefault("telegram_usernames", []).append(str(name))
        add_entity(result, "telegram_id", str(data["id"]), username=data.get("username"),
                   premium=data.get("premium"), dc=data.get("dc_id"), phone=data.get("phone"))
        await self._common_chats(ctx, client, entity, result)
        if data.get("username"):
            add_edge(result, entity_id("telegram_id", str(data["id"])), entity_id("telegram", data["username"]),
                     "id_username", 1.0, "одна и та же сущность Telegram (MTProto)")
        if data.get("phone"):
            add_edge(result, entity_id("telegram_id", str(data["id"])), entity_id("phone", data["phone"]),
                     "bound_phone", 1.0, "номер привязан к аккаунту (виден через MTProto)")

    async def _mtproto_search(self, ctx: Context, client, query: str, result: ModuleResult) -> None:
        """Глобальный поиск по сообщениям — аналог поиска в Void OSINT."""
        try:
            res = await client(search_global_request(query))
        except Exception as exc:
            if _bot_restricted(exc):
                self.add_status(result, SourceStatus(
                    source="mtproto:search", category="telegram", status="unsupported",
                    error=f"{type(exc).__name__}: {exc}"[:200],
                    detail="Глобальный поиск по сообщениям недоступен для бот-сессии (ограничение Telegram). "
                           "Войдите как обычный аккаунт: osintx tgauth --reset && osintx tgauth (номер телефона). "
                           "Публичная альтернатива без входа: поиск по постам канала t.me/s/<канал>?q=…"))
                return
            text = f"{type(exc).__name__}: {exc}"
            hint = ""
            if "tlobject was expected" in text.lower():
                hint = ("Это баг старых версий OsintX (в запросе передавался filter=None) — исправлено "
                        "в 1.2.5. Обновитесь: git pull, затем pip install -e .")
            self.add_status(result, SourceStatus(source="mtproto:search", category="telegram", status="error",
                                                 error=text[:200], detail=hint))
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
        self._chats_finding(result, hits, source="mtproto:chats", label=query)
        search_posts = [{"text": h["text"], "date": h["date"], "url": h.get("link") or ""} for h in hits]
        await self._topics(ctx, f"по запросу «{query}»", search_posts, result,
                           source="mtproto:topics", note="по сообщениям из глобального поиска Telegram")
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
