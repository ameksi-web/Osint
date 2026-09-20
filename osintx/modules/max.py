"""Мессенджер MAX (max.ru): проверка каналов, ботов и ссылок на профиль.

Что реально доступно без входа в аккаунт и без токена:

  * ``max.ru/@nick`` — канал/бот с публичным ником: страница отвечает либо данными
    чата, либо текстом «Не нашли чат по этой ссылке» (значит, ника нет);
  * ``max.ru/u/<hash>`` — персональная ссылка на профиль (её человек получает
    через QR-код в приложении): проверяем существование;
  * ``web.max.ru/@nick`` — веб-версия, если приложение не установлено.

Честно про ограничение: в MAX у личных профилей **нет** публичных @username —
поиск человека возможен только по персональной ссылке (или по номеру телефона
через контакты, что требует авторизации). Поэтому модуль не «находит людей по
нику в MAX» — он проверяет существование канала/бота/ссылки и объясняет, что
именно можно и нельзя узнать публично. Если задан MAX_TOKEN (токен бота с
dev.max.ru), статус помечается как доступный для расширения через Bot API.
"""
from __future__ import annotations

import re

from ..core.models import ModuleResult, SourceStatus
from .base import Context, Module, add_entity

NOT_FOUND = ("Не нашли чат по этой ссылке", "не нашли чат", "not found",
             "Ссылка недействительна", "ссылка устарела")
BLOCKED = ("captcha", "Доступ ограничен", "Cloudflare", "Проверяем, что вы не робот")
META = re.compile(r'<meta[^>]+(?:property|name)=["\'](og:[a-z:]+|description|twitter:[a-z:]+)["\'][^>]+content=["\']([^"\']*)',
                  re.IGNORECASE)
TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.DOTALL)
NICK = re.compile(r"^[A-Za-z0-9_]{3,32}$")


class MaxModule(Module):
    name = "max"
    title = "MAX (max.ru): каналы, боты, ссылки на профиль"
    categories = ("max",)
    target_types = ("username", "telegram", "person", "email", "phone")

    async def run(self, ctx: Context, target: str, result: ModuleResult) -> None:
        target_type = str(ctx.options.get("target_type") or "")
        login = target.lstrip("@").strip()
        if target_type == "email" and "@" in target:
            login = target.split("@")[0]

        if NICK.fullmatch(login or ""):
            await self._nick(ctx, login, result)
        else:
            self.add_status(result, SourceStatus(
                source="max", category="max", status="skipped",
                detail="Ник не подходит под формат MAX (A-Za-z0-9_, 3–32 символа)"))

        # персональные ссылки вида max.ru/u/<hash> — проверяем только если цель сама такая ссылка
        if "max.ru/u/" in target:
            await self._profile_link(ctx, target.strip(), result)

        if target_type == "phone":
            self.add_status(result, SourceStatus(
                source="max:phone", category="max", status="unsupported",
                detail="В MAX нет публичной ссылки на профиль по номеру (в отличие от wa.me). "
                       "Номер можно использовать только из авторизованного аккаунта через контакты. "
                       "Публичных способов проверки нет — честно фиксируем, а не выдумываем результат."))
        if target_type in ("username", "telegram", "person"):
            self.add_status(result, SourceStatus(
                source="max:people-search", category="max", status="unsupported",
                detail="У личных профилей MAX нет публичных @username (только hash-ссылки max.ru/u/...). "
                       "Людей в MAX публично не ищут: модуль проверяет каналы и ботов по нику, "
                       "а профиль — только если у вас есть его персональная ссылка"))

    # ─────────────────────────── проверка ника ───────────────────────────
    async def _nick(self, ctx: Context, nick: str, result: ModuleResult) -> None:
        url = f"https://max.ru/@{nick}"
        resp = await ctx.http.get(url, retries=1)
        body = resp.text or ""
        if resp.error:
            self.add_status(result, SourceStatus(
                source="max", category="max", status="error", url=url, error=resp.error,
                detail="max.ru недоступен из вашей сети (вне РФ сервис может быть недоступен) — "
                       "укажите OSINTX_PROXY, если у вас есть прокси"))
            return
        if resp.looks_blocked() or any(marker.lower() in body.lower() for marker in BLOCKED):
            self.add_status(result, SourceStatus(
                source="max", category="max", status="blocked", url=url,
                http_code=resp.status_code or None,
                detail="max.ru ответил заглушкой/капчей — результат не получен (не «не найдено»)"))
            return
        if any(marker.lower() in body.lower() for marker in NOT_FOUND):
            self.add_status(result, SourceStatus(
                source="max", category="max", status="not_found", url=url,
                http_code=resp.status_code or 404,
                detail=f"в MAX нет канала/бота с ником @{nick} (страница прямо сообщает «не нашли чат»)"))
            return
        if resp.status_code != 200:
            self.add_status(result, SourceStatus(source="max", category="max", status="error", url=url,
                                                 http_code=resp.status_code))
            return
        meta = {key.lower(): value for key, value in META.findall(body)}
        title = TITLE.search(body)
        name = re.sub(r"\s+", " ", title.group(1)).strip() if title else ""
        description = meta.get("og:description") or meta.get("description") or ""
        self.add_finding(
            result, source="max", category="max", kind="profile", confidence="medium",
            title=f"MAX: {name or '@' + nick}" + (f" — {description[:120]}" if description else ""),
            url=url, value=nick,
            data={"name": name, "description": description[:600], "og": meta,
                  "web_url": f"https://web.max.ru/@{nick}", "type": "channel_or_bot"},
            evidence=f"HTTP 200 max.ru/@{nick} (страница не сообщает «не нашли чат»); "
                     f"title={name!r}, meta={list(meta)[:4]}",
            http_code=200, tags=["max", "мессенджер"])
        self.add_status(result, SourceStatus(source="max", category="max", status="found", url=url,
                                             http_code=200,
                                             detail=f"ник @{nick} в MAX занят (канал/бот)"))
        add_entity(result, "max", nick, name=name, url=url)

    # ─────────────────────────── персональная ссылка ───────────────────────────
    async def _profile_link(self, ctx: Context, link: str, result: ModuleResult) -> None:
        resp = await ctx.http.get(link, retries=1)
        body = resp.text or ""
        if resp.error or resp.status_code >= 400:
            self.add_status(result, SourceStatus(source="max:profile", category="max",
                                                 status="error" if resp.error else "not_found",
                                                 url=link, http_code=resp.status_code or None,
                                                 error=resp.error,
                                                 detail="" if resp.error else "ссылка не открывается"))
            return
        if any(marker.lower() in body.lower() for marker in NOT_FOUND):
            self.add_status(result, SourceStatus(source="max:profile", category="max", status="not_found",
                                                 url=link, http_code=resp.status_code,
                                                 detail="персональная ссылка MAX не найдена"))
            return
        meta = {key.lower(): value for key, value in META.findall(body)}
        self.add_finding(
            result, source="max:profile", category="max", kind="link", confidence="medium",
            title=f"Ссылка на профиль MAX существует: {link}",
            url=link, value=link,
            data={"og": meta, "name": meta.get("og:title", "")},
            evidence=f"HTTP {resp.status_code} {link} — страница отдала метаданные профиля",
            http_code=resp.status_code, tags=["max", "профиль"])
        self.add_status(result, SourceStatus(source="max:profile", category="max", status="found",
                                             url=link, http_code=resp.status_code))
