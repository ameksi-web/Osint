"""ВКонтакте: профиль, город, посты («где писал»), сообщества.

Два режима:

1. **С токеном** (``VK_TOKEN`` в .env — бесплатный «сервисный» ключ, получается
   за минуту в настройках приложения VK) — официальный API:
   ``utils.resolveScreenName`` (логин → id), ``users.get`` (имя, город, страна,
   статус, о себе, подписчики, последний визит, сайт, образование, работа),
   ``wall.get`` (публичные записи: тексты, даты, просмотры, лайки),
   ``groups.getById`` (сообщества), ``users.search`` (поиск людей по ФИО).
2. **Без токена** — публичная мобильная страница ``m.vk.com/<логин>``: имя,
   факт существования, публичные записи (ссылки, даты, тексты). Если VK отдаёт
   капчу/заглушку — честный статус ``blocked`` с объяснением, а не «не найдено».

Что даёт «где писал»: список публичных записей со датами и ссылками — реальные
посты человека в VK, как и публичный превью канала в Telegram.
"""
from __future__ import annotations

import html
import re
from datetime import datetime, timezone

from ..core import gazetteer
from ..core.models import ModuleResult, SourceStatus
from .base import Context, Module, add_edge, add_entity, entity_id

API = "https://api.vk.com/method"
API_VERSION = "5.199"

TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.DOTALL)
OG = re.compile(r'<meta[^>]+(?:property|name)=["\'](og:[a-z:]+|description|twitter:[a-z:]+)["\'][^>]+content=["\']([^"\']*)',
                re.IGNORECASE)
WALL_LINK = re.compile(r"/wall(-?\d+)_(\d+)")
POST_TEXT = re.compile(r'<(?:div|span)[^>]+class="[^"]*(?:wall_post_text|pi_text)[^"]*"[^>]*>(.*?)</(?:div|span)>',
                       re.DOTALL)
DATE_TEXT = re.compile(r'class="[^"]*(?:rel_date|post_date|pi_date)[^"]*"[^>]*>([^<]{3,40})<')
BLOCKED_MARKERS = ("Проверяем, что вы не робот", "challenge.html", "captcha", "Подтвердите, что вы не робот",
                   "слишком много запросов", "Too many requests")
NOT_FOUND_MARKERS = ("Страница не найдена", "page not found", "Такой страницы нет",
                     "профиль не найден", "Пользователь не найден")


class VkModule(Module):
    name = "vk"
    title = "ВКонтакте: профиль, город, посты, сообщества"
    categories = ("vk",)
    target_types = ("username", "person", "telegram", "email", "phone")

    async def run(self, ctx: Context, target: str, result: ModuleResult) -> None:
        token = (ctx.key("vk_token") or ctx.key("vk") or "").strip()
        target_type = str(ctx.options.get("target_type") or "")
        login = target.lstrip("@").strip()
        if target_type == "email" and "@" in target:
            login = target.split("@")[0]

        if token:
            await self._api_profile(ctx, token, login, result, target_type)
        else:
            await self._public_page(ctx, login, result)

        if target_type == "phone":
            self.add_status(result, SourceStatus(
                source="vk:phone", category="vk", status="unsupported",
                detail="Поиск профиля ВКонтакте по номеру телефона возможен только из авторизованного "
                       "аккаунта (настройки приватности VK). Публичного способа нет — в отчёте это "
                       "честно помечено, а не выдано за «не найдено»."))

    # ─────────────────────────── официальный API ───────────────────────────
    async def _call(self, ctx: Context, token: str, method: str, **params) -> tuple[dict | list | None, str]:
        resp = await ctx.http.get(f"{API}/{method}",
                                  params={**params, "access_token": token, "v": API_VERSION}, retries=1)
        data = resp.json()
        if not isinstance(data, dict):
            return None, resp.error or f"HTTP {resp.status_code}: ответ не JSON"
        if "error" in data:
            error = data["error"]
            return None, f"VK API error {error.get('error_code')}: {error.get('error_msg')}"
        return data.get("response"), ""

    async def _api_profile(self, ctx: Context, token: str, login: str, result: ModuleResult,
                           target_type: str) -> None:
        resolved, error = await self._call(ctx, token, "utils.resolveScreenName", screen_name=login)
        if error:
            self.add_status(result, SourceStatus(source="vk-api", category="vk", status="error",
                                                 error=error[:250],
                                                 detail="проверьте VK_TOKEN (сервисный ключ приложения)"))
            return
        if not resolved:
            self.add_status(result, SourceStatus(source="vk-api", category="vk", status="not_found",
                                                 detail=f"короткое имя «{login}» в VK не занято"))
            return
        object_id = resolved.get("object_id")
        kind = resolved.get("type")
        if kind == "user":
            await self._api_user(ctx, token, int(object_id), login, result)
        elif kind in ("group", "page"):
            await self._api_group(ctx, token, int(object_id), login, result)
        else:
            self.add_finding(result, source="vk-api", category="vk", kind="meta", confidence="medium",
                             title=f"VK: «{login}» указывает на объект типа {kind} (id {object_id})",
                             url=f"https://vk.com/{login}", value=login,
                             data={"type": kind, "object_id": object_id},
                             evidence=f"utils.resolveScreenName(screen_name={login!r}) → type={kind}, "
                                      f"object_id={object_id}")

    async def _api_user(self, ctx: Context, token: str, user_id: int, login: str,
                        result: ModuleResult) -> None:
        fields = ("city,country,bdate,about,status,followers_count,last_seen,domain,site,photo_max,"
                  "counters,education,career,occupation,verified,friend_status")
        users, error = await self._call(ctx, token, "users.get", user_ids=user_id, fields=fields)
        user = users[0] if isinstance(users, list) and users else None
        if error or not user:
            self.add_status(result, SourceStatus(source="vk-api", category="vk", status="error",
                                                 error=(error or "пустой ответ")[:200]))
            return
        city = (user.get("city") or {}).get("title", "")
        country = (user.get("country") or {}).get("title", "")
        name = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
        location = ", ".join(x for x in (city, country) if x)
        found = gazetteer.find_location(location) if location else []
        self.add_finding(
            result, source="vk-api", category="vk", kind="profile", confidence="high",
            title=f"VK: {name or login}" + (f" — {location}" if location else "")
                  + (f", подписчиков: {user.get('followers_count')}" if user.get("followers_count") is not None else ""),
            url=f"https://vk.com/{user.get('domain') or login}", value=login,
            data={"name": name, "display_name": name, "location": location, "city": city,
                  "country": country, "status": user.get("status"), "about": user.get("about"),
                  "followers": user.get("followers_count"), "bdate": user.get("bdate"),
                  "site": user.get("site"), "photo": user.get("photo_max"),
                  "last_seen": (user.get("last_seen") or {}).get("platform"),
                  "verified": user.get("verified"), "counters": user.get("counters"),
                  "country_code": found[0].code if found else "", "id": user.get("id"),
                  "geo_country": found[0].country if found else ""},
            evidence=f"vk api users.get(user_ids={user_id}) → city={city!r}, country={country!r}, "
                     f"followers={user.get('followers_count')}", http_code=200, tags=["vk", "профиль"])
        self.add_status(result, SourceStatus(source="vk-api", category="vk", status="found",
                                             detail=f"профиль найден: id {user_id}"))
        add_entity(result, "vk", login, vk_id=user.get("id"), name=name, city=city, country=country)
        if location:
            add_edge(result, entity_id("username", login), entity_id("location", location), "location", 0.85,
                     "город/страна из открытого профиля VK")
        await self._api_wall(ctx, token, user_id, login, result)

    async def _api_wall(self, ctx: Context, token: str, owner_id: int, login: str,
                        result: ModuleResult) -> None:
        wall, error = await self._call(ctx, token, "wall.get", owner_id=owner_id, count=20, filter="owner")
        items = (wall or {}).get("items") if isinstance(wall, dict) else None
        if error or not items:
            self.add_status(result, SourceStatus(source="vk:wall", category="vk",
                                                 status="error" if error else "not_found",
                                                 error=error[:200] if error else "",
                                                 detail="" if error else "публичных записей не найдено"))
            return
        posts = [{"date": _ts(p.get("date")),
                  "text": (p.get("text") or "").strip()[:600], "likes": (p.get("likes") or {}).get("count"),
                  "views": (p.get("views") or {}).get("count"), "comments": (p.get("comments") or {}).get("count"),
                  "url": f"https://vk.com/wall{owner_id}_{p.get('id')}"} for p in items]
        self.add_finding(
            result, source="vk:wall", category="vk", kind="posts", confidence="high",
            title=f"VK: {len(posts)} публичных записей, последняя {posts[0]['date'][:10]} "
                  f"(первая в выборке {posts[-1]['date'][:10]})",
            url=posts[0]["url"], value=login,
            data={"posts": posts, "count": len(posts), "last_post_date": posts[0]["date"][:10],
                  "first_post_date": posts[-1]["date"][:10],
                  "mentions": _mentions([p["text"] for p in posts])},
            evidence=f"vk api wall.get(owner_id={owner_id}, count=20) → {len(posts)} записей "
                     f"({posts[0]['date'][:10]} … {posts[-1]['date'][:10]})", http_code=200,
            tags=["vk", "посты", "где писал"])
        self.add_status(result, SourceStatus(source="vk:wall", category="vk", status="found",
                                             detail=f"{len(posts)} записей"))
        add_entity(result, "vk", login, posts=len(posts), last_post=posts[0]["date"][:10])
        for email in _mentions([p["text"] for p in posts])["emails"]:
            add_edge(result, entity_id("username", login), entity_id("email", email), "email_in_vk_posts",
                     0.6, "адрес встречается в публичных записях VK")

    async def _api_group(self, ctx: Context, token: str, group_id: int, login: str,
                         result: ModuleResult) -> None:
        groups, error = await self._call(ctx, token, "groups.getById", group_id=group_id,
                                         fields="description,members_count,city,country,site,status,verified")
        if error:
            self.add_status(result, SourceStatus(source="vk-api", category="vk", status="error", error=error[:200]))
            return
        group = groups[0] if isinstance(groups, list) and groups else (groups if isinstance(groups, dict) else None)
        if not group:
            self.add_status(result, SourceStatus(source="vk-api", category="vk", status="error",
                                                 detail="пустой ответ groups.getById"))
            return
        city = (group.get("city") or {}).get("title", "") if isinstance(group.get("city"), dict) else ""
        country = (group.get("country") or {}).get("title", "") if isinstance(group.get("country"), dict) else ""
        self.add_finding(
            result, source="vk-api", category="vk", kind="profile", confidence="high",
            title=f"VK-сообщество: {group.get('name')}" + (f" — {city}" if city else "")
                  + (f", участников: {group.get('members_count')}" if group.get("members_count") else ""),
            url=f"https://vk.com/{login}", value=login,
            data={"name": group.get("name"), "description": (group.get("description") or "")[:600],
                  "members": group.get("members_count"), "city": city, "country": country,
                  "status": group.get("status"), "site": group.get("site"),
                  "verified": group.get("verified"), "type": "group"},
            evidence=f"vk api groups.getById(group_id={group_id}) → name={group.get('name')!r}, "
                     f"members={group.get('members_count')}", http_code=200, tags=["vk", "сообщество"])
        self.add_status(result, SourceStatus(source="vk-api", category="vk", status="found",
                                             detail=f"сообщество: {group.get('name')}"))
        # посты сообщества тоже показывают «где пишет»
        wall, _ = await self._call(ctx, token, "wall.get", owner_id=-abs(group_id), count=15)
        items = (wall or {}).get("items") if isinstance(wall, dict) else None
        if items:
            posts = [{"date": _ts(p.get("date")),
                      "text": (p.get("text") or "").strip()[:500],
                      "views": (p.get("views") or {}).get("count"),
                      "url": f"https://vk.com/wall-{abs(group_id)}_{p.get('id')}"} for p in items]
            self.add_finding(
                result, source="vk:wall", category="vk", kind="posts", confidence="high",
                title=f"VK-сообщество: {len(posts)} последних записей, свежая {posts[0]['date'][:10]}",
                url=posts[0]["url"], value=login,
                data={"posts": posts, "count": len(posts), "last_post_date": posts[0]["date"][:10]},
                evidence=f"vk api wall.get(owner_id=-{abs(group_id)}) → {len(posts)} записей",
                http_code=200, tags=["vk", "посты"])

    # ─────────────────────────── без токена: m.vk.com ───────────────────────────
    async def _public_page(self, ctx: Context, login: str, result: ModuleResult) -> None:
        url = f"https://m.vk.com/{login}"
        resp = await ctx.http.get(url, retries=1)
        body = resp.text or ""
        if resp.error:
            self.add_status(result, SourceStatus(
                source="vk", category="vk", status="error", url=url, error=resp.error,
                detail="VK недоступен из вашей сети (нужен прокси/VPN): OSINTX_PROXY=http://host:port"))
            return
        if resp.looks_blocked() or any(marker.lower() in body.lower() for marker in BLOCKED_MARKERS):
            self.add_status(result, SourceStatus(
                source="vk", category="vk", status="blocked", url=url, http_code=resp.status_code or None,
                detail="VK показал капчу/проверку («Проверяем, что вы не робот»). Это ожидаемо для "
                       "серверных запросов: добавьте VK_TOKEN (сервисный ключ приложения — бесплатно, "
                       "1 минута в настройках) — модуль переключится на официальный API, где нет капчи"))
            return
        if resp.status_code == 404 or any(marker.lower() in body.lower() for marker in NOT_FOUND_MARKERS):
            self.add_status(result, SourceStatus(source="vk", category="vk", status="not_found", url=url,
                                                 http_code=resp.status_code or 404,
                                                 detail=f"страницы vk.com/{login} нет"))
            return
        if resp.status_code != 200:
            self.add_status(result, SourceStatus(source="vk", category="vk", status="error", url=url,
                                                 http_code=resp.status_code))
            return

        meta = {k.lower(): html.unescape(v) for k, v in OG.findall(body)}
        title = html.unescape(TITLE.search(body).group(1)).strip() if TITLE.search(body) else ""
        name = title.replace("| VK", "").replace("| ВКонтакте", "").strip()
        wall_ids = WALL_LINK.findall(body)
        texts = [html.unescape(re.sub(r"<[^>]+>", " ", raw)).strip()[:400]
                 for raw in POST_TEXT.findall(body)][:10]
        dates = [html.unescape(d).strip() for d in DATE_TEXT.findall(body)][:10]
        location = ""
        for value in (meta.get("og:description", ""), meta.get("description", ""), meta.get("twitter:description", "")):
            if value and not location:
                found = gazetteer.find_location(value)
                if found:
                    location = f"{found[0].city}, {found[0].country}" if found[0].city else found[0].country
        if not name and not wall_ids and not texts:
            self.add_status(result, SourceStatus(source="vk", category="vk", status="blocked", url=url,
                                                 http_code=200,
                                                 detail="VK отдал страницу без данных профиля (вероятно, "
                                                        "показывается форма входа). Для полного доступа "
                                                        "нужен VK_TOKEN"))
            return
        self.add_finding(
            result, source="vk", category="vk", kind="profile", confidence="medium",
            title=f"VK: {name or login}" + (f" — {location}" if location else "")
                  + (f", публичных записей: {len(wall_ids)}" if wall_ids else ""),
            url=f"https://vk.com/{login}", value=login,
            data={"name": name, "display_name": name, "location": location, "posts_links": len(wall_ids),
                  "posts": texts, "dates": dates, "og": meta,
                  "note": "без VK_TOKEN доступны только базовые публичные данные (имя, записи). "
                          "Город, подписчики, статус и точные даты даёт официальный API по сервисному ключу"},
            evidence=f"HTTP 200 m.vk.com/{login}: title={title!r}, wall-ссылок={len(wall_ids)}, "
                     f"og:description={meta.get('og:description', '')[:120]!r}",
            http_code=200, tags=["vk", "профиль"])
        self.add_status(result, SourceStatus(source="vk", category="vk", status="found", url=url,
                                             http_code=200,
                                             detail="публичная страница VK отдалась без токена (базовые данные)"))
        add_entity(result, "vk", login, name=name, posts=len(wall_ids))
        if wall_ids:
            posts = [{"text": text, "url": f"https://vk.com/wall{owner}_{post}", "date": dates[i] if i < len(dates) else ""}
                     for i, (text, (owner, post)) in enumerate(zip(texts or [""] * len(wall_ids), wall_ids))]
            self.add_finding(
                result, source="vk:wall", category="vk", kind="posts", confidence="medium",
                title=f"VK: публичные записи — {len(wall_ids)}, последняя {dates[0] if dates else '—'}",
                url=posts[0]["url"], value=login,
                data={"posts": posts, "count": len(wall_ids), "dates": dates,
                      "mentions": _mentions([p["text"] for p in posts])},
                evidence=f"m.vk.com/{login}: найдено {len(wall_ids)} ссылок вида /wall<id>_<post> в HTML",
                http_code=200, tags=["vk", "посты", "где писал"])


def _ts(value: int | None) -> str:
    """Unix-время VK → «2024-05-01 12:30» (UTC)."""
    try:
        return datetime.fromtimestamp(int(value or 0), tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError, OSError):
        return ""


def _mentions(texts: list[str]) -> dict[str, list[str]]:
    """Что встречается в текстах постов: email, телефоны, ссылки, @упоминания."""
    joined = " \n ".join(texts)
    emails = sorted({m.lower() for m in re.findall(r"[\w.+-]+@[\w-]+\.[\w.]{2,}", joined)})
    phones = []
    for raw in re.findall(r"\+?\d[\d\s().-]{8,}\d", joined):
        digits = re.sub(r"\D", "", raw)
        if 10 <= len(digits) <= 15:
            phones.append("+" + digits)
    return {"emails": emails[:20], "phones": sorted(set(phones))[:20],
            "links": sorted({m for m in re.findall(r"https?://[^\s<>\"']{6,80}", joined)})[:20],
            "mentions": sorted({m for m in re.findall(r"@[A-Za-z0-9_]{3,32}", joined)})[:20]}
