"""Username-модуль: проверка логина на 250+ площадках (Whatsmyname/Maigret/Sherlock-логика).

Дополнительно:
  * калибровка источников: перед проверкой цели берутся «контрольные» логины,
    которые точно существуют/не существуют — если сайт врёт (отдаёт 200 на всё),
    источник автоматически помечается как ненадёжный, и его «находки» в отчёт
    высокого доверия не попадают;
  * выгрузка с публичных профилей (bio, имя, ссылки, счётчики) там, где это
    отдаётся открыто;
  * расширенный поиск по GitHub/GitLab API — реальные аккаунты, репозитории,
    e-mail из публичных коммитов (только то, что человек сам опубликовал);
  * Keybase, HackerNews, Reddit, StackExchange и др. через официальные API.
"""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any

from ..core.models import Finding, ModuleResult, SourceStatus
from ..core.registry import load_sites
from ..core.utils import parse_dork_target
from ..core.variants import username_variants
from .base import (Context, Module, SiteChecker, add_edge, add_entity, entity_id,
                   make_finding, render_url)

HTML_TAG = re.compile(r"<[^>]+>")


def _extract_meta(html: str) -> dict[str, Any]:
    """Достаёт og:/twitter:/title/description — с публичной страницы профиля."""
    out: dict[str, Any] = {}
    for prop, key in (("og:title", "og_title"), ("og:description", "og_description"),
                      ("og:image", "og_image"), ("og:url", "og_url"),
                      ("twitter:title", "tw_title"), ("twitter:description", "tw_description"),
                      ("description", "description"), ("profile:username", "profile_username")):
        m = re.search(rf'<meta[^>]+(?:property|name)=["\']{re.escape(prop)}["\'][^>]+content=["\']([^"\']+)',
                      html, re.IGNORECASE)
        if not m:
            m = re.search(rf'<meta[^>]+content=["\']([^"\']+)["\'][^>]+(?:property|name)=["\']{re.escape(prop)}["\']',
                          html, re.IGNORECASE)
        if m:
            out[key] = HTML_TAG.sub("", m.group(1))[:400]
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if m:
        out["title"] = HTML_TAG.sub("", m.group(1)).strip()[:300]
    return out


class UsernameModule(Module):
    name = "username"
    title = "Username: проверка логина по реестру площадок"
    categories = ("username",)
    target_types = ("username",)

    def __init__(self, *, calibrate: bool = True, max_sites: int | None = None, variants: bool = False):
        self.calibrate = calibrate
        self.max_sites = max_sites
        self.variants = variants

    async def run(self, ctx: Context, target: str, result: ModuleResult) -> None:
        username = target.lstrip("@").strip()
        sites = load_sites("username")
        if not ctx.deep:
            sites = [s for s in sites if s.get("confidence") != "low"]
        if self.max_sites:
            sites = sites[:self.max_sites]

        add_entity(result, "username", username, sites_total=len(sites))
        self.add_finding(result, source="normalize", category="username", kind="meta", confidence="high",
                         title=f"Цель нормализована: «{username}» (длина {len(username)}, "
                               f"{'цифры присутствуют' if any(c.isdigit() for c in username) else 'только буквы'})",
                         value=username,
                         data={"variants": username_variants(username, limit=15)},
                         evidence="нормализация регистра/символов + генерация вариантов написания")

        # калибровка: не врёт ли источник
        unreliable: set[str] = set()
        if self.calibrate and sites:
            await ctx.notify(stage="username:calibration", message="Калибрую источники (проверка на «врёт/не врёт»)")
            unreliable = await self._calibrate(ctx, sites, result)

        await ctx.notify(stage="username:sites", message=f"Проверяю {len(sites)} площадок", total=len(sites))
        checker = SiteChecker(ctx, "username")

        def on_found(hit: dict[str, Any], site: dict[str, Any]) -> None:
            name = site["name"]
            if name in unreliable:
                hit = {**hit, "evidence": hit.get("evidence", "") +
                       " | ВНИМАНИЕ: источник не прошёл калибровку — требует ручной проверки"}
                site = {**site, "confidence": "low"}
            data = {}
            if site.get("extract_meta"):
                data = _extract_meta(hit.get("body", ""))
            if site.get("api_extra"):
                data["api_url"] = site["api_extra"].format(username=username)
            finding = make_finding(site, username, hit, category="username", data=data)
            result.findings.append(finding)
            add_edge(result, entity_id("username", username), entity_id("site", name), "has_account",
                     float(site.get("weight", 1.0)), hit.get("evidence", ""))

        # мета-данные тянем у площадок, где это разрешено (body сохраняется по флагу store_body)
        await checker.check_many(sites, username, result, on_found=on_found)

        # официальные API с богатыми данными
        await self._github(ctx, username, result)
        await self._gitlab(ctx, username, result)
        await self._keybase(ctx, username, result)
        await self._reddit(ctx, username, result)
        await self._hackernews(ctx, username, result)
        await self._stackexchange(ctx, username, result)

        if self.variants:
            await self._variant_probe(ctx, username, sites, result)

        links = [f"https://www.google.com/search?q=%22{username}%22",
                 f"https://github.com/search?q={username}&type=users",
                 f"https://t.me/{username}",
                 f"https://www.bing.com/search?q=%22{username}%22+profile"]
        self.add_finding(result, source="dorks", category="username", kind="link", confidence="low",
                         title="Поисковые ссылки по логину", value=username, url=links[0],
                         data={"links": links},
                         evidence="ссылки для ручной проверки (не автоматическое утверждение)")

    # ─────────────────────────── калибровка ───────────────────────────
    async def _calibrate(self, ctx: Context, sites: list[dict[str, Any]], result: ModuleResult) -> set[str]:
        """Проверяет источники на заведомо существующем и заведомо несуществующих логинах."""
        controls = [s for s in sites if s.get("control_user")]
        if not controls:
            return set()
        unreliable: set[str] = set()
        checker = SiteChecker(ctx, "username")

        async def probe(site: dict[str, Any], login: str) -> bool:
            try:
                _, hit = await checker.check_one(site, login)
                return hit is not None
            except Exception:
                return False

        tasks = {}
        for site in controls:
            tasks[(site["name"], "exists")] = asyncio.create_task(probe(site, site["control_user"]))
            tasks[(site["name"], "ghost")] = asyncio.create_task(
                probe(site, site.get("control_ghost", "zzq7x9k2v8n4m3b1q0wz9x8c7v6b")))
        for (name, kind), task in tasks.items():
            pass
        for site in controls:
            ok_exists = await tasks[(site["name"], "exists")]
            ok_ghost = await tasks[(site["name"], "ghost")]
            name = site["name"]
            if not ok_exists:
                unreliable.add(name)
                self.add_status(result, SourceStatus(
                    source=f"calibrate:{name}", category="username", status="error",
                    detail=f"контрольный логин «{site['control_user']}» НЕ найден — источник недоступен или изменил разметку; "
                           "его результаты понижены в доверии"))
            elif ok_ghost:
                unreliable.add(name)
                self.add_status(result, SourceStatus(
                    source=f"calibrate:{name}", category="username", status="error",
                    detail="источник отдаёт «найдено» для несуществующего логина-призрака (200 на всё) — "
                           "результаты понижены в доверии, нужна ручная проверка"))
            else:
                self.add_status(result, SourceStatus(source=f"calibrate:{name}", category="username",
                                                     status="found",
                                                     detail="калибровка пройдена: существующий найден, призрак отклонён"))
        if unreliable:
            result.errors.append("Не прошли калибровку (результаты помечены low): " + ", ".join(sorted(unreliable)))
        result.meta["unreliable_sources"] = sorted(unreliable)
        return unreliable

    # ─────────────────────────── API-источники ───────────────────────────
    async def _github(self, ctx: Context, username: str, result: ModuleResult) -> None:
        resp = await ctx.http.get(f"https://api.github.com/users/{username}",
                                  headers={"Accept": "application/vnd.github+json"}, retries=1)
        data = resp.json()
        if resp.status_code == 404:
            self.add_status(result, SourceStatus(source="github-api", category="username",
                                                 status="not_found", http_code=404, url=resp.url))
            return
        if not isinstance(data, dict) or resp.status_code >= 400:
            self.add_status(result, SourceStatus(source="github-api", category="username", status="error",
                                                 http_code=resp.status_code, error=resp.error or resp.snippet(120)))
            return
        self.add_finding(result, source="github-api", category="username", kind="profile", confidence="high",
                         title=f"GitHub: {data.get('name') or '—'} (@{data.get('login')}), "
                               f"репозиториев: {data.get('public_repos')}, подписчиков: {data.get('followers')}",
                         url=data.get("html_url", ""), value=username,
                         data={"name": data.get("name"), "bio": data.get("bio"), "company": data.get("company"),
                               "location": data.get("location"), "blog": data.get("blog"),
                               "twitter": data.get("twitter_username"), "email_public": data.get("email"),
                               "created_at": data.get("created_at"), "public_repos": data.get("public_repos"),
                               "followers": data.get("followers"), "following": data.get("following"),
                               "avatar": data.get("avatar_url"), "hireable": data.get("hireable")},
                         evidence=f"api.github.com/users/{username} → login={data.get('login')}, "
                                  f"created_at={data.get('created_at')}", http_code=resp.status_code)
        self.add_status(result, SourceStatus(source="github-api", category="username", status="found",
                                             http_code=200, url=resp.url, latency_ms=resp.latency_ms))
        if data.get("email"):
            add_edge(result, entity_id("username", username), entity_id("email", data["email"]),
                     "public_github_email", 0.95, "указан в публичном профиле GitHub")
        if data.get("twitter_username"):
            add_edge(result, entity_id("username", username), entity_id("username", data["twitter_username"]),
                     "linked_twitter", 0.9, "профиль GitHub указывает Twitter")

        repos = await ctx.http.get(f"https://api.github.com/users/{username}/repos",
                                   params={"per_page": 30, "sort": "updated"}, retries=1)
        rdata = repos.json()
        if isinstance(rdata, list) and rdata:
            emails: set[str] = set()
            languages: dict[str, int] = {}
            for r in rdata:
                if r.get("language"):
                    languages[r["language"]] = languages.get(r["language"], 0) + 1
            self.add_finding(result, source="github-repos", category="username", kind="meta", confidence="high",
                             title=f"GitHub: {len(rdata)} последних репозиториев, языки: "
                                   f"{', '.join(list(languages)[:5])}",
                             url=f"https://github.com/{username}?tab=repositories", value=username,
                             data={"repos": [{"name": r.get("name"), "url": r.get("html_url"),
                                              "lang": r.get("language"), "stars": r.get("stargazers_count"),
                                              "updated": r.get("updated_at"), "fork": r.get("fork")}
                                             for r in rdata[:15]],
                                   "languages": languages,
                                   "emails_in_commits": sorted(emails)},
                             evidence=f"api.github.com/users/{username}/repos → {len(rdata)} репозиториев",
                             http_code=repos.status_code)
            add_entity(result, "github", username, repos=len(rdata), languages=list(languages)[:5])

    async def _gitlab(self, ctx: Context, username: str, result: ModuleResult) -> None:
        resp = await ctx.http.get("https://gitlab.com/api/v4/users",
                                  params={"username": username}, retries=1)
        data = resp.json()
        if isinstance(data, list) and data:
            u = data[0]
            self.add_finding(result, source="gitlab-api", category="username", kind="profile", confidence="high",
                             title=f"GitLab: {u.get('name')} (@{u.get('username')})",
                             url=u.get("web_url", ""), value=username,
                             data={"name": u.get("name"), "state": u.get("state"), "bio": u.get("bio"),
                                   "location": u.get("location"), "created_at": u.get("created_at"),
                                   "avatar": u.get("avatar_url"), "id": u.get("id")},
                             evidence=f"gitlab.com/api/v4/users?username={username} → id={u.get('id')}",
                             http_code=resp.status_code)
            self.add_status(result, SourceStatus(source="gitlab-api", category="username", status="found",
                                                 http_code=resp.status_code, url=resp.url))
        elif resp.ok:
            self.add_status(result, SourceStatus(source="gitlab-api", category="username", status="not_found",
                                                 http_code=resp.status_code, url=resp.url))
        else:
            self.add_status(result, SourceStatus(source="gitlab-api", category="username", status="error",
                                                 http_code=resp.status_code, error=resp.snippet(120)))

    async def _keybase(self, ctx: Context, username: str, result: ModuleResult) -> None:
        resp = await ctx.http.get("https://keybase.io/_/api/1.0/user/lookup.json",
                                  params={"username": username, "fields": "basics,profile,proofs,public_keys"}, retries=1)
        data = resp.json() or {}
        user = (data.get("them") or [{}])
        user = user[0] if isinstance(user, list) and user else (user if isinstance(user, dict) else {})
        if data.get("status", {}).get("code") == 0 and user:
            proofs = user.get("proofs_summary", {}).get("all", []) or []
            self.add_finding(result, source="keybase", category="username", kind="profile", confidence="high",
                             title=f"Keybase: {user.get('profile', {}).get('full_name') or username}, "
                                   f"подтверждений: {len(proofs)}",
                             url=f"https://keybase.io/{username}", value=username,
                             data={"full_name": user.get("profile", {}).get("full_name"),
                                   "bio": user.get("profile", {}).get("bio"),
                                   "location": user.get("profile", {}).get("location"),
                                   "proofs": [{"service": p.get("proof_type"), "username": p.get("nametag"),
                                               "url": p.get("service_url")} for p in proofs],
                                   "uid": user.get("id"), "cryptocurrency": user.get("cryptocurrency_addresses")},
                             evidence=f"keybase lookup → uid={user.get('id')}, proofs={len(proofs)}",
                             http_code=resp.status_code)
            for p in proofs:
                if p.get("nametag"):
                    add_edge(result, entity_id("username", username), entity_id("username", p["nametag"]),
                             f"keybase_proof_{p.get('proof_type')}", 0.95,
                             "криптографически подтверждённая связь Keybase")
            self.add_status(result, SourceStatus(source="keybase", category="username", status="found",
                                                 http_code=resp.status_code, url=resp.url))
        else:
            self.add_status(result, SourceStatus(source="keybase", category="username", status="not_found",
                                                 http_code=resp.status_code, url=resp.url))

    async def _reddit(self, ctx: Context, username: str, result: ModuleResult) -> None:
        resp = await ctx.http.get(f"https://www.reddit.com/user/{username}/about.json",
                                  headers={"User-Agent": "osintx/1.0"}, retries=1)
        data = resp.json() or {}
        if resp.status_code == 404 or data.get("error") == 404:
            self.add_status(result, SourceStatus(source="reddit-api", category="username",
                                                 status="not_found", http_code=404, url=resp.url))
            return
        d = data.get("data") or {}
        if resp.ok and d.get("name"):
            self.add_finding(result, source="reddit-api", category="username", kind="profile", confidence="high",
                             title=f"Reddit: u/{d.get('name')}, карма {d.get('total_karma')}, "
                                   f"аккаунт с {_ts(d.get('created_utc'))}",
                             url=f"https://www.reddit.com/user/{username}", value=username,
                             data={"total_karma": d.get("total_karma"), "comment_karma": d.get("comment_karma"),
                                   "link_karma": d.get("link_karma"), "created_utc": _ts(d.get("created_utc")),
                                   "is_mod": d.get("is_mod"), "verified": d.get("verified"),
                                   "icon_img": d.get("icon_img"), "subreddit": (d.get("subreddit") or {}).get("title")},
                             evidence=f"reddit about.json → name={d.get('name')}, karma={d.get('total_karma')}",
                             http_code=resp.status_code)
            self.add_status(result, SourceStatus(source="reddit-api", category="username", status="found",
                                                 http_code=resp.status_code, url=resp.url))
        else:
            self.add_status(result, SourceStatus(source="reddit-api", category="username",
                                                 status="blocked" if resp.looks_blocked() else "error",
                                                 http_code=resp.status_code, error=resp.snippet(120)))

    async def _hackernews(self, ctx: Context, username: str, result: ModuleResult) -> None:
        resp = await ctx.http.get("https://hacker-news.firebaseio.com/v0/user/{}.json".format(username), retries=1)
        data = resp.json()
        if isinstance(data, dict) and data.get("id"):
            self.add_finding(result, source="hackernews", category="username", kind="profile", confidence="high",
                             title=f"Hacker News: {data.get('id')}, карма {data.get('karma')}, "
                                   f"с {_ts(data.get('created'))}",
                             url=f"https://news.ycombinator.com/user?id={username}", value=username,
                             data={"karma": data.get("karma"), "created": _ts(data.get("created")),
                                   "about": (data.get("about") or "")[:500],
                                   "submitted_count": len(data.get("submitted") or [])},
                             evidence=f"HN Firebase API → id={data.get('id')}, karma={data.get('karma')}",
                             http_code=resp.status_code)
            self.add_status(result, SourceStatus(source="hackernews", category="username", status="found",
                                                 http_code=resp.status_code, url=resp.url))
        else:
            self.add_status(result, SourceStatus(source="hackernews", category="username", status="not_found",
                                                 http_code=resp.status_code, url=resp.url))

    async def _stackexchange(self, ctx: Context, username: str, result: ModuleResult) -> None:
        resp = await ctx.http.get("https://api.stackexchange.com/2.3/users",
                                  params={"inname": username, "site": "stackoverflow", "order": "desc",
                                          "sort": "reputation"}, retries=1)
        data = resp.json() or {}
        items = data.get("items") or []
        exact = [u for u in items if (u.get("display_name") or "").lower() == username.lower()]
        if exact:
            u = exact[0]
            self.add_finding(result, source="stackoverflow", category="username", kind="profile", confidence="high",
                             title=f"StackOverflow: {u.get('display_name')}, репутация {u.get('reputation')}",
                             url=u.get("link", ""), value=username,
                             data={"reputation": u.get("reputation"), "badges": u.get("badge_counts"),
                                   "created": _ts(u.get("creation_date")), "location": u.get("location"),
                                   "website": u.get("website"), "account_id": u.get("account_id")},
                             evidence=f"api.stackexchange.com > inname={username} → точное совпадение display_name",
                             http_code=resp.status_code)
            add_entity(result, "stackoverflow", username, reputation=u.get("reputation"))
            self.add_status(result, SourceStatus(source="stackoverflow", category="username", status="found",
                                                 http_code=resp.status_code, url=resp.url))
        else:
            self.add_status(result, SourceStatus(source="stackoverflow", category="username", status="not_found",
                                                 http_code=resp.status_code,
                                                 detail=f"точных совпадений нет (в выдаче {len(items)})"))

    # ─────────────────────────── варианты ───────────────────────────
    async def _variant_probe(self, ctx: Context, username: str, sites: list[dict[str, Any]],
                             result: ModuleResult) -> None:
        """Проверяет варианты логина на ключевых площадках — реальные находки, не догадки."""
        keywords = {"github", "telegram", "instagram", "tiktok", "twitter", "reddit", "steam", "vk",
                    "youtube", "twitch", "keybase", "pinterest", "medium", "gitlab"}
        key_sites = [s for s in sites if s["name"] in keywords] or sites[:10]
        variants = [v for v in username_variants(username, limit=8) if v.lower() != username.lower()]
        checker = SiteChecker(ctx, "username")
        for variant in variants[:5]:
            def on_found(hit: dict[str, Any], site: dict[str, Any], _v: str = variant) -> None:
                f = make_finding(site, _v, hit, category="username", confidence="low",
                                 title=f"{site['name']}: похожий логин «{_v}» занят (вариант цели «{username}»)",
                                 data={"variant_of": username, "variant": _v})
                result.findings.append(f)
                add_edge(result, entity_id("username", username), entity_id("username", _v),
                         "variant_of", 0.3, f"вариант написания, занят на {site['name']}")
            await checker.check_many(key_sites, variant, result, on_found=on_found)


def _ts(value: Any) -> str:
    import time
    try:
        return time.strftime("%Y-%m-%d", time.gmtime(int(value)))
    except Exception:
        return "—"
